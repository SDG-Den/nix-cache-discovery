// Adapted from nix-serve-ng cbits/nix.cpp (BSD-3-Clause, Arista Networks).
// See NOTICE for the original license.
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <nix/main/shared.hh>
#include <nix/store/log-store.hh>
#include <nix/store/store-api.hh>
#include <nix/store/store-open.hh>
#include <nix/util/serialise.hh>
#include <nix/util/signature/local-keys.hh>

#include "nix.h"

namespace {

std::optional<nix::ref<nix::Store>> store_instance;
std::string store_uri;

nix::Store &store()
{
    if (!store_instance.has_value()) {
        nix::initNix();
        store_instance = store_uri.empty() ? nix::openStore() : nix::openStore(store_uri);
    }
    return **store_instance;
}

char *duplicate(std::string_view input)
{
    char *data = static_cast<char *>(std::malloc(input.size() + 1));

    if (data == nullptr) {
        throw std::bad_alloc();
    }

    std::memcpy(data, input.data(), input.size());
    data[input.size()] = '\0';

    return data;
}

void assign_error(char **error, std::string const &message)
{
    if (error != nullptr) {
        *error = duplicate(message);
    }
}

void copy_strings(std::vector<std::string> const &input, char ***output, size_t *count)
{
    char **data = static_cast<char **>(std::calloc(input.size(), sizeof(char *)));

    if (data == nullptr && !input.empty()) {
        throw std::bad_alloc();
    }

    size_t index = 0;

    try {
        for (auto const &item : input) {
            data[index++] = duplicate(item);
        }
    } catch (...) {
        for (size_t i = 0; i < index; ++i) {
            std::free(data[i]);
        }
        std::free(data);
        throw;
    }

    *output = data;
    *count = index;
}

void free_strings(char **data, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        std::free(data[i]);
    }
    std::free(data);
}

template<typename Function>
int guarded(char **error, Function function)
{
    try {
        return function();
    } catch (std::exception const &exception) {
        assign_error(error, exception.what());
        return 2;
    } catch (...) {
        assign_error(error, "unknown error");
        return 2;
    }
}

} // namespace

extern "C" {

int ccd_init_store(const char *uri, char **error)
{
    return guarded(error, [&]() {
        if (uri != nullptr && uri[0] != '\0') {
            store_uri = uri;
        }
        store();
        return 0;
    });
}

char *ccd_store_dir(char **error)
{
    try {
        return duplicate(store().storeDir);
    } catch (std::exception const &exception) {
        assign_error(error, exception.what());
        return nullptr;
    } catch (...) {
        assign_error(error, "unknown error");
        return nullptr;
    }
}

int ccd_query_path_from_hash_part(const char *hash_part, char **out_path, char **error)
{
    return guarded(error, [&]() {
        auto &current = store();
        auto path = current.queryPathFromHashPart(hash_part);

        if (!path.has_value()) {
            return 1;
        }

        *out_path = duplicate(current.printStorePath(*path));
        return 0;
    });
}

int ccd_query_path_info(const char *store_path, struct ccd_path_info *out, char **error)
{
    return guarded(error, [&]() {
        auto &current = store();
        auto info = current.queryPathInfo(current.parseStorePath(store_path));

        if (info->deriver.has_value()) {
            out->deriver = duplicate(current.printStorePath(*info->deriver));
        } else {
            out->deriver = duplicate("");
        }

        out->nar_hash = duplicate(info->narHash.to_string(nix::HashFormat::Nix32, true));
        out->nar_size = info->narSize;

        std::vector<std::string> references;
        references.reserve(info->references.size());
        for (auto const &reference : info->references) {
            references.push_back(current.printStorePath(reference));
        }
        copy_strings(references, &out->references, &out->reference_count);

        std::vector<std::string> signatures;
        signatures.reserve(info->sigs.size());
        for (auto const &signature : info->sigs) {
            signatures.push_back(signature.to_string());
        }
        copy_strings(signatures, &out->signatures, &out->signature_count);

        return 0;
    });
}

void ccd_free_path_info(struct ccd_path_info *info)
{
    std::free(info->deriver);
    std::free(info->nar_hash);
    free_strings(info->references, info->reference_count);
    free_strings(info->signatures, info->signature_count);
}

int ccd_dump_path(const char *hash_part, int fd, char **error)
{
    return guarded(error, [&]() {
        auto &current = store();
        auto path = current.queryPathFromHashPart(hash_part);

        if (!path.has_value()) {
            return 1;
        }

        nix::LambdaSink sink([fd](std::string_view chunk) {
            size_t offset = 0;

            while (offset < chunk.size()) {
                ssize_t written = ::write(fd, chunk.data() + offset, chunk.size() - offset);

                if (written < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    throw std::runtime_error(std::string("write failed: ") + std::strerror(errno));
                }

                offset += static_cast<size_t>(written);
            }
        });

        current.narFromPath(*path, sink);
        return 0;
    });
}

int ccd_dump_log(const char *base_name, char **out_data, size_t *out_size, char **error)
{
    return guarded(error, [&]() {
        auto &current = store();
        nix::StorePath path(base_name);
        auto substituters = nix::getDefaultSubstituters();
        substituters.push_front(*store_instance);

        for (auto &candidate : substituters) {
            auto *log_store = dynamic_cast<nix::LogStore *>(&*candidate);

            if (log_store == nullptr) {
                continue;
            }

            auto log = log_store->getBuildLog(path);

            if (log.has_value()) {
                *out_data = duplicate(*log);
                *out_size = log->size();
                return 0;
            }
        }

        return 1;
    });
}

int ccd_sign_string(const char *secret_key, const char *message, char **out_signature, char **error)
{
    return guarded(error, [&]() {
        nix::SecretKey key(secret_key);
        *out_signature = duplicate(key.signDetached(message).to_string());
        return 0;
    });
}

void ccd_free(void *pointer)
{
    std::free(pointer);
}

} // extern "C"
