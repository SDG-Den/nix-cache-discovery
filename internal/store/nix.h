#ifndef NIX_CACHE_DISCOVERY_NIX_H
#define NIX_CACHE_DISCOVERY_NIX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ccd_path_info {
    char *deriver;
    char *nar_hash;
    uint64_t nar_size;
    char **references;
    size_t reference_count;
    char **signatures;
    size_t signature_count;
};

/* All functions return 0 on success, 1 when the path is absent and 2 on error. */

int ccd_init_store(const char *uri, char **error);

char *ccd_store_dir(char **error);

int ccd_query_path_from_hash_part(const char *hash_part, char **out_path, char **error);

int ccd_query_path_info(const char *store_path, struct ccd_path_info *out, char **error);

void ccd_free_path_info(struct ccd_path_info *info);

int ccd_dump_path(const char *hash_part, int fd, char **error);

int ccd_dump_log(const char *base_name, char **out_data, size_t *out_size, char **error);

int ccd_sign_string(const char *secret_key, const char *message, char **out_signature, char **error);

void ccd_free(void *pointer);

#ifdef __cplusplus
}
#endif

#endif
