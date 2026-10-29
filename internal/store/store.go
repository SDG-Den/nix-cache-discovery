package store

/*
#cgo pkg-config: nix-main nix-store
#cgo CXXFLAGS: -std=c++23
#cgo LDFLAGS: -lstdc++
#include <stdlib.h>
#include "nix.h"
*/
import "C"

import (
	"errors"
	"io"
	"os"
	"unsafe"
)

var ErrNotFound = errors.New("store path not found")

type PathInfo struct {
	StorePath  string
	Deriver    string
	NarHash    string
	NarSize    uint64
	References []string
	Signatures []string
}

type NarStream struct {
	Reader *os.File
	done   chan error
}

func Init(uri string) error {
	var cURI *C.char

	if uri != "" {
		cURI = C.CString(uri)
		defer C.free(unsafe.Pointer(cURI))
	}

	var cErr *C.char

	if code := C.ccd_init_store(cURI, &cErr); code != 0 {
		return takeError(cErr)
	}

	return nil
}

func StoreDir() (string, error) {
	var cErr *C.char

	value := C.ccd_store_dir(&cErr)

	if value == nil {
		return "", takeError(cErr)
	}

	defer C.ccd_free(unsafe.Pointer(value))

	return C.GoString(value), nil
}

func QueryPathFromHashPart(hashPart string) (string, error) {
	cHash := C.CString(hashPart)
	defer C.free(unsafe.Pointer(cHash))

	var cPath *C.char
	var cErr *C.char

	switch code := C.ccd_query_path_from_hash_part(cHash, &cPath, &cErr); code {
	case 0:
		defer C.ccd_free(unsafe.Pointer(cPath))
		return C.GoString(cPath), nil
	case 1:
		return "", ErrNotFound
	default:
		return "", takeError(cErr)
	}
}

func QueryPathInfo(storePath string) (PathInfo, error) {
	cPath := C.CString(storePath)
	defer C.free(unsafe.Pointer(cPath))

	var raw C.struct_ccd_path_info
	var cErr *C.char

	switch code := C.ccd_query_path_info(cPath, &raw, &cErr); code {
	case 0:
		defer C.ccd_free_path_info(&raw)

		return PathInfo{
			StorePath:  storePath,
			Deriver:    C.GoString(raw.deriver),
			NarHash:    C.GoString(raw.nar_hash),
			NarSize:    uint64(raw.nar_size),
			References: goStrings(raw.references, raw.reference_count),
			Signatures: goStrings(raw.signatures, raw.signature_count),
		}, nil
	case 1:
		return PathInfo{}, ErrNotFound
	default:
		return PathInfo{}, takeError(cErr)
	}
}

func DumpPath(hashPart string) (*NarStream, error) {
	reader, writer, err := os.Pipe()

	if err != nil {
		return nil, err
	}

	stream := &NarStream{Reader: reader, done: make(chan error, 1)}
	cHash := C.CString(hashPart)

	go func() {
		defer C.free(unsafe.Pointer(cHash))

		var cErr *C.char

		code := C.ccd_dump_path(cHash, C.int(writer.Fd()), &cErr)
		writer.Close()

		switch code {
		case 0:
			stream.done <- nil
		case 1:
			stream.done <- ErrNotFound
		default:
			stream.done <- takeError(cErr)
		}
	}()

	return stream, nil
}

func DumpLog(baseName string) ([]byte, error) {
	cName := C.CString(baseName)
	defer C.free(unsafe.Pointer(cName))

	var data *C.char
	var size C.size_t
	var cErr *C.char

	switch code := C.ccd_dump_log(cName, &data, &size, &cErr); code {
	case 0:
		defer C.ccd_free(unsafe.Pointer(data))
		return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
	case 1:
		return nil, ErrNotFound
	default:
		return nil, takeError(cErr)
	}
}

func Sign(secretKey, message string) (string, error) {
	cKey := C.CString(secretKey)
	defer C.free(unsafe.Pointer(cKey))

	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))

	var signature *C.char
	var cErr *C.char

	if code := C.ccd_sign_string(cKey, cMessage, &signature, &cErr); code != 0 {
		return "", takeError(cErr)
	}

	defer C.ccd_free(unsafe.Pointer(signature))

	return C.GoString(signature), nil
}

func (stream *NarStream) Wait() error {
	return <-stream.done
}

func (stream *NarStream) Close() error {
	return stream.Reader.Close()
}

func goStrings(data **C.char, count C.size_t) []string {
	if data == nil || count == 0 {
		return nil
	}

	values := unsafe.Slice(data, int(count))
	result := make([]string, len(values))

	for index, value := range values {
		result[index] = C.GoString(value)
	}

	return result
}

func takeError(cErr *C.char) error {
	if cErr == nil {
		return errors.New("unknown store error")
	}

	defer C.ccd_free(unsafe.Pointer(cErr))

	return errors.New(C.GoString(cErr))
}

var _ io.Closer = (*NarStream)(nil)
