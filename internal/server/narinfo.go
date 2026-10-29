package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/den/nix-cache-discovery/internal/store"
)

func (server *Server) localNarinfo(hashPart string) ([]byte, error) {
	storePath, err := store.QueryPathFromHashPart(hashPart)

	if err != nil {
		return nil, err
	}

	info, err := store.QueryPathInfo(storePath)

	if err != nil {
		return nil, err
	}

	return server.renderNarinfo(info)
}

func (server *Server) renderNarinfo(info store.PathInfo) ([]byte, error) {
	hashPart := hashPartOfStorePath(info.StorePath)

	if hashPart == "" {
		return nil, errors.New("store path has no valid hash part")
	}

	var builder strings.Builder

	fmt.Fprintf(&builder, "StorePath: %s\n", info.StorePath)
	fmt.Fprintf(&builder, "URL: nar/%s-%s.nar\n", hashPart, strings.TrimPrefix(info.NarHash, "sha256:"))
	builder.WriteString("Compression: none\n")
	fmt.Fprintf(&builder, "NarHash: %s\n", info.NarHash)
	fmt.Fprintf(&builder, "NarSize: %d\n", info.NarSize)

	if len(info.References) > 0 {
		builder.WriteString("References:")

		for _, reference := range info.References {
			builder.WriteString(" ")
			builder.WriteString(server.baseName(reference))
		}

		builder.WriteString("\n")
	}

	if info.Deriver != "" {
		fmt.Fprintf(&builder, "Deriver: %s\n", server.baseName(info.Deriver))
	}

	if server.options.SecretKey != "" {
		signature, err := store.Sign(server.options.SecretKey, fingerprint(info))

		if err != nil {
			return nil, err
		}

		fmt.Fprintf(&builder, "Sig: %s\n", signature)
	} else {
		for _, signature := range info.Signatures {
			fmt.Fprintf(&builder, "Sig: %s\n", signature)
		}
	}

	return []byte(builder.String()), nil
}

func fingerprint(info store.PathInfo) string {
	return fmt.Sprintf(
		"1;%s;%s;%d;%s",
		info.StorePath,
		info.NarHash,
		info.NarSize,
		strings.Join(info.References, ","),
	)
}

func hashPartOfStorePath(storePath string) string {
	base := storePath
	slash := strings.LastIndexByte(base, '/')

	if slash >= 0 {
		base = base[slash+1:]
	}

	if len(base) < 32 {
		return ""
	}

	base = base[:32]

	if !validHashPart(base) {
		return ""
	}

	return base
}

func validHashPart(hashPart string) bool {
	for index := 0; index < len(hashPart); index++ {
		character := hashPart[index]

		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'd':
		case character >= 'f' && character <= 'n':
		case character >= 'p' && character <= 's':
		case character >= 'v' && character <= 'z':
		default:
			return false
		}
	}

	return true
}
