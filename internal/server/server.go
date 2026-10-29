package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/den/nix-cache-discovery/internal/discovery"
	"github.com/den/nix-cache-discovery/internal/proxy"
	"github.com/den/nix-cache-discovery/internal/registry"
	"github.com/den/nix-cache-discovery/internal/store"
)

type Options struct {
	StoreDir   string
	Priority   int
	Port       int
	InstanceID string
	Allowlist  []netip.Prefix
	SecretKey  string
	Peers      *registry.Registry
	Proxier    *proxy.Proxier
	Trusted    func() bool
	Logger     *slog.Logger
}

type Server struct {
	options Options
}

func New(options Options) *Server {
	return &Server{options: options}
}

func (server *Server) Handler() http.Handler {
	return server.guard(http.HandlerFunc(server.route))
}

func (server *Server) route(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/nix-cache-info":
		server.handleCacheInfo(w)
	case path == discovery.InfoPath:
		server.handleDiscoveryInfo(w)
	case strings.HasSuffix(path, ".narinfo"):
		server.handleNarinfo(w, r)
	case strings.HasPrefix(path, "/nar/"):
		server.handleNar(w, r)
	case strings.HasPrefix(path, "/log/"):
		server.handleLog(w, r)
	default:
		http.Error(w, "File not found.\n", http.StatusNotFound)
	}
}

func (server *Server) handleCacheInfo(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "StoreDir: %s\nWantMassQuery: 1\nPriority: %d\n", server.options.StoreDir, server.options.Priority)
}

func (server *Server) handleDiscoveryInfo(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "id=%s\nversion=%s\nport=%d\n", server.options.InstanceID, discovery.Version, server.options.Port)
}

func (server *Server) handleNarinfo(w http.ResponseWriter, r *http.Request) {
	hashPart := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, ".narinfo"), "/")

	if len(hashPart) != 32 || !validHashPart(hashPart) {
		http.Error(w, "Invalid path.\n", http.StatusBadRequest)
		return
	}

	body, err := server.localNarinfo(hashPart)

	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		if server.localOnly(r) {
			http.Error(w, "No such path.\n", http.StatusNotFound)
			return
		}

		var found bool
		body, found = server.options.Proxier.Narinfo(r.Context(), hashPart, hopsFrom(r))

		if !found {
			http.Error(w, "No such path.\n", http.StatusNotFound)
			return
		}
	default:
		server.options.Logger.Error("cannot render narinfo", "hash", hashPart, "error", err)
		http.Error(w, "Internal server error.\n", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/x-nix-narinfo")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (server *Server) handleNar(w http.ResponseWriter, r *http.Request) {
	interior := strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, ".nar"), "/nar/")
	hashPart := ""

	switch {
	case len(interior) == 32:
		hashPart = interior
	case len(interior) == 85 && interior[32] == '-':
		hashPart = interior[:32]
	}

	if hashPart != "" && !validHashPart(hashPart) {
		http.Error(w, "Invalid path.\n", http.StatusBadRequest)
		return
	}

	if hashPart != "" {
		_, err := store.QueryPathFromHashPart(hashPart)

		switch {
		case err == nil:
			server.streamLocal(w, hashPart)
			return
		case !errors.Is(err, store.ErrNotFound):
			server.options.Logger.Error("cannot query store path", "hash", hashPart, "error", err)
			http.Error(w, "Internal server error.\n", http.StatusInternalServerError)
			return
		}
	}

	if !validNarPath(r.URL.Path) {
		server.options.Logger.Warn("invalid nar path", "path", r.URL.Path)
		http.Error(w, "Invalid path.\n", http.StatusBadRequest)
		return
	}

	if server.localOnly(r) {
		http.Error(w, "No such path.\n", http.StatusNotFound)
		return
	}

	if server.options.Proxier.Nar(r.Context(), w, r.URL.Path, hopsFrom(r)) {
		return
	}

	http.Error(w, "No such path.\n", http.StatusNotFound)
}

func validNarPath(path string) bool {
	if !strings.HasPrefix(path, "/nar/") {
		return false
	}

	name := strings.TrimPrefix(path, "/nar/")

	if name == "" || strings.ContainsAny(name, "/\\") {
		return false
	}

	switch {
	case strings.HasSuffix(name, ".nar"):
	case strings.HasSuffix(name, ".nar.xz"):
	case strings.HasSuffix(name, ".nar.zst"):
	case strings.HasSuffix(name, ".nar.bz2"):
	default:
		return false
	}

	for _, character := range name {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'z':
		case character == '.' || character == '-':
		default:
			return false
		}
	}

	return true
}

func (server *Server) streamLocal(w http.ResponseWriter, hashPart string) {
	stream, err := store.DumpPath(hashPart)

	if err != nil {
		server.options.Logger.Error("cannot open nar stream", "hash", hashPart, "error", err)
		http.Error(w, "Internal server error.\n", http.StatusInternalServerError)
		return
	}

	defer stream.Close()

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	controller := http.NewResponseController(w)
	buffer := make([]byte, 64*1024)

	for {
		read, readErr := stream.Reader.Read(buffer)

		if read > 0 {
			if _, writeErr := w.Write(buffer[:read]); writeErr != nil {
				server.options.Logger.Debug("client went away during nar stream", "hash", hashPart, "error", writeErr)
				return
			}

			controller.Flush()
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			server.options.Logger.Warn("nar stream interrupted", "hash", hashPart, "error", readErr)
			return
		}
	}

	if err := stream.Wait(); err != nil {
		server.options.Logger.Warn("nar dump failed", "hash", hashPart, "error", err)
	}
}

func (server *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	baseName := strings.TrimPrefix(r.URL.Path, "/log/")

	if len(baseName) < 32 {
		http.Error(w, "Invalid path.\n", http.StatusBadRequest)
		return
	}

	data, err := store.DumpLog(baseName)

	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "No such path.\n", http.StatusNotFound)
		return
	}

	if err != nil {
		server.options.Logger.Error("cannot read build log", "name", baseName, "error", err)
		http.Error(w, "Internal server error.\n", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (server *Server) baseName(storePath string) string {
	return strings.TrimPrefix(storePath, server.options.StoreDir+"/")
}
