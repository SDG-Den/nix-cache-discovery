package server

import (
	"net/http"
	"net/netip"
	"strconv"

	"github.com/den/nix-cache-discovery/internal/proxy"
)

func (server *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, err := netip.ParseAddrPort(r.RemoteAddr)

		if err != nil {
			http.Error(w, "Forbidden.\n", http.StatusForbidden)
			return
		}

		source := address.Addr().Unmap()
		allowed := server.allowed(source)

		if !source.IsLoopback() && server.options.Trusted != nil && !server.options.Trusted() {
			allowed = false
		}

		if !allowed {
			server.options.Logger.Warn("rejected non-local connection", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "Forbidden.\n", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (server *Server) allowed(address netip.Addr) bool {
	if address.IsLoopback() {
		return true
	}

	return allowlist(server.options.Allowlist).Contains(address)
}

func (server *Server) isPeerRequest(r *http.Request) bool {
	identity := r.Header.Get(proxy.PeerHeader)

	if identity == "" || identity == server.options.InstanceID {
		return false
	}

	address, err := netip.ParseAddrPort(r.RemoteAddr)

	if err != nil {
		return false
	}

	source := address.Addr().Unmap()

	for _, peer := range server.options.Peers.Snapshot() {
		if peer.ID == identity && peer.Addr == source {
			return true
		}
	}

	return false
}

func (server *Server) localOnly(r *http.Request) bool {
	return server.isPeerRequest(r) || hopsFrom(r) >= 2
}

func hopsFrom(r *http.Request) int {
	value, err := strconv.Atoi(r.Header.Get(proxy.HopsHeader))

	if err != nil || value < 0 {
		return 0
	}

	return value
}

type allowlist []netip.Prefix

func (list allowlist) Contains(address netip.Addr) bool {
	for _, prefix := range list {
		if prefix.Contains(address) {
			return true
		}
	}

	return false
}
