package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/den/nix-cache-discovery/internal/registry"
)

const sampleNarinfo = "StorePath: /nix/store/9l0j15jg8634hkb6d4c9y95mpxl0nhrd-jq-1.8.2-bin\n" +
	"NarHash: sha256:1y1zn2h9pza8ha96l3xrvqananbqxcgw8iirgxixmmzwd8brlhrf\n" +
	"NarSize: 35680\n"

func newTestProxier(t *testing.T, url string, retries int) *Proxier {
	t.Helper()

	peers := registry.New()
	peers.Mark(registry.Peer{
		ID:   "peer",
		URL:  url,
		Addr: netip.MustParseAddr("192.0.2.10"),
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	return New(peers, "/nix/store", "", "self", nil, nil, false, 2*time.Second, retries, "http", logger)
}

func TestNarinfoRetriesTransientFailures(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		_, _ = w.Write([]byte(sampleNarinfo))
	}))
	defer server.Close()

	proxier := newTestProxier(t, server.URL, 1)

	body, found, err := proxier.Narinfo(context.Background(), "9l0j15jg8634hkb6d4c9y95mpxl0nhrd", 0)

	if err != nil {
		t.Fatal(err)
	}

	if !found {
		t.Fatal("expected the narinfo to be found after a retry")
	}

	if string(body) != sampleNarinfo {
		t.Fatalf("unexpected body %q", body)
	}

	if attempts.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts.Load())
	}
}

func TestNarinfoReportsTransientFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	proxier := newTestProxier(t, server.URL, 0)

	_, found, err := proxier.Narinfo(context.Background(), "9l0j15jg8634hkb6d4c9y95mpxl0nhrd", 0)

	if err == nil {
		t.Fatal("expected a transient error")
	}

	if found {
		t.Fatal("expected the narinfo to be reported as missing")
	}

	if proxier.recentlyMissed("9l0j15jg8634hkb6d4c9y95mpxl0nhrd") {
		t.Fatal("a transient failure must not be cached as a miss")
	}
}

func TestNarinfoDoesNotRetryMissingPaths(t *testing.T) {
	var attempts atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	proxier := newTestProxier(t, server.URL, 3)

	_, found, err := proxier.Narinfo(context.Background(), "9l0j15jg8634hkb6d4c9y95mpxl0nhrd", 0)

	if err != nil {
		t.Fatalf("a missing path is not an error: %v", err)
	}

	if found {
		t.Fatal("expected the narinfo to be reported as missing")
	}

	if attempts.Load() != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts.Load())
	}
}
