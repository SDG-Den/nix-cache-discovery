package trust

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsTrusted(t *testing.T) {
	networks := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}

	if !IsTrusted(netip.MustParseAddr("203.0.113.7"), networks) {
		t.Fatal("expected address to be trusted")
	}

	if IsTrusted(netip.MustParseAddr("198.51.100.7"), networks) {
		t.Fatal("expected address to be untrusted")
	}

	if !IsTrusted(netip.MustParseAddr("198.51.100.7"), nil) {
		t.Fatal("expected empty network list to trust everything")
	}
}

func TestMonitorUsesPublicAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.7\n"))
	}))
	defer server.Close()

	monitor := New(
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		server.URL,
		time.Second,
		testLogger(t),
	)

	monitor.Refresh(nil)

	if !monitor.Trusted() {
		t.Fatal("expected trusted state after a matching lookup")
	}
}

func TestMonitorKeepsStateWhenLookupFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("198.51.100.7\n"))
	}))

	monitor := New(
		[]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		server.URL,
		time.Second,
		testLogger(t),
	)

	monitor.Refresh(nil)

	if !monitor.Trusted() {
		t.Fatal("expected trusted state before the server stops")
	}

	server.Close()
	monitor.Refresh(nil)

	if !monitor.Trusted() {
		t.Fatal("expected trust state to survive a failed lookup")
	}
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()

	handler := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})

	return slog.New(handler)
}
