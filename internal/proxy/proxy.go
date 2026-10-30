package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/den/nix-cache-discovery/internal/registry"
	"github.com/den/nix-cache-discovery/internal/store"
)

const (
	PeerHeader = "X-Nix-Cache-Discovery-Peer"
	HopsHeader = "X-Nix-Cache-Discovery-Hops"
	maxBody    = 1 << 20
)

type Proxier struct {
	Registry                 *registry.Registry
	StoreDir                 string
	SecretKey                string
	SelfID                   string
	Fallbacks                []string
	TrustedKeys              []string
	VerifyFallbackSignatures bool
	Logger                   *slog.Logger
	PositiveTTL              time.Duration
	NegativeTTL              time.Duration
	Timeout                  time.Duration
	Retries                  int
	WaitTimeout              time.Duration
	PollInterval             time.Duration

	client       *http.Client
	streamClient *http.Client

	mu     sync.Mutex
	cache  map[string]cacheEntry
	misses map[string]time.Time
}

type cacheEntry struct {
	body    []byte
	expires time.Time
}

func New(peers *registry.Registry, storeDir, secretKey, selfID string, fallbacks, trustedKeys []string, verifyFallbackSignatures bool, timeout time.Duration, retries int, scheme string, logger *slog.Logger) *Proxier {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	streamTransport := transport.Clone()
	streamTransport.ResponseHeaderTimeout = timeout

	return &Proxier{
		Registry:                 peers,
		StoreDir:                 storeDir,
		SecretKey:                secretKey,
		SelfID:                   selfID,
		Fallbacks:                fallbacks,
		TrustedKeys:              trustedKeys,
		VerifyFallbackSignatures: verifyFallbackSignatures,
		Logger:                   logger,
		PositiveTTL:              10 * time.Minute,
		NegativeTTL:              15 * time.Second,
		Timeout:                  timeout,
		Retries:                  retries,
		WaitTimeout:              2 * time.Minute,
		PollInterval:             2 * time.Second,
		client:                   &http.Client{Transport: transport, Timeout: timeout},
		streamClient:             &http.Client{Transport: streamTransport},
		cache:                    make(map[string]cacheEntry),
		misses:                   make(map[string]time.Time),
	}
}

func (proxier *Proxier) Narinfo(ctx context.Context, hashPart string, hops int) ([]byte, bool, error) {
	deadline := time.Now().Add(proxier.WaitTimeout)

	for {
		body, found, err := proxier.narinfoOnce(ctx, hashPart, hops)

		if found || err == nil || time.Now().After(deadline) {
			return body, found, err
		}

		proxier.Logger.Debug("waiting for a cache source", "hash", hashPart, "error", err)

		if err := sleepContext(ctx, proxier.PollInterval); err != nil {
			return nil, false, err
		}
	}
}

func (proxier *Proxier) narinfoOnce(ctx context.Context, hashPart string, hops int) ([]byte, bool, error) {
	if body, ok := proxier.cached(hashPart); ok {
		return body, true, nil
	}

	if proxier.recentlyMissed(hashPart) {
		return nil, false, nil
	}

	var transientErr error

	for _, peer := range proxier.Registry.Snapshot() {
		body, err := proxier.fetchNarinfo(ctx, peer.URL, hashPart, hops)

		if err != nil {
			proxier.Logger.Debug("peer narinfo miss", "peer", peer.URL, "hash", hashPart, "error", err)

			if isTransient(err) {
				transientErr = err
			}

			continue
		}

		body = normalize(body)

		if err := validate(body, hashPart); err != nil {
			proxier.Logger.Warn("discarding invalid peer narinfo", "peer", peer.URL, "error", err)
			continue
		}

		if proxier.SecretKey != "" {
			signed, err := proxier.sign(body)

			if err != nil {
				proxier.Logger.Warn("cannot re-sign peer narinfo", "peer", peer.URL, "error", err)
				continue
			}

			body = signed
		}

		proxier.remember(hashPart, body)
		return body, true, nil
	}

	for _, fallback := range proxier.Fallbacks {
		body, err := proxier.fetchNarinfo(ctx, fallback, hashPart, hops)

		if err != nil {
			proxier.Logger.Debug("fallback narinfo miss", "fallback", fallback, "hash", hashPart, "error", err)

			if isTransient(err) {
				transientErr = err
			}

			continue
		}

		body = normalize(body)

		if err := validate(body, hashPart); err != nil {
			proxier.Logger.Warn("discarding invalid fallback narinfo", "fallback", fallback, "error", err)
			continue
		}

		if proxier.VerifyFallbackSignatures {
			if err := verifyNarinfo(body, proxier.StoreDir, proxier.TrustedKeys); err != nil {
				proxier.Logger.Warn("fallback narinfo failed signature verification", "fallback", fallback, "error", err)
				continue
			}
		}

		if proxier.SecretKey != "" {
			signed, err := proxier.sign(body)

			if err != nil {
				proxier.Logger.Warn("cannot re-sign fallback narinfo", "fallback", fallback, "error", err)
				continue
			}

			body = signed
		}

		proxier.remember(hashPart, body)
		return body, true, nil
	}

	if transientErr != nil {
		return nil, false, transientErr
	}

	proxier.rememberMiss(hashPart)
	return nil, false, nil
}

func (proxier *Proxier) Nar(ctx context.Context, w http.ResponseWriter, path string, hops int) (bool, error) {
	deadline := time.Now().Add(proxier.WaitTimeout)

	for {
		found, err := proxier.narOnce(ctx, w, path, hops)

		if found || err == nil || time.Now().After(deadline) {
			return found, err
		}

		proxier.Logger.Debug("waiting for a cache source", "path", path, "error", err)

		if err := sleepContext(ctx, proxier.PollInterval); err != nil {
			return false, err
		}
	}
}

func (proxier *Proxier) narOnce(ctx context.Context, w http.ResponseWriter, path string, hops int) (bool, error) {
	sources := make([]string, 0, len(proxier.Fallbacks)+1)
	interior := strings.TrimSuffix(strings.TrimPrefix(path, "/nar/"), ".nar")

	if len(interior) == 32 || (len(interior) == 85 && interior[32] == '-') {
		for _, peer := range proxier.Registry.Snapshot() {
			sources = append(sources, peer.URL)
		}
	}

	sources = append(sources, proxier.Fallbacks...)

	var transientErr error

	for _, source := range sources {
		streamed, err := proxier.streamNar(ctx, w, source, path, hops)

		if streamed {
			return true, nil
		}

		if err != nil {
			proxier.Logger.Debug("nar request failed", "source", source, "error", err)

			if isTransient(err) {
				transientErr = err
			}
		}
	}

	return false, transientErr
}

func (proxier *Proxier) streamNar(ctx context.Context, w http.ResponseWriter, source, path string, hops int) (bool, error) {
	var lastErr error

	for attempt := 0; attempt <= proxier.Retries; attempt++ {
		if attempt > 0 {
			if err := sleepContext(ctx, retryBackoff(attempt)); err != nil {
				return false, err
			}
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, source+path, nil)

		if err != nil {
			return false, err
		}

		request.Header.Set(PeerHeader, proxier.SelfID)
		request.Header.Set(HopsHeader, strconv.Itoa(hops+1))

		response, err := proxier.streamClient.Do(request)

		if err != nil {
			lastErr = err

			if !isTransient(err) || ctx.Err() != nil {
				return false, err
			}

			continue
		}

		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			lastErr = statusError{code: response.StatusCode}

			if !isTransient(lastErr) {
				return false, lastErr
			}

			continue
		}

		if length := response.Header.Get("Content-Length"); length != "" {
			w.Header().Set("Content-Length", length)
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		if _, err := io.Copy(w, response.Body); err != nil {
			proxier.Logger.Warn("nar stream interrupted", "source", source, "error", err)
		}

		response.Body.Close()
		return true, nil
	}

	return false, lastErr
}

func (proxier *Proxier) fetchNarinfo(ctx context.Context, source, hashPart string, hops int) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= proxier.Retries; attempt++ {
		if attempt > 0 {
			if err := sleepContext(ctx, retryBackoff(attempt)); err != nil {
				return nil, err
			}
		}

		body, err := proxier.fetchNarinfoOnce(ctx, source, hashPart, hops)

		if err == nil {
			return body, nil
		}

		lastErr = err

		if !isTransient(err) || ctx.Err() != nil {
			return nil, err
		}
	}

	return nil, lastErr
}

func (proxier *Proxier) fetchNarinfoOnce(ctx context.Context, source, hashPart string, hops int) ([]byte, error) {
	timeout, cancel := context.WithTimeout(ctx, proxier.Timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(timeout, http.MethodGet, source+"/"+hashPart+".narinfo", nil)

	if err != nil {
		return nil, err
	}

	request.Header.Set(PeerHeader, proxier.SelfID)
	request.Header.Set(HopsHeader, strconv.Itoa(hops+1))

	response, err := proxier.client.Do(request)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}

	if response.StatusCode != http.StatusOK {
		return nil, statusError{code: response.StatusCode}
	}

	return io.ReadAll(io.LimitReader(response.Body, maxBody))
}

type statusError struct {
	code int
}

func (err statusError) Error() string {
	return fmt.Sprintf("source returned status %d", err.code)
}

var errNotFound = errors.New("not found")

func isTransient(err error) bool {
	if errors.Is(err, errNotFound) {
		return false
	}

	var status statusError

	if errors.As(err, &status) {
		return status.code >= 500 || status.code == http.StatusTooManyRequests
	}

	return true
}

func retryBackoff(attempt int) time.Duration {
	return time.Duration(attempt) * time.Second
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validate(body []byte, hashPart string) error {
	fields, err := parseNarinfo(body)

	if err != nil {
		return err
	}

	base := fields.StorePath

	if slash := strings.LastIndexByte(base, '/'); slash >= 0 {
		base = base[slash+1:]
	}

	if !strings.HasPrefix(base, hashPart+"-") {
		return fmt.Errorf("narinfo path %q does not match requested hash %q", fields.StorePath, hashPart)
	}

	if !strings.HasPrefix(fields.NarHash, "sha256:") || len(fields.NarHash) != len("sha256:")+52 {
		return fmt.Errorf("unexpected NarHash %q", fields.NarHash)
	}

	if _, err := strconv.ParseUint(fields.NarSize, 10, 64); err != nil {
		return fmt.Errorf("invalid NarSize %q", fields.NarSize)
	}

	return nil
}

func verifyNarinfo(body []byte, storeDir string, trustedKeys []string) error {
	fields, err := parseNarinfo(body)

	if err != nil {
		return err
	}

	references := make([]string, len(fields.References))

	for index, name := range fields.References {
		references[index] = storeDir + "/" + name
	}

	fingerprint := fmt.Sprintf(
		"1;%s;%s;%s;%s",
		fields.StorePath,
		fields.NarHash,
		fields.NarSize,
		strings.Join(references, ","),
	)

	for _, signature := range fields.Signatures {
		name, encoded, ok := strings.Cut(signature, ":")

		if !ok {
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(encoded)

		if err != nil || len(raw) != ed25519.SignatureSize {
			continue
		}

		for _, key := range trustedKeys {
			keyName, keyData, ok := strings.Cut(key, ":")

			if !ok || keyName != name {
				continue
			}

			public, err := base64.StdEncoding.DecodeString(keyData)

			if err != nil || len(public) != ed25519.PublicKeySize {
				continue
			}

			if ed25519.Verify(ed25519.PublicKey(public), []byte(fingerprint), raw) {
				return nil
			}
		}
	}

	return errors.New("narinfo has no valid signature from a trusted key")
}

type narinfoFields struct {
	StorePath  string
	NarHash    string
	NarSize    string
	References []string
	Signatures []string
}

func parseNarinfo(body []byte) (narinfoFields, error) {
	var fields narinfoFields

	for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "StorePath: "):
			fields.StorePath = strings.TrimPrefix(line, "StorePath: ")
		case strings.HasPrefix(line, "NarHash: "):
			fields.NarHash = strings.TrimPrefix(line, "NarHash: ")
		case strings.HasPrefix(line, "NarSize: "):
			fields.NarSize = strings.TrimPrefix(line, "NarSize: ")
		case strings.HasPrefix(line, "References: "):
			fields.References = strings.Fields(strings.TrimPrefix(line, "References: "))
		case strings.HasPrefix(line, "Sig: "):
			fields.Signatures = append(fields.Signatures, strings.TrimPrefix(line, "Sig: "))
		}
	}

	if fields.StorePath == "" {
		return fields, errors.New("narinfo is missing StorePath")
	}

	return fields, nil
}

func normalize(body []byte) []byte {
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")

	for index, line := range lines {
		if !strings.HasPrefix(line, "URL: ") {
			continue
		}

		value := strings.TrimPrefix(line, "URL: ")

		if question := strings.IndexByte(value, '?'); question >= 0 {
			value = value[:question]
		}

		if !strings.Contains(value, "://") {
			continue
		}

		if slash := strings.LastIndexByte(value, '/'); slash >= 0 {
			value = value[slash+1:]
		}

		lines[index] = "URL: nar/" + value
	}

	return []byte(strings.Join(lines, "\n") + "\n")
}

func (proxier *Proxier) sign(body []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	kept := make([]string, 0, len(lines))

	var (
		storePath  string
		narHash    string
		narSize    uint64
		references []string
	)

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "Sig: "):
			continue
		case strings.HasPrefix(line, "StorePath: "):
			storePath = strings.TrimPrefix(line, "StorePath: ")
		case strings.HasPrefix(line, "NarHash: "):
			narHash = strings.TrimPrefix(line, "NarHash: ")
		case strings.HasPrefix(line, "NarSize: "):
			narSize, _ = strconv.ParseUint(strings.TrimPrefix(line, "NarSize: "), 10, 64)
		case strings.HasPrefix(line, "References: "):
			for _, name := range strings.Fields(strings.TrimPrefix(line, "References: ")) {
				references = append(references, proxier.StoreDir+"/"+name)
			}
		}

		kept = append(kept, line)
	}

	if storePath == "" || narHash == "" {
		return nil, errors.New("peer narinfo is missing StorePath or NarHash")
	}

	fingerprint := fmt.Sprintf("1;%s;%s;%d;%s", storePath, narHash, narSize, strings.Join(references, ","))

	signature, err := store.Sign(proxier.SecretKey, fingerprint)

	if err != nil {
		return nil, err
	}

	kept = append(kept, "Sig: "+signature)

	return []byte(strings.Join(kept, "\n") + "\n"), nil
}

func (proxier *Proxier) cached(hashPart string) ([]byte, bool) {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()

	entry, ok := proxier.cache[hashPart]

	if !ok || time.Now().After(entry.expires) {
		delete(proxier.cache, hashPart)
		return nil, false
	}

	return entry.body, true
}

func (proxier *Proxier) remember(hashPart string, body []byte) {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()

	proxier.cache[hashPart] = cacheEntry{body: body, expires: time.Now().Add(proxier.PositiveTTL)}
}

func (proxier *Proxier) recentlyMissed(hashPart string) bool {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()

	seen, ok := proxier.misses[hashPart]

	if !ok {
		return false
	}

	if time.Now().After(seen.Add(proxier.NegativeTTL)) {
		delete(proxier.misses, hashPart)
		return false
	}

	return true
}

func (proxier *Proxier) rememberMiss(hashPart string) {
	proxier.mu.Lock()
	defer proxier.mu.Unlock()

	proxier.misses[hashPart] = time.Now()
}
