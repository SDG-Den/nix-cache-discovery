package discovery

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/den/nix-cache-discovery/internal/registry"
)

const (
	InfoPath = "/.nix-cache-discovery/v1/info"
	Version  = "1"
)

type Prober struct {
	Ranges   []netip.Prefix
	Port     int
	Timeout  time.Duration
	Workers  int
	Scheme   string
	SelfID   string
	Gate     func() bool
	Registry *registry.Registry
	Logger   *slog.Logger

	client *http.Client
}

func New(ranges []netip.Prefix, port int, timeout time.Duration, workers int, scheme, selfID string, peers *registry.Registry, logger *slog.Logger) *Prober {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		DisableKeepAlives: true,
		MaxIdleConns:      0,
	}

	if scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Prober{
		Ranges:   ranges,
		Port:     port,
		Timeout:  timeout,
		Workers:  workers,
		Scheme:   scheme,
		SelfID:   selfID,
		Registry: peers,
		Logger:   logger,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

func (prober *Prober) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if prober.Gate == nil || prober.Gate() {
			started := time.Now()
			found := prober.Scan(ctx)

			prober.Logger.Debug("discovery scan finished", "peers", found, "duration", time.Since(started))
		} else {
			prober.Logger.Debug("skipping discovery scan outside trusted networks")
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (prober *Prober) Scan(ctx context.Context) int {
	var (
		wait    sync.WaitGroup
		found   atomic.Int64
		workers = make(chan struct{}, prober.Workers)
	)

	for _, prefix := range prober.Ranges {
		for address := prefix.Masked().Addr(); address.IsValid() && prefix.Contains(address); address = address.Next() {
			if ctx.Err() != nil {
				break
			}

			wait.Add(1)
			workers <- struct{}{}

			go func(address netip.Addr) {
				defer wait.Done()
				defer func() { <-workers }()

				peer, err := prober.probe(ctx, address)

				if err != nil {
					return
				}

				prober.Registry.Mark(*peer)
				found.Add(1)
			}(address)
		}
	}

	wait.Wait()

	return int(found.Load())
}

func (prober *Prober) probe(ctx context.Context, address netip.Addr) (*registry.Peer, error) {
	base := prober.Scheme + "://" + net.JoinHostPort(address.String(), strconv.Itoa(prober.Port))
	timeout, cancel := context.WithTimeout(ctx, prober.Timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(timeout, http.MethodGet, base+InfoPath, nil)

	if err != nil {
		return nil, err
	}

	response, err := prober.client.Do(request)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errUnexpectedStatus(response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))

	if err != nil {
		return nil, err
	}

	fields := make(map[string]string)

	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(line, "=")

		if ok {
			fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	id := fields["id"]

	if id == "" || id == prober.SelfID || fields["version"] != Version {
		return nil, errNotAPeer{}
	}

	return &registry.Peer{
		ID:       id,
		URL:      base,
		Addr:     address,
		LastSeen: time.Now(),
	}, nil
}

type errUnexpectedStatus int

func (err errUnexpectedStatus) Error() string {
	return "unexpected discovery status " + strconv.Itoa(int(err))
}

type errNotAPeer struct{}

func (errNotAPeer) Error() string { return "not a cache discovery peer" }
