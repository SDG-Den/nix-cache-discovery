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
			prober.Scan(ctx)
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
	started := time.Now()

	prober.Registry.BeginScan()

	targets := buildTargets(prober.Ranges, localPrefixes(), prober.Registry.Snapshot())

	var (
		wait       sync.WaitGroup
		workers    = make(chan struct{}, prober.Workers)
		discovered atomic.Int64
	)

	for _, address := range targets {
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

			if prober.Registry.Mark(*peer) {
				discovered.Add(1)
				prober.Logger.Info("discovered peer", "url", peer.URL, "id", peer.ID)
			}
		}(address)
	}

	wait.Wait()

	for _, peer := range prober.Registry.EndScan() {
		prober.Logger.Info("lost peer", "url", peer.URL, "id", peer.ID)
	}

	live := len(prober.Registry.Snapshot())

	prober.Logger.Debug(
		"discovery scan finished",
		"targets", len(targets),
		"discovered", discovered.Load(),
		"peers", live,
		"duration", time.Since(started),
	)

	return live
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

func buildTargets(ranges, locals []netip.Prefix, peers []registry.Peer) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	targets := make([]netip.Addr, 0, 1024)

	add := func(address netip.Addr) {
		address = address.Unmap()

		if !address.IsValid() {
			return
		}

		if _, ok := seen[address]; ok {
			return
		}

		inside := false

		for _, prefix := range ranges {
			if prefix.Contains(address) {
				inside = true
				break
			}
		}

		if !inside {
			return
		}

		seen[address] = struct{}{}
		targets = append(targets, address)
	}

	for _, peer := range peers {
		add(peer.Addr)
	}

	for _, configured := range ranges {
		for _, local := range locals {
			if intersection, ok := intersect(configured, local); ok {
				enumerate(intersection, add)
			}
		}
	}

	for _, configured := range ranges {
		enumerate(configured, add)
	}

	return targets
}

func localPrefixes() []netip.Prefix {
	var prefixes []netip.Prefix

	interfaces, err := net.Interfaces()

	if err != nil {
		return prefixes
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addresses, err := iface.Addrs()

		if err != nil {
			continue
		}

		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())

			if err != nil {
				continue
			}

			if prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
				continue
			}

			prefixes = append(prefixes, prefix.Masked())
		}
	}

	return prefixes
}

func intersect(left, right netip.Prefix) (netip.Prefix, bool) {
	if !left.IsValid() || !right.IsValid() || left.Addr().BitLen() != right.Addr().BitLen() {
		return netip.Prefix{}, false
	}

	if left.Bits() >= right.Bits() {
		if right.Contains(left.Addr()) {
			return left.Masked(), true
		}

		return netip.Prefix{}, false
	}

	if left.Contains(right.Addr()) {
		return right.Masked(), true
	}

	return netip.Prefix{}, false
}

func enumerate(prefix netip.Prefix, add func(netip.Addr)) {
	for address := prefix.Masked().Addr(); address.IsValid() && prefix.Contains(address); address = address.Next() {
		add(address)
	}
}

type errUnexpectedStatus int

func (err errUnexpectedStatus) Error() string {
	return "unexpected discovery status " + strconv.Itoa(int(err))
}

type errNotAPeer struct{}

func (errNotAPeer) Error() string { return "not a cache discovery peer" }
