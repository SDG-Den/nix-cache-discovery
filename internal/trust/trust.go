package trust

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const maxBody = 128

type Monitor struct {
	networks []netip.Prefix
	url      string
	client   *http.Client
	logger   *slog.Logger
	trusted  atomic.Bool
}

func New(networks []netip.Prefix, url string, timeout time.Duration, logger *slog.Logger) *Monitor {
	return &Monitor{
		networks: networks,
		url:      url,
		client:   &http.Client{Timeout: timeout},
		logger:   logger,
	}
}

func (monitor *Monitor) Enabled() bool {
	return len(monitor.networks) > 0
}

func (monitor *Monitor) Trusted() bool {
	if !monitor.Enabled() {
		return true
	}

	return monitor.trusted.Load()
}

func (monitor *Monitor) Run(ctx context.Context, interval time.Duration, onChange func(bool)) {
	monitor.Refresh(onChange)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			monitor.Refresh(onChange)
		}
	}
}

func (monitor *Monitor) Refresh(onChange func(bool)) {
	if !monitor.Enabled() {
		return
	}

	address, err := monitor.publicAddress()

	if err != nil {
		monitor.logger.Debug("cannot determine public address, keeping current trust state", "error", err)
		return
	}

	trusted := false

	for _, network := range monitor.networks {
		if network.Contains(address) {
			trusted = true
			break
		}
	}

	if previous := monitor.trusted.Swap(trusted); previous != trusted {
		monitor.logger.Info("trusted network state changed", "trusted", trusted, "publicAddress", address)

		if onChange != nil {
			onChange(trusted)
		}
	}
}

func (monitor *Monitor) publicAddress() (netip.Addr, error) {
	response, err := monitor.client.Get(monitor.url)

	if err != nil {
		return netip.Addr{}, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, errors.New("public address lookup returned " + response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody))

	if err != nil {
		return netip.Addr{}, err
	}

	address, err := netip.ParseAddr(strings.TrimSpace(string(body)))

	if err != nil {
		return netip.Addr{}, err
	}

	return address.Unmap(), nil
}

func IsTrusted(address netip.Addr, networks []netip.Prefix) bool {
	if len(networks) == 0 {
		return true
	}

	for _, network := range networks {
		if network.Contains(address) {
			return true
		}
	}

	return false
}
