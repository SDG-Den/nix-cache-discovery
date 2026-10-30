package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const maxScannedHosts = 65536

type Config struct {
	Host                     string
	Port                     int
	Priority                 int
	StoreURI                 string
	AllowedClients           []netip.Prefix
	DiscoveryRanges          []netip.Prefix
	Fallbacks                []string
	TrustedKeys              []string
	VerifyFallbackSignatures bool
	DiscoveryAuto            bool
	ProxyTimeout             time.Duration
	ProxyRetries             int
	ProxyWait                time.Duration
	TrustedNetworks          []netip.Prefix
	PublicIPURL              string
	TrustCheckInterval       time.Duration
	DiscoveryInterval        time.Duration
	DiscoveryTimeout         time.Duration
	DiscoveryWorkers         int
	TLSCertFile              string
	TLSKeyFile               string
	SecretKeyFile            string
	SecretKey                string
	LogLevel                 string
	InstanceID               string
}

func ParsePrefixes(values []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix

	for _, value := range values {
		value = strings.TrimSpace(value)

		if value == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(value)

		if err != nil {
			address, addressErr := netip.ParseAddr(value)

			if addressErr != nil {
				return nil, fmt.Errorf("invalid prefix %q: %w", value, err)
			}

			prefix = netip.PrefixFrom(address, address.BitLen())
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, nil
}

func (cfg *Config) Validate() error {
	switch {
	case cfg.Port < 1 || cfg.Port > 65535:
		return fmt.Errorf("port %d is outside 1-65535", cfg.Port)
	case cfg.DiscoveryWorkers < 1:
		return fmt.Errorf("discovery workers must be at least 1")
	case cfg.DiscoveryInterval < time.Second:
		return fmt.Errorf("discovery interval must be at least 1s")
	case cfg.DiscoveryTimeout <= 0:
		return fmt.Errorf("discovery timeout must be positive")
	case cfg.ProxyTimeout <= 0:
		return fmt.Errorf("proxy timeout must be positive")
	case cfg.ProxyRetries < 0:
		return fmt.Errorf("proxy retries must not be negative")
	case cfg.ProxyWait <= 0:
		return fmt.Errorf("proxy wait must be positive")
	case len(cfg.DiscoveryRanges) == 0:
		return fmt.Errorf("at least one discovery range is required")
	case len(cfg.AllowedClients) == 0:
		return fmt.Errorf("at least one allowed client prefix is required")
	}

	total := 0

	for _, prefix := range cfg.DiscoveryRanges {
		total += hostCount(prefix)

		if total > maxScannedHosts {
			return fmt.Errorf("discovery ranges exceed %d addresses", maxScannedHosts)
		}
	}

	for _, scanned := range cfg.DiscoveryRanges {
		inside := false

		for _, allowed := range cfg.AllowedClients {
			if allowed.Contains(scanned.Addr()) && allowed.Bits() <= scanned.Bits() {
				inside = true
				break
			}
		}

		if !inside {
			return fmt.Errorf("discovery range %s is not inside any allowed client prefix", scanned)
		}
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("tls cert and key must be configured together")
	}

	if len(cfg.TrustedNetworks) > 0 {
		if cfg.PublicIPURL == "" {
			return fmt.Errorf("trusted networks require a public ip lookup url")
		}

		if cfg.TrustCheckInterval <= 0 {
			return fmt.Errorf("trust check interval must be positive")
		}
	}

	for _, fallback := range cfg.Fallbacks {
		if !strings.HasPrefix(fallback, "http://") && !strings.HasPrefix(fallback, "https://") {
			return fmt.Errorf("fallback substituter %q must be an http or https URL", fallback)
		}
	}

	return nil
}

func ListenAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func hostCount(prefix netip.Prefix) int {
	if !prefix.IsValid() {
		return 0
	}

	bits := prefix.Addr().BitLen() - prefix.Bits()

	if bits >= 20 {
		return maxScannedHosts + 1
	}

	return 1 << bits
}
