package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/den/nix-cache-discovery/internal/config"
	"github.com/den/nix-cache-discovery/internal/discovery"
	"github.com/den/nix-cache-discovery/internal/proxy"
	"github.com/den/nix-cache-discovery/internal/registry"
	"github.com/den/nix-cache-discovery/internal/server"
	"github.com/den/nix-cache-discovery/internal/store"
	"github.com/den/nix-cache-discovery/internal/trust"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		cfg            config.Config
		allowedClients listFlag
		discoveryRange listFlag
		fallbacks      listFlag
		trustedKeys    listFlag
		trustedNets    listFlag
	)

	flag.StringVar(&cfg.Host, "host", "0.0.0.0", "address to listen on")
	flag.IntVar(&cfg.Port, "port", 5000, "port to listen on and scan")
	flag.IntVar(&cfg.Priority, "priority", 30, "binary cache priority")
	flag.StringVar(&cfg.StoreURI, "store", "daemon", "nix store URI")
	flag.Var(&allowedClients, "allowed-clients", "comma separated client prefixes allowed to connect")
	flag.Var(&discoveryRange, "discovery-range", "comma separated prefixes to scan for peers")
	flag.Var(&fallbacks, "fallback-substituter", "comma separated upstream cache URLs queried after local store and peers")
	flag.Var(&trustedKeys, "trusted-public-key", "trusted public key used to verify fallback narinfos, repeatable")
	flag.BoolVar(&cfg.VerifyFallbackSignatures, "verify-fallback-signatures", true, "verify narinfo signatures from fallback substitutes")
	flag.Var(&trustedNets, "trusted-network", "comma separated public IPs or prefixes where serving and discovery are allowed")
	flag.StringVar(&cfg.PublicIPURL, "public-ip-url", "https://api.ipify.org", "URL returning this network's public IP address")
	flag.DurationVar(&cfg.TrustCheckInterval, "trust-check-interval", time.Minute, "time between public IP checks")
	flag.DurationVar(&cfg.DiscoveryInterval, "discovery-interval", time.Minute, "time between discovery scans")
	flag.DurationVar(&cfg.DiscoveryTimeout, "discovery-timeout", 750*time.Millisecond, "timeout for each peer probe")
	flag.IntVar(&cfg.DiscoveryWorkers, "discovery-workers", 64, "concurrent discovery probes")
	flag.StringVar(&cfg.TLSCertFile, "tls-cert", "", "TLS certificate file")
	flag.StringVar(&cfg.TLSKeyFile, "tls-key", "", "TLS key file")
	flag.StringVar(&cfg.SecretKeyFile, "secret-key-file", os.Getenv("NIX_SECRET_KEY_FILE"), "binary cache signing key file")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug, info, warn or error")
	flag.StringVar(&cfg.InstanceID, "instance-id", "", "instance identifier used to exclude this host from discovery")
	flag.Parse()

	var err error

	cfg.DiscoveryRanges, err = config.ParsePrefixes(discoveryRange)

	if err != nil {
		return err
	}

	cfg.AllowedClients, err = config.ParsePrefixes(allowedClients)

	if err != nil {
		return err
	}

	for _, fallback := range fallbacks {
		cfg.Fallbacks = append(cfg.Fallbacks, strings.TrimSuffix(fallback, "/"))
	}

	cfg.TrustedKeys = append(cfg.TrustedKeys, trustedKeys...)

	cfg.TrustedNetworks, err = config.ParsePrefixes(trustedNets)

	if err != nil {
		return err
	}

	if len(cfg.AllowedClients) == 0 {
		cfg.AllowedClients = cfg.DiscoveryRanges
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = randomID()

		if err != nil {
			return err
		}
	}

	if cfg.SecretKeyFile != "" {
		key, err := os.ReadFile(cfg.SecretKeyFile)

		if err != nil {
			return fmt.Errorf("cannot read signing key: %w", err)
		}

		cfg.SecretKey = strings.TrimSpace(string(key))
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	if cfg.VerifyFallbackSignatures && len(cfg.TrustedKeys) == 0 {
		logger.Warn("fallback signature verification is enabled but no trusted public keys are configured")
	}

	if err := store.Init(cfg.StoreURI); err != nil {
		return fmt.Errorf("cannot open nix store %q: %w", cfg.StoreURI, err)
	}

	storeDir, err := store.StoreDir()

	if err != nil {
		return fmt.Errorf("cannot determine store directory: %w", err)
	}

	scheme := "http"

	if cfg.TLSCertFile != "" {
		scheme = "https"
	}

	ttl := 3 * cfg.DiscoveryInterval

	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}

	peers := registry.New(ttl)
	monitor := trust.New(cfg.TrustedNetworks, cfg.PublicIPURL, 5*time.Second, logger)
	prober := discovery.New(cfg.DiscoveryRanges, cfg.Port, cfg.DiscoveryTimeout, cfg.DiscoveryWorkers, scheme, cfg.InstanceID, peers, logger)
	prober.Gate = monitor.Trusted
	proxier := proxy.New(peers, storeDir, cfg.SecretKey, cfg.InstanceID, cfg.Fallbacks, cfg.TrustedKeys, cfg.VerifyFallbackSignatures, 10*time.Second, scheme, logger)

	handler := server.New(server.Options{
		StoreDir:   storeDir,
		Priority:   cfg.Priority,
		Port:       cfg.Port,
		InstanceID: cfg.InstanceID,
		Allowlist:  cfg.AllowedClients,
		SecretKey:  cfg.SecretKey,
		Peers:      peers,
		Proxier:    proxier,
		Trusted:    monitor.Trusted,
		Logger:     logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	onTrustChange := func(trusted bool) {
		if !trusted {
			peers.Clear()
		}
	}

	monitor.Refresh(onTrustChange)
	go monitor.Run(ctx, cfg.TrustCheckInterval, onTrustChange)
	go prober.Run(ctx, cfg.DiscoveryInterval)

	httpServer := &http.Server{
		Addr:              config.ListenAddress(cfg.Host, cfg.Port),
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info(
		"starting cache",
		"address", httpServer.Addr,
		"store", cfg.StoreURI,
		"storeDir", storeDir,
		"instance", cfg.InstanceID,
		"ranges", fmt.Sprint(cfg.DiscoveryRanges),
		"allowedClients", fmt.Sprint(cfg.AllowedClients),
		"signed", cfg.SecretKey != "",
	)

	failures := make(chan error, 1)

	go func() {
		if cfg.TLSCertFile != "" {
			failures <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}

		failures <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return httpServer.Shutdown(shutdown)
}

func newLogger(level string) *slog.Logger {
	parsed := slog.LevelInfo

	switch strings.ToLower(level) {
	case "debug":
		parsed = slog.LevelDebug
	case "warn":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parsed}))
}

func randomID() (string, error) {
	bytes := make([]byte, 8)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

type listFlag []string

func (list *listFlag) String() string {
	return strings.Join(*list, ",")
}

func (list *listFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)

		if item != "" {
			*list = append(*list, item)
		}
	}

	return nil
}
