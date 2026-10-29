{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nix-cache-discovery;

  inherit (lib)
    concatStringsSep
    mkEnableOption
    mkIf
    mkOption
    optional
    optionals
    types
    ;

  scheme = if cfg.tls.enable then "https" else "http";
  localURL = "${scheme}://127.0.0.1:${toString cfg.port}";

  allowedClients =
    if cfg.allowedClients != [ ] then
      cfg.allowedClients
    else
      cfg.discovery.ranges;

  split = lib.partition (value: lib.hasInfix ":" value) allowedClients;

  firewallRules = concatStringsSep "\n" (
    optional (split.wrong != [ ]) "ip saddr { ${concatStringsSep ", " split.wrong} } tcp dport ${toString cfg.port} accept"
    ++ optional (split.right != [ ]) "ip6 saddr { ${concatStringsSep ", " split.right} } tcp dport ${toString cfg.port} accept"
  );

  keyFile = toString cfg.signingKeyFile;
in
{
  options.services.nix-cache-discovery = {
    enable = mkEnableOption "a LAN-discovering Nix binary cache";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      description = "The nix-cache-discovery package to run.";
    };

    port = mkOption {
      type = types.port;
      default = 5000;
      description = ''
        Port used both to serve the cache and to scan for peers.
        Every host that should discover each other must use the same port.
      '';
    };

    listenAddress = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address the HTTP(S) server binds to.";
    };

    allowedClients = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "192.168.1.0/24" ];
      description = ''
        Client prefixes allowed to connect and the only prefixes the daemon
        probes during discovery. Requests from any other address are answered
        with 403. An empty list uses
        {option}`services.nix-cache-discovery.discovery.ranges`.
      '';
    };

    priority = mkOption {
      type = types.int;
      default = 30;
      description = "Binary cache priority advertised in nix-cache-info.";
    };

    fallbackSubstituters = mkOption {
      type = types.listOf types.str;
      default = [ "https://cache.nixos.org" ];
      example = [ "https://cache.nixos.org" ];
      description = ''
        Upstream binary caches consulted only after the local store and all
        live LAN peers. Their narinfos are verified when
        {option}`services.nix-cache-discovery.verifyFallbackSignatures` is
        enabled, then proxied, so their NARs also travel through this host.
      '';
    };

    exclusive = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Make this daemon the only substituter of the host. Nix then never
        talks to an upstream cache directly, and all substitution goes through
        this daemon, which prefers LAN peers and verifies upstream narinfos
        when {option}`services.nix-cache-discovery.verifyFallbackSignatures`
        is enabled.
      '';
    };

    trustedNetworks = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "203.0.113.7" ];
      description = ''
        Public IP addresses (or prefixes) of networks where this daemon may
        serve and discover peers. On any other network it stops discovery,
        drops known peers and refuses every non-loopback client, while
        loopback keeps working. Empty disables the check.
      '';
    };

    publicIpUrl = mkOption {
      type = types.str;
      default = "https://api.ipify.org";
      description = ''
        URL that returns the public IP of the current network as plain text.
        Only used when
        {option}`services.nix-cache-discovery.trustedNetworks` is non-empty.
      '';
    };

    trustCheckInterval = mkOption {
      type = types.ints.positive;
      default = 60;
      description = "Seconds between public IP checks.";
    };

    discovery = {
      ranges = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "192.168.1.0/24" ];
        description = ''
          Prefixes scanned for other instances on the configured port. Local
          subnets inside these ranges are scanned first. At most 65536
          addresses in total.
        '';
      };

      interval = mkOption {
        type = types.ints.positive;
        default = 60;
        description = "Seconds between discovery scans.";
      };

      timeout = mkOption {
        type = types.ints.positive;
        default = 500;
        description = "Milliseconds allowed for each probe.";
      };

      workers = mkOption {
        type = types.ints.positive;
        default = 256;
        description = "Number of concurrent probes during a scan.";
      };
    };

    tls = {
      enable = mkEnableOption "TLS for the cache and for peer communication";

      certFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "TLS certificate used for HTTPS.";
      };

      keyFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "TLS private key used for HTTPS.";
      };
    };

    signingKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Optional binary cache signing key. When unset, this host does not sign
        narinfos and Nix trusts its local daemon directly through
        `nix.settings.require-sigs` = false. When set, narinfos are signed and
        {option}`services.nix-cache-discovery.publicKey` is added to
        `nix.settings.trusted-public-keys` instead.
      '';
    };

    publicKey = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "household-cache-1:base64...";
      description = "Public half of {option}`services.nix-cache-discovery.signingKeyFile`.";
    };

    verifyFallbackSignatures = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Verify narinfo signatures from
        {option}`services.nix-cache-discovery.fallbackSubstituters` against
        `nix.settings.trusted-public-keys` before proxying them. LAN peers are
        not checked because they are trusted by network membership, not by a
        distributed key.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = true;
      description = "Open the cache port to the allowed client prefixes only.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra command line arguments for nix-cache-discovery.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.discovery.ranges != [ ];
        message = "services.nix-cache-discovery.discovery.ranges must not be empty.";
      }
      {
        assertion = cfg.signingKeyFile == null || cfg.publicKey != null;
        message = "services.nix-cache-discovery.signingKeyFile requires publicKey.";
      }
      {
        assertion = cfg.tls.enable -> (cfg.tls.certFile != null && cfg.tls.keyFile != null);
        message = "TLS requires both certFile and keyFile.";
      }
    ];

    users.groups.nix-cache-discovery = { };

    users.users.nix-cache-discovery = {
      isSystemUser = true;
      group = "nix-cache-discovery";
    };

    nix.settings.extra-allowed-users = [ "nix-cache-discovery" ];
    nix.settings.substituters =
      if cfg.exclusive then lib.mkForce [ localURL ] else lib.mkBefore [ localURL ];
    nix.settings.trusted-substituters =
      if cfg.exclusive then lib.mkForce [ localURL ] else lib.mkBefore [ localURL ];
    nix.settings.trusted-public-keys = optional (cfg.publicKey != null) cfg.publicKey;
    nix.settings.require-sigs = mkIf (cfg.signingKeyFile == null) false;

    systemd.services.nix-cache-discovery = {
      description = "LAN-discovering Nix binary cache";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
        "nix-daemon.service"
      ];

      serviceConfig = {
        User = "nix-cache-discovery";
        Group = "nix-cache-discovery";

        ExecStart = lib.escapeShellArgs (
          [
            "${cfg.package}/bin/nix-cache-discovery"
            "--host"
            cfg.listenAddress
            "--port"
            (toString cfg.port)
            "--priority"
            (toString cfg.priority)
            "--store"
            "daemon"
            "--allowed-clients"
            (concatStringsSep "," allowedClients)
            "--discovery-range"
            (concatStringsSep "," cfg.discovery.ranges)
            "--discovery-interval"
            "${toString cfg.discovery.interval}s"
            "--discovery-timeout"
            "${toString cfg.discovery.timeout}ms"
            "--discovery-workers"
            (toString cfg.discovery.workers)
          ]
          ++ optionals (cfg.fallbackSubstituters != [ ]) [
            "--fallback-substituter"
            (concatStringsSep "," cfg.fallbackSubstituters)
          ]
          ++ map (key: "--trusted-public-key=${key}") config.nix.settings.trusted-public-keys
          ++ [
            "--verify-fallback-signatures=${lib.boolToString cfg.verifyFallbackSignatures}"
            "--public-ip-url"
            cfg.publicIpUrl
            "--trust-check-interval"
            "${toString cfg.trustCheckInterval}s"
          ]
          ++ optionals (cfg.trustedNetworks != [ ]) [
            "--trusted-network"
            (concatStringsSep "," cfg.trustedNetworks)
          ]
          ++ optionals cfg.tls.enable [
            "--tls-cert"
            (toString cfg.tls.certFile)
            "--tls-key"
            (toString cfg.tls.keyFile)
          ]
          ++ optionals (cfg.signingKeyFile != null) [
            "--secret-key-file"
            keyFile
          ]
          ++ cfg.extraArgs
        );

        Restart = "always";
        RestartSec = "5s";

        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
      };
    };

    networking.firewall.extraInputRules = mkIf cfg.openFirewall firewallRules;
  };
}
