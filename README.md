# nix-cache-discovery

A Nix binary cache for a household LAN. Every host runs the same daemon on the
same port. Each daemon serves its own Nix store, finds the other daemons on the
configured prefixes, and proxies anything it does not have locally. A package
that any household host has built once can then be substituted by every other
host instead of being rebuilt.

The daemon is written in Go and links `libstore`/`libutil` through a small C++
shim adapted from [nix-serve-ng](https://github.com/aristanetworks/nix-serve-ng).

## How a request is served

For a narinfo or NAR the daemon tries, in order:

1. the local Nix store,
2. every live daemon discovered on the configured prefixes,
3. the configured `fallbackSubstituters` (for example `https://cache.nixos.org`).

Misses are cached briefly, including negative answers. A narinfo obtained from a
peer or a fallback is proxied directly; it is re-signed when a signing key is
configured.

Discovered peers are marked with an instance header. When a request arrives from
a peer that is present in the local peer registry, the daemon serves it from the
local store only. Registered peers therefore never trigger further proxying, and
a hop limit bounds the case where a peer is not registered yet. This prevents
proxy loops and discovery storms.

## NixOS usage

```nix
{
  inputs.nix-cache-discovery.url = "path:/home/den/repos/nix-cache-discovery";

  outputs = { nixpkgs, nix-cache-discovery, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nix-cache-discovery.nixosModules.default
        {
          services.nix-cache-discovery = {
            enable = true;
            port = 5000;
            discovery.ranges = [ "192.168.1.0/24" ];
          };
        }
      ];
    };
  };
}
```

That is the whole configuration. By default the module makes the local daemon
the only substituter of the host, points Nix at `http://127.0.0.1:5000`, and
trusts that local daemon directly. No key files, secrets or extra options have to
be added to the system.

The module then:

- adds `http://127.0.0.1:5000` as the substituter and trusted substituter,
  replacing the upstream substituters while `exclusive` is enabled,
- opens the port in the firewall only to `allowedClients` when `openFirewall`
  is enabled (the default),
- runs the daemon as a static system user that talks to the Nix daemon over its
  socket.

`allowedClients` is empty by default, which means `discovery.ranges`. Loopback is
always accepted and does not need to be listed. Keep `listenAddress = "0.0.0.0"`
so the loopback substituter URL keeps working; binding to a single LAN address
makes `127.0.0.1` unreachable.

### Signing and trust

No key has to be generated or distributed by default. The module sets
`require-sigs = false` and makes the local daemon the only substituter of the
host, so Nix trusts its local daemon over loopback. The daemon is then the trust
boundary:

- narinfos from `fallbackSubstituters` are verified against the host's
  `trusted-public-keys` before they are proxied;
- paths from LAN peers are trusted because only `allowedClients` can reach the
  daemon;
- paths already in the local store are trusted as usual.

The tradeoff is that Nix itself no longer checks signatures for substituters
configured outside this module. That is why `exclusive = true` is the default:
Nix never talks to an upstream cache directly. Set `exclusive = false` only if
you accept that tradeoff or configure a signing key.

If you already manage a binary cache key, set `signingKeyFile` and `publicKey`.
Narinfos are then signed with that key, `require-sigs` stays enabled, and the
public key is added to `trusted-public-keys`.

```nix
services.nix-cache-discovery = {
  enable = true;
  discovery.ranges = [ "192.168.1.0/24" ];
  signingKeyFile = "/run/secrets/household-cache-key";
  publicKey = "household-cache-1:AAAA...";
};
```

Generate a pair for manual mode with
`nix key generate-secret --key-name household-cache-1` and
`nix key convert-secret-to-public`. The key file must be readable by the
`nix-cache-discovery` system user.

### Roaming laptops

A host that leaves the household network must not keep serving its store or
scanning whatever network it joins. List the public IP addresses of the trusted
networks:

```nix
services.nix-cache-discovery = {
  enable = true;
  port = 5000;
  discovery.ranges = [ "192.168.1.0/24" ];
  trustedNetworks = [ "203.0.113.7" ];
};
```

Every `trustCheckInterval` seconds the daemon asks `publicIpUrl` for the current
network's public address. When that address is not in `trustedNetworks` it stops
discovery, forgets all peers and answers every non-loopback request with 403.
Loopback keeps working, so the local Nix client can still use the local store.
A failed lookup keeps the previous state, and the initial state is untrusted, so
a host that boots on an unknown network does not serve non-loopback clients until
it sees a trusted address. The default lookup endpoint is a third-party service;
point `publicIpUrl` at an endpoint you control if that request should not leave
your infrastructure.

### Upstream caches and substituter order

By default `exclusive = true`, so Nix only talks to this daemon. Set
`exclusive = false` if Nix should also contact upstream caches directly. The
daemon itself still prefers the local store, then LAN peers, then
`fallbackSubstituters`:

```nix
services.nix-cache-discovery = {
  enable = true;
  port = 5000;
  discovery.ranges = [ "192.168.1.0/24" ];
  exclusive = true;
  fallbackSubstituters = [ "https://cache.nixos.org" ];
};
```

Fallback NARs (including compressed `.nar.xz`, `.nar.zst` and `.nar.bz2` files)
are streamed through the daemon, so with `exclusive` enabled the upstream caches
are only contacted by the daemon. Narinfos are re-signed when a signing key is
configured.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `enable` | `false` | Enable the service. |
| `package` | built from this repository | Daemon package. |
| `port` | `5000` | Serving and discovery port. Must match on every host. |
| `listenAddress` | `"0.0.0.0"` | Bind address. |
| `allowedClients` | empty uses `discovery.ranges` | Prefixes allowed to connect; everything else gets 403, and only loopback is served outside `trustedNetworks`. |
| `priority` | `30` | Value advertised in `nix-cache-info`. |
| `discovery.ranges` | required | Prefixes scanned for peers. Max 65536 addresses. |
| `discovery.interval` | `60` | Seconds between scans. |
| `discovery.timeout` | `750` | Milliseconds per probe. |
| `discovery.workers` | `64` | Concurrent probes. |
| `fallbackSubstituters` | `[ "https://cache.nixos.org" ]` | Upstream caches checked after the local store and peers. |
| `verifyFallbackSignatures` | `true` | Verify fallback narinfos against `trusted-public-keys`. |
| `exclusive` | `true` | Make this daemon the only substituter of the host. |
| `trustedNetworks` | `[]` | Public IPs of networks where serving and discovery are allowed. |
| `publicIpUrl` | `https://api.ipify.org` | Lookup used to determine the current public IP. |
| `trustCheckInterval` | `60` | Seconds between public IP checks. |
| `signingKeyFile` | `null` | Optional signing key. |
| `publicKey` | `null` | Public half for an optional signing key. |
| `tls.enable` | `false` | Serve HTTPS and use HTTPS for discovery. |
| `tls.certFile`, `tls.keyFile` | `null` | Certificate and key. |
| `openFirewall` | `true` | Open the port to `allowedClients` only. |
| `extraArgs` | `[]` | Extra command line arguments. |

## Security model

- Inbound requests from any address that is not loopback and not inside
  `allowedClients` are rejected with 403 before routing. When the host is outside
  `trustedNetworks`, every non-loopback request is rejected regardless of
  `allowedClients`.
- Discovery only sends probes to addresses inside `discovery.ranges`, and the
  module refuses a range that is not contained in `allowedClients`.
- Peers are only registered when they answer the discovery endpoint with a
  compatible protocol version and an instance ID different from the local one.
- Outbound proxy requests go only to registered peers and explicitly configured
  fallback substituters. Request paths are validated before forwarding.
- Fallback narinfos are verified against `trusted-public-keys` before they are
  served by default.
- Narinfos are signed when a signing key is configured. Without one, the module
  sets `require-sigs = false` and keeps Nix pointed only at the local daemon;
  Nix still verifies the NAR hash of every path it downloads.
- The cache has no user authentication. While the host is on a trusted network,
  any host inside `allowedClients` can read every path in the local store that
  the daemon can see. Treat the configured ranges as the trust boundary.

TLS is optional. Peer probes accept self-signed certificates, but the host's own
Nix client must trust the certificate used by the loopback substituter URL. On a
trusted LAN, plain HTTP with a narrow `allowedClients` range is the simpler
setup.

## Development

```console
$ nix develop
$ go test ./...
$ nix build
$ nix build .#checks.x86_64-linux.vm
```

The VM test starts two household nodes and one outsider. The client substitutes
`hello` through its own daemon from the server's store, and the outsider receives
403.

`internal/store/nix.cpp` and `nix.h` are adapted from nix-serve-ng; see `NOTICE`.

## License

GPL-3.0-only. See `LICENSE`.
