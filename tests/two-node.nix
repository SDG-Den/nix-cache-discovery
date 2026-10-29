{ pkgs }:

let
  port = 5055;
  hello = pkgs.hello;
  helloPath = toString hello;
  helloHash = builtins.substring 0 32 (baseNameOf helloPath);
in
pkgs.testers.nixosTest {
  name = "nix-cache-discovery";

  nodes.server =
    { lib, ... }:
    {
      imports = [ ../nix/module.nix ];

      virtualisation.vlans = [ 1 ];

      networking = {
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.168.1.1";
            prefixLength = 24;
          }
          {
            address = "10.0.0.1";
            prefixLength = 24;
          }
        ];
      };

      services.nix-cache-discovery = {
        enable = true;
        port = port;
        discovery = {
          ranges = [ "192.168.1.0/24" ];
          interval = 5;
        };
      };

      environment.systemPackages = [ hello ];
    };

  nodes.client =
    { lib, ... }:
    {
      imports = [ ../nix/module.nix ];

      virtualisation.vlans = [ 1 ];

      networking = {
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "192.168.1.2";
            prefixLength = 24;
          }
        ];
      };

      services.nix-cache-discovery = {
        enable = true;
        port = port;
        discovery = {
          ranges = [ "192.168.1.0/24" ];
          interval = 5;
        };
      };
    };

  nodes.outsider =
    { lib, ... }:
    {
      virtualisation.vlans = [ 1 ];

      networking = {
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = lib.mkForce [
          {
            address = "10.0.0.3";
            prefixLength = 24;
          }
        ];
      };
    };

  testScript = ''
    start_all()

    for machine in (server, client):
        machine.wait_for_unit("nix-cache-discovery.service")
        machine.wait_for_open_port(${toString port})

    # The client has no copy of hello, so this narinfo can only come from the
    # server through the client's own daemon.
    client.wait_until_succeeds(
        "curl -sf http://127.0.0.1:${toString port}/${helloHash}.narinfo | grep -q 'StorePath: ${helloPath}'",
        timeout=180,
    )

    client.succeed("nix-store --realise ${helloPath}")
    client.succeed("test -x ${helloPath}/bin/hello")

    status = outsider.succeed(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://10.0.0.1:${toString port}/nix-cache-info"
    )
    assert status.strip() == "403", f"expected 403 for outsider, got {status!r}"
  '';
}
