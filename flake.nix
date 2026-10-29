{
  description = "In-home Nix binary cache with LAN auto-discovery";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forEachSystem = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forEachSystem (
        pkgs:
        rec {
          default = pkgs.callPackage ./nix/package.nix { };
          nix-cache-discovery = default;
        }
      );

      devShells = forEachSystem (pkgs: {
        default = pkgs.callPackage ./nix/devshell.nix { };
      });

      nixosModules.default = import ./nix/module.nix;
      nixosModules.nix-cache-discovery = self.nixosModules.default;

      checks = forEachSystem (pkgs: {
        package = self.packages.${pkgs.system}.default;
        vm = import ./tests/two-node.nix { inherit pkgs; };
      });
    };
}
