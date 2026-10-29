{
  lib,
  buildGoModule,
  pkg-config,
  nix,
  boost,
}:

buildGoModule {
  pname = "nix-cache-discovery";
  version = "0.1.0";

  src = lib.cleanSource ./..;

  vendorHash = null;

  nativeBuildInputs = [ pkg-config ];

  buildInputs = [
    (lib.getDev nix)
    nix
    boost.dev
  ];

  env.CGO_ENABLED = "1";
  env.CXXFLAGS = "-std=c++23";

  meta = {
    description = "Nix binary cache that discovers and proxies LAN peers";
    license = lib.licenses.gpl3Only;
    mainProgram = "nix-cache-discovery";
    platforms = lib.platforms.linux;
  };
}
