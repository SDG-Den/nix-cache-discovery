{
  lib,
  mkShell,
  go,
  gopls,
  gotools,
  pkg-config,
  nix,
  boost,
  gcc,
  gdb,
  sqlite,
  curl,
  jq,
  git,
}:

mkShell {
  packages = [
    go
    gopls
    gotools
    pkg-config
    (lib.getDev nix)
    nix
    boost.dev
    gcc
    gdb
    sqlite
    curl
    jq
    git
  ];

  env.CGO_ENABLED = "1";
  env.CXXFLAGS = "-std=c++23";
}
