{ nixpkgs ? import <nixpkgs> {} }:
let
  unstable = import (fetchTarball "https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz") { };
  # rustupFlagFile = ".lock-rustup";
in
with nixpkgs; mkShell {
  buildInputs = [
    # unstable.rustup
    # unstable.cargo-generate
    # llvmPackages_19.clang
    just

    # python3
    pipenv

    # Requirements for `cargo install cargo-generate`
    gcc
    openssl
    pkg-config

    # other tools
    bpftools
    xdp-tools
    stress-ng
  ];

  shellHook = ''
    unset TMPDIR || set -e TMPDIR || true

    echo ""
    echo    ">>>>> rust_ebpf_playground:"
    echo    ">>>>>"
    echo -n ">>>>> "; gcc   --version | head -n1 | awk '{print $1"  ", $3, $2}'
    echo -n ">>>>> "; rustup --version 2>/dev/null | head -n1
    echo -n ">>>>> "; cargo --version
    echo -n ">>>>> "; cargo +nightly --version
    echo -n ">>>>> "; rust-analyzer --version
    echo -n ">>>>> "; bpf-linker --version
    echo -n ">>>>> "; python --version
    echo ""
  '';
}
