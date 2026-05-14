{
  description = "knet-labs:";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          # ─── Dev ───
          # rustup
          # bpf-linker
          # cargo-generate

          # ─── Tools ───
          gnumake
          just
          which
          entr

          # ─── Kernel build tools ───
          gnumake
          flex
          bison
          bc
          perl
          openssl
          elfutils             # libelf, needed for BTF
          # dwarves              # pahole, needed for CONFIG_DEBUG_INFO_BTF
          ncurses              # menuconfig
          pkg-config
          zstd
          cpio

          # ─── Test/Bench ───
          python3
          python3Packages.pytest
          python3Packages.pytest-benchmark
          hping

          # pkgsMusl.stdenv.cc  # For musl-gcc wrapper
          # pipenv
          # bpftools
          # xdp-tools
          # stress-ng
        ];

        shellHook = ''
          rustup default stable
          rustup target add x86_64-unknown-linux-musl

          # Re-inject the system path so 'sudo' is visible
          # export PATH="$PATH:/run/current-system/sw/bin:/usr/bin:/bin"

          echo ""
          echo ">>>>> knet-labs:"
          echo    ">>>>>"
          echo -n ">>>>> "; cargo --version
          echo -n ">>>>> "; cargo +nightly --version
          echo -n ">>>>> "; rustup --version 2>/dev/null | head -n1
          echo -n ">>>>> "; rust-analyzer --version
          echo -n ">>>>> "; bpf-linker --version
          echo -n ">>>>> "; gcc   --version | head -n1 | awk '{print $1"  ", $3, $2}'
          echo -n ">>>>> "; python --version
          echo ""
        '';
      };
    };
}
