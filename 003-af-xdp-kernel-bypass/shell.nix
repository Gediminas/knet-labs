{ pkgs ? import <nixpkgs> {} }:

let
  buildDeps = with pkgs; [ git gnumake ];
  devDeps = with pkgs; buildDeps ++ [
    # rustup
    # cargo-generate
    cargo-watch
    # rust-analyzer
    # bpf-linker

    just
  ];
in

pkgs.mkShell {
  buildInputs = devDeps;

  shellHook = ''
    #curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    #source "$HOME/.cargo/env.fish"

    #curl -L "https://github.com/aya-rs/bpf-linker/releases/download/v0.9.14/bpf-linker-x86_64-unknown-linux-gnu.tar.gz" | tar xzv -C /usr/bin/
     
    # rustup default stable
    # rustup target add x86_64-unknown-linux-musl
    # rustup toolchain install nightly --component rust-src

    # echo ">>>>>"
    # CUR=$(rustc --print sysroot)
    # PIN=$(echo $CUR | sed -E 's/nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}/nightly/')
    # echo ">>>>> Pin: $CUR"
    # echo ">>>>>  to: $PIN"
    # rm -rf "PIN"
    # # cp "$CUR" "$PIN"
    # rm -rf "$PIN"

    echo ""
    echo    ">>>>> AuthBPF (PoC):"
    echo    ">>>>>"
    echo -n ">>>>> "; gcc   --version | head -n1 | awk '{print $1"  ", $3, $2}'
    echo -n ">>>>> "; cargo --version
    echo -n ">>>>> "; bpf-linker --version
    echo -n ">>>>> "; rust-analyzer --version
    echo ""
  '';
}
