# Rust+eBPF Labs (Research / Benchmarks / Examples)

## Labs

- [001](./001_xdp_ringbuf_vs_perf): Bench: **Ringbuf vs Perf** — **XDP** to user-space packet transfer
- [002](./002_af_xdp_kernel_bypass): Linux kernel network bypass via **AF_XDP** using [xdpilone](https://docs.rs/xdpilone)

## Requirements

- [rustup](https://rustup.rs/)
- [just](https://github.com/casey/just) (optional)

```sh
# Prep option 1: nix+direnv
direnv allow

# Prep option 2: nix
nix develop
```
