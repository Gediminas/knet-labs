# Rust + eBPF Labs

## Labs

- [000](./000-legacy): Legacy projects
- [001](./001-xdp-ringbuf-vs-perf): Benchmark: **Ringbuf vs Perf** — **XDP** packet delivery to userspace
- [002](./002-xdp-ringbuf-dump): **XDP** packet capture with userspace delivery via **ringbuf**
- [003](./003-af-xdp-kernel-bypass): **AF_XDP**–based Linux kernel bypass using [xdpilone](https://docs.rs/xdpilone)


## Requirements

- [rustup](https://rustup.rs/)
- [just](https://github.com/casey/just) (optional)

```sh
# Prep option 1: nix + direnv
direnv allow

# Prep option 2: nix
nix develop
```
