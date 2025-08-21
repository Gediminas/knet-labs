# PoC AF_XDP Kernel Network Bypass

PoC: Network packets redirection to AF_XDP to bypass kernel network stack; using [xdpilone](https://docs.rs/xdpilone)


## Build & Run

[Requirements](../#Requirements)

```sh
# Terminal-1
just build
just root
just run --iface lo

# Terminal-2
just traffic
```

## Dev

```sh
# Terminal-1
just build
just root
just run-dev         

# Terminal-2
just traffic
```
