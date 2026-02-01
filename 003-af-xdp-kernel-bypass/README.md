# AF_XDP Kernel Bypass

Network packets redirection to AF_XDP to bypass kernel network stack; using [xdpilone](https://docs.rs/xdpilone)

[Requirements](../#Requirements)

## Build & Run

```sh
# Build
just build

# Run
just run --iface lo   # Terminal-1
just traffic          # Terminal-2
```

## Dev

```sh
just run-dev          # Terminal-1
just traffic          # Terminal-2
```
