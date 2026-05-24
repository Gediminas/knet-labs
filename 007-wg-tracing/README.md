# WireGuard eBPF Tracing

Network namespaces + netkit/veth links + WireGuard tunnel + eBPF tracing via Rust/Aya.

<!-- topology -->
```
    cli  10.5.5.101        net/L2          10.5.0.1  vpn                web
┌─────────┐      ┌─────────────────────────┐   ┌──────────────┐      ┌────────┐
│ ── wg0 -│------│---------tunnel----------│---│- wg0 ────┐   │      │        │
│     |   │      │                         │   │   |      │   │      │        │
│   eth0 ═╪══════╪═ nk-cli ═ br0 ═ nk-vpn ═╪═══╪═ eth0  eth1 ─┼──────┼─ nk0   │
└─────────┘      └─────────────────────────┘   └──────────────┘      └────────┘
192.168.111.101        192.168.111.254         .111.1 / .222.1   192.168.222.80

--- plain packets (inside tunnel)
─── plain packets
═══ encrypted packets
```
<!-- /topology -->

[Requirements](../#Requirements)

## Quick start

```sh
# Terminal 1
just build
just up     # `just [link=veth] up` for older kernels
just status # Optional
just enter vpn ./target/x86_64-unknown-linux-musl/debug/poc

# Terminal 2
just enter cli ping 192.168.222.80 -c 3
```

## Run in VM (custom kernel)

```sh
just kernel v7.0.1    # Terminal 1 — boot VM (needs kvm group: `usermod -aG kvm $USER`)
just kernel-ssh       # Terminal 2 — connect to running VM
```

## Enter machines

```sh
just enter vpn                       # interactive shell
just enter cli                       # interactive shell
just enter net                       # interactive shell
just enter web                       # interactive shell

just enter cli ping 192.168.222.80   # run single command
just enter vpn tcpdump -i eth0 -nl   # capture traffic
just enter vpn wg show               # inspect WireGuard
```

## Lab lifecycle

```sh
just up             # create namespaces, links, WireGuard, routes
just down           # tear down
just reload         # down + up
just status         # topology + live state
just ping           # verbose connectivity checks
```

## Dev (eBPF tracing)

```sh
just dev-build                      # watch + build
just dev-ns                         # watch + build + run in vpn ns
just dev-ns --wg wg0 --iface eth0   # with args
```
