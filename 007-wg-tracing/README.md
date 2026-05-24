# WireGuard eBPF Tracing

Network namespaces + netkit links + WireGuard tunnel + eBPF tracing via Rust/Aya.

<!-- topology -->
```
    cli                 net/L2                        vpn                web
┌─────────┐      ┌─────────────────────────┐   ┌──────────────┐      ┌────────┐
│ ── wg0 -│------│---------tunnel----------│---│- wg0 ────┐   │      │        │
│     |   │      │                         │   │   |      │   │      │        │
│   eth0 ═╪══nk══╪═ nk-cli ═ br0 ═ nk-vpn ═╪═══╪═ eth0  eth1 ─┼──nk──┼─ nk0   │
└─────────┘      └─────────────────────────┘   └──────────────┘      └────────┘
192.168.111.101        192.168.111.254         .111.1 / .200.1   192.168.200.80

--- plain (in tunnel)
─── plain
═══ encrypted
```
<!-- /topology -->

[Requirements](../#Requirements)

## Quick start (host kernel)

```sh
just demo           # up + status + ping checks
just enter vpn      # interactive shell (vpn:~#)
just enter cli      # open in another terminal
```

## Run in VM (custom kernel)

```sh
# Terminal 1 — boot VM
just kernel v7.0.1          # needs kvm group (usermod -aG kvm $USER)

# Inside the VM:
just demo
just enter vpn

# Terminal 2 — additional shell into the same VM
just kernel-ssh
just enter cli
```

## Enter machines

```sh
just enter vpn                       # interactive shell
just enter cli                       # interactive shell
just enter net                       # interactive shell
just enter web                       # interactive shell

just enter cli ping 192.168.200.80   # run single command
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
