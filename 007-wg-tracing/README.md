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

## Privileges

Two tools provide elevation:

- **sudo** (required) — `up`/`down` create/destroy network namespaces, which needs
  real root: writing `/run/netns` is permission-gated (DAC), and capabilities don't
  bypass that. Sudo is scoped to the `ip`/`wg` calls inside the recipes, not the
  whole recipe, so only the privileged syscalls run as root.
- **capsh** / libcap (for `just caps`) — opens a sudo-once session holding
  `cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin`, enough to run `enter`/`ping`/
  poc-style commands without per-command sudo. It intentionally omits
  `cap_dac_override`, so it can't create namespaces — run `up`/`down` with sudo.

Run `up`/`down` from a normal terminal (real root); use `just caps` for repeated
namespace/poc commands without re-typing your password.

## Quick start

```sh
# Terminal 1
just up     # `just link=veth up` for older kernels
just caps
just run

# Terminal 2
just caps
just enter cli ping 192.168.222.80 -c 3  # or `just ping`
```

## Capability shell (sudo once)

`just caps` opens a shell holding `cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin`
(password once, dropped on `exit`). Inside it, namespace commands run without
per-command sudo:

```sh
just caps
ip netns exec k007-cli ping 192.168.222.80
ip netns exec k007-vpn tcpdump -i eth0 -nl
```

Note: `poc` still requires real root (`getuid() == 0`), so run it via
`just enter vpn ./…/poc` or `just dev` — not from inside `just caps`.

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
just dev-build                   # watch + build
just dev                         # watch + build + run in vpn ns
just dev --wg wg0 --iface eth0   # with args
just dev-host                    # watch + build + run on host
just dev-run                     # watch + run (entr)
```
