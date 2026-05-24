# virtme-ng + netns + netkit + WireGuard

Network namespaces + netkit/veth links + WireGuard tunnel — runnable on any kernel via [virtme-ng](https://github.com/arighi/virtme-ng).

<!-- topology -->
```
    cli  10.5.5.101   10.5.0.1  vpn                      web
 ┌─────────┐             ┌───────────────┐            ┌────────┐
 │ ── wg0 -│---tunnel----│- wg0 ────┐    │            │        │
 │     ↕   │             │   ↕      │    │            │        │
 │   eth0 ═╪══ netkit ═══╪═ eth0   eth1 ─┼───netkit───┼─ nk0   │
 └─────────┘             └───────────────┘            └────────┘
 192.168.111.101   192.168.111.1 / 192.168.222.1  192.168.222.80

   --- plain packets (inside tunnel)
   ─── plain packets
   ═══ encrypted packets
   netkit — L2 link between namespaces (veth on older kernels)
```
<!-- /topology -->

[Requirements](../#Requirements)

## Quick start (host kernel)

```sh
just demo           # up + status + ping checks (netkit, kernel >= 6.7)
just link=veth demo # same, using veth pairs (older kernels)
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
