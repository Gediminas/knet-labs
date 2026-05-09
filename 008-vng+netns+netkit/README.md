# virtme-ng + netns + netkit

Network namespaces + netkit links + WireGuard tunnel — runnable on any kernel via [virtme-ng](https://github.com/arighi/virtme-ng).

```
     cli                         vpn                     web
  ┌────────┐               ┌──────────────┐          ┌─────────┐
  │   wg0 ─│----tunnel-----│─ wg0   eth1 ─┼──netkit──┼─ nk0    │
  │    |   │               │   |          │          │         │
  │  eth0 ═╪═══ netkit ════╪═ eth0        │          │         │
  └────────┘               └──────────────┘          └─────────┘

  ---: plain packets (inside tunnel)
  ───: plain packets
  ═══: encrypted packets
```
```sh
ip netns list
# k008-web
# k008-vpn
# k008-cli
```

[Requirements](../#Requirements)

## Run from host

```sh
just demo
```

## Run in VM (specific kernel)

```sh
# Boot kernel v7.0.1 in virtme-ng
just kernel v7.0.1

# Inside the VM
uname -a
just demo
```

## Explore the lab

```sh
# Enter VPN namespace
just shell-vpn
ip netns identify
ip address
wg show
exit

# Enter cliet namespace
just shell-cli
ip netns identify
wg show
ip address
ip route get 192.168.200.2
ping -c3 192.168.200.2   # cli → web through tunnel
exit
```

## Demo

```sh
# Terminal-1
[just kernel v7.0.1] # any kernel 6.7+
just demo
just exec-vpn RUST_LOG="poc=debug" ./wg_trace_bpf
just exec-vpn ./wg_trace_ebpf

# Terminal-2
[just kernel-ssh]
ip netns exec k008-cli ping 192.168.222.2
```

