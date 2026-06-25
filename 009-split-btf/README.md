# Split BTF: fentry on a kernel-module function (raw BPF syscalls implementation)

Currently (2026-06) Aya can attach fentry to **vmlinux** functions
(`/sys/kernel/btf/vmlinux`), but not to kernel **module** ones in *split BTF*
(`/sys/kernel/btf/<module>`) - e.g. WireGuard's `wg_xmit` in
`/sys/kernel/btf/wireguard`. A module's type ids continue after vmlinux's, so the
load + attach is implemented here via raw BPF syscalls.

Upstream attempts:
- [#300: Add support for kernel module "split" BTFs](https://github.com/aya-rs/aya/issues/300)
- [#301: Support attaching to BtfTracepoint of a kernel module](https://github.com/aya-rs/aya/issues/301)

The loader is the [`../kmod-btf`](../kmod-btf) crate; this lab is the
minimal demo. WireGuard is just the default - retarget with `--module`/`--func`.

## Run

```sh
just up        # k009 netns + wg0 (loads the wireguard module) - real root
just caps      # cap_sys_admin,cap_bpf,cap_perfmon (sudo once)
just build
just run       # loads + attaches; default --module wireguard --func wg_xmit
# another terminal:
just trigger   # one packet through wg0 → "[W] fentry fired"
just down
```

## Implementation

Aya's `FEntry` can't set `attach_btf_id` (absolute) or `attach_btf_obj_fd`, which
module functions need.
`kmod-btf` implements it so:
1. find the module's BTF fd by name (iterate loaded BTF objects)
2. resolve the absolute `attach_btf_id` (vmlinux type count + module-local index)
3. relocate the program's map/`.rodata` refs against aya's loaded maps (keeps `warn!` working)
4. `BPF_PROG_LOAD` (TRACING/FENTRY), then `BPF_LINK_CREATE`

