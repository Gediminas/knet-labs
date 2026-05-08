# WireGuard Tracing

TBD / WIP


[Requirements](../#Requirements)

## Build & Run

```sh
# Build Release
#cargo build --release

# Run
#sudo ./target/release/poc --iface lo


just root
just dev --wg wg0 --iface eth0

just lab-up
just lab-shell-vpn dmesg -Tw
just lab-down
```
