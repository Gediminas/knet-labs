# XDP Ringbuf Dump

**XDP** packet capture to **pcap** (delivery to userspace via **ringbuf**)

[Requirements](../#Requirements)

## Build & Run

```sh
# Build Debug
cargo build

# Build Release
cargo build --release

# Run
sudo ./target/release/poc --iface lo --out dump.pcap
```
