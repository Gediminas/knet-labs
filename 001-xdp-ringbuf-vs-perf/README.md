# Benchmark: Ringbuf vs Perf

Benchmark of **ringbuf vs perf** for sending packets from **XDP** to userspace, implemented in **Rust (Aya)**.

[Requirements](../#Requirements)

## Table of Contents

- [Install and Run](#install-and-run)
- [Benchmark Ringbuf vs Perf](#benchmark-ringbuf-vs-perf)
- [Interpretation](#interpretation)
- [Theory Notes](#theory-notes)
- [Conclusion](#conclusion)
- [Links](#links)

## Install and Run

```sh
################################
# Prep option 1: nix+direnv
direnv allow
# Prep option 2: nix
nix develop
# Prep option 3: pip
pip install --user pipenv
pipenv install pytest
################################

# Build
just build

# Check if all good
just run --iface lo  # terminal-1
just traffic         # terminal-2
                     # Ctrl+C in both terminals

# Run tests
just build-release
just bench        # 5*hping3 flood for 1s
just bench 3000   # 5*hping3 flood for 3s
just bench 30000  # 5*hping3 flood for 30s
POC_HPING_TRAFFIC="--faster" just bench-30s  # 1 instance of `hping3 ... --faster`
```

## Benchmark Ringbuf vs Perf

(`just bench-30s`: UDP flood via 5 × `hping3` for 30s per test on the `lo` interface; each event includes `packet_capture_time: u64`, `packet_len: usize`, and a 165-byte packet)


| Mode    | Sleep | Latency | Thrghpt | Lost   | CPU BPF | CPU Usr | CPU sys+user Time |
|---------|-------|---------|---------|--------|---------|---------|-------------------|
|         | [µs]  | [µs]    | [kpk/s] | [pk%]  | [%]     | [%]     | [ms/s]            |
|         |       |         |         |        |         |         |                   |
| baseline|       |         | **717** |        |   ~3.5  |     0   |     0.0 +   0.0   |
|         |       |         |         |        |         |         |                   |
| perf    | epoll |  **7**  |   573   |**0.21**|  ~58    |**~135** | **802.8 + 606.7** |
|         |       |         |         |        |         |         |                   |
| ringbuf | epoll |   12    |   612   |  0     |  ~53    |   ~51   |   256.0 + 256.1   |
| ringbuf |     0 |   10    |   618   |  0     |  ~44    |**~100** | **999.7 +   0.0** |
| ringbuf |    10 |   43    |   621   |  0     |  ~45    |   ~21   |   195.2 +  12.5   |
| ringbuf |    20 |   42    |   621   |  0     |  ~45    |   ~21   |   187.2 +  12.8   |
| ringbuf |    50 |   61    |   622   |  0     |  ~45    |   ~19   |   183.9 +   9.2   |
| ringbuf |   100 |   99    |   619   |  0     |  ~45    |   ~17   |   182.7 +   5.7   |
| ringbuf |   200 |  131    |   647   |  0     |  ~50    |   ~16   |   162.4 +   3.5   |
| ringbuf |   500 |  294    |   599   |  0     |  ~50    |   ~19   |   187.9 +   4.5   |

[Full benchmark log](./docs/bench_buf_165_flood.md)


## Interpretation

**Under low load (1x `hping --fast`):**

- CPU usage is minimal in all modes except the busy-loop (`ring-delay=0`), which consumes a full CPU core


**Under sustained high load (5x `hping --flood`):**

- **Perf**
  - Packet loss under sustained load (~0.21% loss)
  - Lowest average latency during testing (~7 µs)
  - Very high CPU usage (≈ 58% BPF + 135% userspace -> **~2 cores total**)
  - Requires per-CPU consumers, increasing implementation complexity and reducing scalability
- **Ringbuf with epoll (with BPF_RB_FORCE_WAKEUP submit flag)**
  - No packet loss
  - Latency close to perf (~12 µs)
  - High but significantly lower CPU utilization compared to perf (≈ 53% BPF + 51% userspace -> **~1 core total (2x less than perf)**)
  - Single-threaded consumer model, substantially simplifying implementation and reasoning
  - Requires an epoll-based event loop, introducing minor additional complexity
- **Ringbuf with busy-loop**
  - No packet loss
  - Latency comparable to perf (~10 µs)
  - Very high CPU utilization (≈ 41% BPF + 100% userspace -> **~1.4 cores**)
  - Practical only when minimal latency is the primary objective and CPU cost is acceptable
- **Ringbuf with sleep delays (10-500 µs)**
  - No packet loss
  - Latency increases proportionally with sleep duration (approximately 40–320 µs)
  - A sleep interval of **50–100 µs** provides the best throughput-to-CPU tradeoff in these tests
  - Reduced userspace CPU utilization, though combined CPU usage still relatively high
  - Simple implementation based on periodic sleep

Across all evaluated configurations, **ringbuf exhibited zero packet loss**.
If the ring buffer becomes full, this condition is explicitly **detectable** via `bpf_ringbuf_reserve()`, enabling the program to apply **backpressure or retry logic**. This level of control is not available with `perf_event_output()`.


## Theory Notes

- **perf** uses one ring buffer per CPU, resulting in higher memory usage and additional coordination overhead.
- **ringbuf** uses a single shared ring buffer (with configurable size) and atomic reservation, allowing producers to safely coordinate under concurrent load and improving behavior under bursty traffic.


## Conclusion

- **Ringbuf with epoll** is the best overall option, offering low latency, zero packet loss, reasonable CPU usage, and a simple single-threaded consumer model
- **Ringbuf with a 50–100 µs delay** provides the best latency-to-CPU tradeoff and is well suited for moderate to high traffic workloads
- **Ringbuf with busy-loop polling** achieves the lowest latency (comparable to perf) but consumes a full CPU core; it is only appropriate when latency is the overriding constraint
- **perf** delivers ultra-low latency but incurs packet loss under sustained load and excessive CPU usage; it should only be considered when minimal latency outweighs packet loss and implementation complexity


## Links

- [BPF ring buffer: Performance and applicability](https://nakryiko.com/posts/bpf-ringbuf/#performance-and-applicability)
- [BPF ringbuf and perf buffer benchmarks](https://patchwork.ozlabs.org/project/netdev/patch/20200529075424.3139988-5-andriin@fb.com)
- [XDP packet capture in Rust with aya](https://reitw.fr/blog/aya-xdp-pcap)
- [TC ringbuf example](https://github.com/vadorovsky/aya-examples/tree/main/tc-ringbuf)
