# PoC Ringbuf vs Perf

Benchmark of **ringbuf vs perf** for sending packets from **XDP** to userspace, implemented in **Rust (Aya)**.

## Table of Contents

- [Install and Run](#install-and-run)
- [Benchmark Ringbuf vs Perf](#benchmark-ringbuf-vs-perf)
- [Interpretation](#interpretation)
- [Theory Notes](#theory-notes)
- [Conclusion](#conclusion)
- [Links](#links)

## Install and run

```sh
# Ubuntu:
pip install --user pipenv
# NixOS:
direnv enable

just install
just build-release
just root
just bench      # 5*hping3 flood for 1s
just bench-3s   # 5*hping3 flood for 3s
just bench-30s  # 5*hping3 flood for 30s
POC_HPING_TRAFFIC="--faster" just bench-30s  # 1 instance of `hping3 ... --faster`
```

## Benchmark Ringbuf vs Perf

(`just bench-30s`: UDP Flood via 5 × `hping3` for 30s each test @ `lo` interface;
 `packet_capture_time: u64`, `packet_len: usize` and 165 packet are sent)

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

- CPU usage minimal in all modes except busy-loop (`ring-delay=0`), which consumes full CPU core as expected.

**Under sustained high load (5x `hping --flood`):**

- **Perf**
  - ❌ Drops packets under sustained load (~0.21% loss)
  - ✅ Lowest average latency (~7 µs)
  - ❌ Very high CPU usage (≈ 58% BPF + 135% userspace => **~2 cores total**)
  - ⚠️ Requires per-CPU listeners, complicating implementation and scaling
- **Ringbuf with epoll (with BPF_RB_FORCE_WAKEUP submit flag)**
  - ✅ Zero packet loss
  - ✅ Latency close to perf (~12 µs)
  - ⚠️ High CPU usage (≈ 53% BPF + 51% userspace => **~1 core total (2x less than perf)**)
  - ✅ Single-threaded consumer => much simpler to implement and reason about
  - ⚠️ Requires epoll-style event loop (minor complexity)
- **Ringbuf with busy-loop**
  - ✅ Zero packet loss
  - ✅ Latency close to perf (~10 µs)
  - ❌ Very high CPU usage (≈ 41% BPF + 100% userspace => **~1.4 cores**)
  - ⚠️ Only viable when absolute minimal delay is critical, and CPU cost is acceptable
- **Ringbuf with sleep delays (10-500 µs)**
  - ✅ Zero packet loss
  - ⚠️ Latency increases with delay (40–320 µs)
    -  50–100 µs delay gives best throughput vs CPU tradeoff
  - ⚠️ Lower userspace CPU usage (but the combined usage still relatively high)
  - ✅ Simple implementation — just `sleep`

**ringbuf** achieved **zero packet loss** across all test cases. While extremely rare drops may still occur if the ring becomes full, this is **controlled by `bpf_ringbuf_reserve()`**, allowing the program to detect exhaustion and retry — a level of control not possible with `perf_event_output()`.


## Theory Notes

- **perf** uses one ring buffer **per CPU**, leading to higher memory usage and coordination overhead.
- **ringbuf** uses a single shared ring (configurable size), providing better resilience under bursty load.


## Conclusion

- ✅ **Ringbuf with epoll** — best all-around: low latency, zero packet loss, reasonable CPU usage, and simple single-threaded code
- ✅ **Ringbuf with delay 50–100 µs** — best latency vs CPU tradeoff; ideal for moderate to high traffic
- ❌ **Ringbuf with busy-loop** — lowest latency (equal to perf), but burns a full CPU core; only viable when latency is everything
- ❌ **Perf** — ultra-low latency, but drops packets and consumes excessive CPU; only use when latency is absolutely critical and packet loss + multithreaded complexity are acceptable

## Links

- [BPF ring buffer: Performance and applicability](https://nakryiko.com/posts/bpf-ringbuf/#performance-and-applicability)
- [BPF ringbuf and perf buffer benchmarks](https://patchwork.ozlabs.org/project/netdev/patch/20200529075424.3139988-5-andriin@fb.com)
- [XDP packet capture in Rust with aya](https://reitw.fr/blog/aya-xdp-pcap)
- [TC ringbuf example](https://github.com/vadorovsky/aya-examples/tree/main/tc-ringbuf)
