# Benchmark details

- Command: `just bench-30s`
- UDP Flood via 5 × `hping3`
- 30s each test
- `lo` interface
- `packet_capture_time: u64`, `packet_len: usize`, and 1500 buff is sent

```sh
Starting UDP traffic 5 x `hping3 --flood` (timeout 600.0)...

tests/test_bench.py::test_axray_throughput[1-app_extra_args0]
[1] Run: ./target/release/poc --iface lo --timeout 30000
[W] NONE: base-line
[I] * Latency:            0 µs/pk
[W] * Throughput:       717 kpk/s  (21517405 pk / 30.002 s)
[I] * Lost:               0 pk
[I] * Idle:               0 cycles
[I] * CPU sys-time:     0.0 ms/s
[I] * CPU usr-time:     0.0 ms/s

tests/test_bench.py::test_axray_throughput[2-app_extra_args1]
[2] Run: ./target/release/poc --iface lo --timeout 30000 --perf
[W] PERF: Userspace listeners: 22 (CPUs)
[W] * Latency:            7 µs/pk
[W] * Throughput:       573 kpk/s  (17181115 pk / 30.001 s)
[E] * Lost:        0.205782 pk%  (    35499 pk)
[I] * Idle:               0 cycles
[E] * CPU sys-time:   802.8 ms/s
[E] * CPU usr-time:   606.7 ms/s

tests/test_bench.py::test_axray_throughput[3-app_extra_args2]
[3] Run: ./target/release/poc --iface lo --timeout 30000 --ring
[W] RING: Userspace loop with epoll
[W] * Latency:           12 µs/pk
[W] * Throughput:       612 kpk/s  (18351635 pk / 30.002 s)
[I] * Lost:               0 pk
[I] * Idle:         4603477 cycles
[E] * CPU sys-time:   256.0 ms/s
[E] * CPU usr-time:   256.1 ms/s

tests/test_bench.py::test_axray_throughput[4-app_extra_args3]
[4] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 0
[W] RING: Userspace loop delay: 0
[W] * Latency:           10 µs/pk
[W] * Throughput:       618 kpk/s  (18527910 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:       3798608958 cycles
[E] * CPU sys-time:   999.7 ms/s
[I] * CPU usr-time:     0.0 ms/s

tests/test_bench.py::test_axray_throughput[5-app_extra_args4]
[5] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 10
[W] RING: Userspace loop delay: 10
[W] * Latency:           43 µs/pk
[W] * Throughput:       621 kpk/s  (18620452 pk / 30.002 s)
[I] * Lost:               0 pk
[I] * Idle:          395859 cycles
[E] * CPU sys-time:   195.2 ms/s
[I] * CPU usr-time:    12.5 ms/s

tests/test_bench.py::test_axray_throughput[6-app_extra_args5]
[6] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 20
[W] RING: Userspace loop delay: 20
[W] * Latency:           42 µs/pk
[W] * Throughput:       621 kpk/s  (18628016 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          343984 cycles
[E] * CPU sys-time:   187.2 ms/s
[I] * CPU usr-time:    12.8 ms/s

tests/test_bench.py::test_axray_throughput[7-app_extra_args6]
[7] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 50
[W] RING: Userspace loop delay: 50
[W] * Latency:           61 µs/pk
[W] * Throughput:       622 kpk/s  (18655385 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          242355 cycles
[E] * CPU sys-time:   183.9 ms/s
[I] * CPU usr-time:     9.2 ms/s

tests/test_bench.py::test_axray_throughput[8-app_extra_args7]
[8] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 100
[W] RING: Userspace loop delay: 100
[W] * Latency:           99 µs/pk
[W] * Throughput:       619 kpk/s  (18567681 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          162654 cycles
[E] * CPU sys-time:   182.7 ms/s
[I] * CPU usr-time:     5.7 ms/s

tests/test_bench.py::test_axray_throughput[9-app_extra_args8]
[9] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 200
[W] RING: Userspace loop delay: 200
[W] * Latency:          131 µs/pk
[W] * Throughput:       647 kpk/s  (19413929 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:           99931 cycles
[E] * CPU sys-time:   162.4 ms/s
[I] * CPU usr-time:     3.5 ms/s

tests/test_bench.py::test_axray_throughput[10-app_extra_args9]
[10] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 500
[W] RING: Userspace loop delay: 500
[W] * Latency:          294 µs/pk
[W] * Throughput:       599 kpk/s  (17965297 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:           43922 cycles
[E] * CPU sys-time:   187.9 ms/s
[I] * CPU usr-time:     4.5 ms/s
```
