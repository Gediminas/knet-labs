# Benchmark details

- Command: `POC_HPING_TRAFFIC="--fast" just bench-30s`
- UDP Flood via 1 × `hping3 --fast`
- 30s each test
- `lo` interface
- Only `packet_capture_time: u64` and `packet_len: usize` are sent

```sh
Starting UDP traffic 1 x `hping3 --fast` (timeout 600.0)...

tests/test_bench.py::test_axray_throughput[1-app_extra_args0]
[1] Run: ./target/release/poc --iface lo --timeout 30000
[W] NONE: base-line
[I] * Latency:            0 µs/pk
[W] * Throughput:        10 pk/s  (299 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:               0 cycles
[I] * CPU sys-time:     0.0 ms/s
[I] * CPU usr-time:     0.0 ms/s

tests/test_bench.py::test_axray_throughput[2-app_extra_args1]
[2] Run: ./target/release/poc --iface lo --timeout 30000 --perf
[W] PERF: Userspace listeners: 22 (CPUs)
[W] * Latency:           91 µs/pk
[W] * Throughput:        10 pk/s  (300 pk /  30.002 s)
[I] * Lost:               0 pk
[I] * Idle:               0 cycles
[I] * CPU sys-time:     0.3 ms/s
[I] * CPU usr-time:     1.5 ms/s

tests/test_bench.py::test_axray_throughput[3-app_extra_args2]
[3] Run: ./target/release/poc --iface lo --timeout 30000 --ring
[W] RING: Userspace loop with epoll
[W] * Latency:           45 µs/pk
[W] * Throughput:        10 pk/s  (304 pk /  30.002 s)
[I] * Lost:               0 pk
[I] * Idle:             410 cycles
[I] * CPU sys-time:     0.1 ms/s
[I] * CPU usr-time:     0.1 ms/s

tests/test_bench.py::test_axray_throughput[4-app_extra_args3]
[4] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 0
[W] RING: Userspace loop delay: 0
[W] * Latency:            2 µs/pk
[W] * Throughput:        10 pk/s  (300 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:       5992055735 cycles
[E] * CPU sys-time:   999.4 ms/s
[I] * CPU usr-time:     0.2 ms/s

tests/test_bench.py::test_axray_throughput[5-app_extra_args4]
[5] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 10
[W] RING: Userspace loop delay: 10
[W] * Latency:           34 µs/pk
[W] * Throughput:        10 pk/s  (301 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          486251 cycles
[I] * CPU sys-time:     7.9 ms/s
[I] * CPU usr-time:    21.5 ms/s

tests/test_bench.py::test_axray_throughput[6-app_extra_args5]
[6] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 20
[W] RING: Userspace loop delay: 20
[W] * Latency:           64 µs/pk
[W] * Throughput:        10 pk/s  (301 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          418146 cycles
[I] * CPU sys-time:     7.7 ms/s
[I] * CPU usr-time:    19.3 ms/s

tests/test_bench.py::test_axray_throughput[7-app_extra_args6]
[7] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 50
[W] RING: Userspace loop delay: 50
[W] * Latency:           51 µs/pk
[W] * Throughput:        10 pk/s  (301 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          298098 cycles
[I] * CPU sys-time:     8.8 ms/s
[I] * CPU usr-time:    12.5 ms/s

tests/test_bench.py::test_axray_throughput[8-app_extra_args7]
[8] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 100
[W] RING: Userspace loop delay: 100
[W] * Latency:           77 µs/pk
[W] * Throughput:        10 pk/s  (301 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          196659 cycles
[I] * CPU sys-time:     2.4 ms/s
[I] * CPU usr-time:    14.2 ms/s

tests/test_bench.py::test_axray_throughput[9-app_extra_args8]
[9] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 200
[W] RING: Userspace loop delay: 200
[W] * Latency:          132 µs/pk
[W] * Throughput:        10 pk/s  (300 pk /  30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          119585 cycles
[I] * CPU sys-time:     3.8 ms/s
[I] * CPU usr-time:     7.9 ms/s

tests/test_bench.py::test_axray_throughput[10-app_extra_args9]
[10] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 500
[W] RING: Userspace loop delay: 500
[W] * Latency:          291 µs/pk
[W] * Throughput:        10 pk/s  (300 pk /  30.002 s)
[I] * Lost:               0 pk
[I] * Idle:           54083 cycles
[I] * CPU sys-time:     2.1 ms/s
[I] * CPU usr-time:     6.1 ms/s
```
