# Benchmark details

- Command: `just bench-30s`
- UDP Flood via 5 × `hping3`
- 30s each test
- `lo` interface
- Only `packet_capture_time: u64` and `packet_len: usize` are sent

```sh
Starting 5x hping3 UDP flood (timeout 600.0)...

tests/test_bench.py::test_axray_throughput[1-app_extra_args0]
[1] Run: ./target/release/poc --iface lo --timeout 30000
[W] NONE: base-line
[I] * Latency:            0 µs/pk
[W] * Throughput:       765 kpk/s  (22963180 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:               0 cycles
[I] * CPU sys-time:     0.0 ms/s
[I] * CPU usr-time:     0.0 ms/s

tests/test_bench.py::test_axray_throughput[2-app_extra_args1]
[2] Run: ./target/release/poc --iface lo --timeout 30000 --perf
[W] PERF: Userspace listeners: 22 (CPUs)
[W] * Latency:            8 µs/pk
[W] * Throughput:       610 kpk/s  (18306034 pk / 30.001 s)
[E] * Lost:        0.030789 pk%  (     5640 pk)
[I] * Idle:               0 cycles
[E] * CPU sys-time:   626.9 ms/s
[E] * CPU usr-time:   585.2 ms/s

tests/test_bench.py::test_axray_throughput[3-app_extra_args2]
[3] Run: ./target/release/poc --iface lo --timeout 30000 --ring
[W] RING: Userspace loop with epoll
[W] * Latency:           10 µs/pk
[W] * Throughput:       638 kpk/s  (19152214 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:         4498757 cycles
[I] * CPU sys-time:    95.2 ms/s
[E] * CPU usr-time:   306.1 ms/s

tests/test_bench.py::test_axray_throughput[4-app_extra_args3]
[4] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 0
[W] RING: Userspace loop delay: 0
[W] * Latency:           13 µs/pk
[W] * Throughput:       705 kpk/s  (21146530 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:       4077907323 cycles
[E] * CPU sys-time:   999.4 ms/s
[I] * CPU usr-time:     0.1 ms/s

tests/test_bench.py::test_axray_throughput[5-app_extra_args4]
[5] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 10
[W] RING: Userspace loop delay: 10
[W] * Latency:           37 µs/pk
[W] * Throughput:       738 kpk/s  (22136280 pk / 30.002 s)
[I] * Lost:               0 pk
[I] * Idle:          453831 cycles
[I] * CPU sys-time:    63.7 ms/s
[I] * CPU usr-time:    19.2 ms/s

tests/test_bench.py::test_axray_throughput[6-app_extra_args5]
[6] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 20
[W] RING: Userspace loop delay: 20
[W] * Latency:           46 µs/pk
[W] * Throughput:       777 kpk/s  (23323679 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          391137 cycles
[I] * CPU sys-time:    69.2 ms/s
[I] * CPU usr-time:     9.4 ms/s

tests/test_bench.py::test_axray_throughput[7-app_extra_args6]
[7] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 50
[W] RING: Userspace loop delay: 50
[W] * Latency:           55 µs/pk
[W] * Throughput:       693 kpk/s  (20780345 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          279422 cycles
[I] * CPU sys-time:    54.4 ms/s
[I] * CPU usr-time:    12.8 ms/s

tests/test_bench.py::test_axray_throughput[8-app_extra_args7]
[8] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 100
[W] RING: Userspace loop delay: 100
[W] * Latency:           84 µs/pk
[W] * Throughput:       771 kpk/s  (23137512 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          184919 cycles
[I] * CPU sys-time:    63.4 ms/s
[I] * CPU usr-time:     7.8 ms/s

tests/test_bench.py::test_axray_throughput[9-app_extra_args8]
[9] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 200
[W] RING: Userspace loop delay: 200
[W] * Latency:          151 µs/pk
[W] * Throughput:       770 kpk/s  (23105436 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:          112227 cycles
[I] * CPU sys-time:    55.5 ms/s
[I] * CPU usr-time:     6.6 ms/s

tests/test_bench.py::test_axray_throughput[10-app_extra_args9]
[10] Run: ./target/release/poc --iface lo --timeout 30000 --ring --ring-delay 500
[W] RING: Userspace loop delay: 500
[W] * Latency:          293 µs/pk
[W] * Throughput:       706 kpk/s  (21193582 pk / 30.001 s)
[I] * Lost:               0 pk
[I] * Idle:           50663 cycles
[I] * CPU sys-time:    63.4 ms/s
[I] * CPU usr-time:     5.1 ms/s
```