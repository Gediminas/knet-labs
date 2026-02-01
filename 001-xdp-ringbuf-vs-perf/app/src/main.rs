// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

mod cli;

use crate::cli::Opt;
use anyhow::Context as _;
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{MapData, PerCpuArray, PerfEventArray, RingBuf},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
};
use bytes::BytesMut;
use log::{debug, error, info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use poc_common::{PerfEvent, RingEvent, Stat};
use std::{
    mem::{self},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    ptr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    signal,
    time::{self},
};

const PERF_BUF_COUNT: usize = 100;
const PERF_BUF_SIZE: usize = 9000;

static EXIT_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));
static RECV_PACKETS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static LOST_PACKETS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static IDLE_CYCLES: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static LATENCY_SUM: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    kit::logger::init();
    let args = cli::parse();

    let bee = if args.ring {
        if args.ring_delay.is_some() {
            "poc_ring_with_delay"
        } else {
            "poc_ring_with_epoll"
        }
    } else if args.perf {
        "poc_perf"
    } else {
        "poc_none"
    };

    let mut ebpf = init_with_single_xdp(bee, &args.iface)?;

    let stat: PerCpuArray<MapData, Stat> =
        PerCpuArray::try_from(ebpf.take_map("STAT").expect("STAT-1")).expect("STAT-2");

    let start_time = kit::system::now_ns();
    let start_cpu_time = kit::system::cpu_time_ms();

    if args.ring {
        spawn_ringbuf_loop(&mut ebpf, args.ring_delay, &stat)?;
    } else if args.perf {
        spawn_perf_loop(&mut ebpf)?;
    } else {
        warn!("NONE: base-line"); // no perf, no ringbuf
    }

    // wait for the end
    if let Some(millis) = args.timeout {
        debug!("Waiting {} ms", millis);
        time::sleep(tokio::time::Duration::from_millis(millis)).await;
    } else {
        debug!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
    }

    EXIT_FLAG.store(true, Relaxed);

    let end_cpu_time = kit::system::cpu_time_ms();
    let end_time = kit::system::now_ns();

    let elapsed = (end_time - start_time) as f64 / 1_000_000_000.0;
    let sys_ms = (end_cpu_time.0 - start_cpu_time.0) as f64 / 1_000.0 / elapsed;
    let usr_ms = (end_cpu_time.1 - start_cpu_time.1) as f64 / 1_000.0 / elapsed;

    let stat = stat.get(&0, 0)?;
    let total_packets = stat.iter().fold(0, |acc, x| acc + x.total_packets);

    print_report(&args, total_packets, elapsed, sys_ms, usr_ms);
    Ok(())
}

#[inline(always)]
fn process_packet_burst(ring: &mut RingBuf<MapData>) {
    // let mut burst = 0;
    while let Some(item) = ring.next() {
        let ptr = item.as_ptr();
        let evt = unsafe { ptr::read_unaligned(ptr as *const RingEvent) };
        let now = kit::system::now_ns();
        let latency = now - evt.time;

        debug!("{:?}", &evt.buf[..evt.len]);

        RECV_PACKETS.fetch_add(1, Relaxed);
        LATENCY_SUM.fetch_add(latency as usize, Relaxed);
        // burst += 1;
    }
    // if burst > 1 {
    //     error!("BURST: {burst}");
    // }

    IDLE_CYCLES.fetch_add(1, Relaxed);
}

fn spawn_ringbuf_loop(
    ebpf: &mut Ebpf,
    ring_delay: Option<u32>,
    stat: &PerCpuArray<MapData, Stat>,
) -> anyhow::Result<()> {
    let mut ring = RingBuf::try_from(ebpf.take_map("RING").expect("RING")).expect("RING-2");
    let fd = AsyncFd::new(ring.as_raw_fd())?;

    tokio::task::spawn(async move {
        match ring_delay {
            Some(delay) => {
                warn!("RING: Userspace loop delay: {delay}");

                while !EXIT_FLAG.load(Relaxed) {
                    process_packet_burst(&mut ring);

                    if delay > 0 {
                        std::thread::sleep(Duration::from_micros(delay as u64));
                    }
                }
            }
            None => {
                warn!("RING: Userspace loop with epoll");

                while !EXIT_FLAG.load(Relaxed) {
                    process_packet_burst(&mut ring);

                    let mut guard = fd.readable().await.expect("E7279");
                    guard.clear_ready();
                }
            }
        }
    });

    let stat = stat.get(&0, 0)?;
    let lost = stat.iter().fold(0, |acc, x| acc + x.ring_lost_packets);
    LOST_PACKETS.store(lost, Relaxed);

    Ok(())
}

fn spawn_perf_loop(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let cpus = online_cpus().expect("CPU");
    let num_cpus = cpus.len();

    warn!("PERF: Userspace listeners: {num_cpus} (CPUs)");

    let mut events =
        PerfEventArray::try_from(ebpf.take_map("PERF").expect("PERF")).expect("PERF-2");

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        let fd = AsyncFd::new(buf.as_raw_fd())?;

        let recv = RECV_PACKETS.clone();
        let lost = LOST_PACKETS.clone();

        tokio::task::spawn(async move {
            let mut buffers = (0..PERF_BUF_COUNT)
                .map(|_| BytesMut::with_capacity(PERF_BUF_SIZE))
                .collect::<Vec<_>>();

            while !EXIT_FLAG.load(Relaxed) {
                let mut guard = fd.readable().await.expect("E7229");

                let events = buf.read_events(&mut buffers).expect("E7732");
                lost.fetch_add(events.lost, Relaxed);
                recv.fetch_add(events.read, Relaxed);

                for rcv_buf in buffers.iter_mut().take(events.read) {
                    let data: PerfEvent =
                        unsafe { ptr::read_unaligned(rcv_buf.as_ptr() as *const PerfEvent) };

                    let latency = kit::system::now_ns() - data.time;
                    LATENCY_SUM.fetch_add(latency as usize, Relaxed);

                    let pos = mem::size_of::<PerfEvent>();
                    let pkt_buf = rcv_buf.split().freeze().slice(pos..pos + data.len);

                    let ethhdr = pkt_buf.slice(..EthHdr::LEN);
                    let ethhdr = unsafe { ptr::read_unaligned(ethhdr.as_ptr() as *const EthHdr) };
                    let ethty = ethhdr.ether_type; // EthHdr struct is packed -> requires local copy
                    assert!(ethty == EtherType::Ipv4);

                    let pos = EthHdr::LEN;
                    let ip4 = pkt_buf.slice(pos..pos + Ipv4Hdr::LEN);
                    let ip4 = unsafe { ptr::read_unaligned(ip4.as_ptr() as *const Ipv4Hdr) };
                    assert!(ip4.proto == IpProto::Udp);

                    let pos = EthHdr::LEN + Ipv4Hdr::LEN;
                    let udp = pkt_buf.slice(pos..pos + UdpHdr::LEN);
                    let udp = unsafe { ptr::read_unaligned(udp.as_ptr() as *const UdpHdr) };

                    let saddr = Ipv4Addr::from(u32::from_be(ip4.src_addr));
                    let daddr = Ipv4Addr::from(u32::from_be(ip4.dst_addr));
                    let sport = u16::from_be(udp.source);
                    let dport = u16::from_be(udp.dest);

                    let len = data.len;
                    let lat = latency / 1000;
                    debug!("APP: {lat:3} us / {saddr:?}:{sport} -> {daddr:?}:{dport} / {len} b");
                }
                guard.clear_ready();
            }
        });
    }

    Ok(())
}

fn print_report(args: &Opt, total_packets: usize, elapsed: f64, sys_ms: f64, usr_ms: f64) {
    if !args.perf && !args.ring {
        RECV_PACKETS.store(total_packets, Relaxed);
    }

    let recv_packets = RECV_PACKETS.load(Relaxed);
    let idle_cycles = IDLE_CYCLES.load(Relaxed);
    let latency_sum = LATENCY_SUM.load(Relaxed);
    let lost_packets = LOST_PACKETS.load(Relaxed);

    let latency_micro = latency_sum as f64 / recv_packets as f64 / 1000.0;
    let pps = recv_packets as f64 / elapsed;

    if latency_sum == 0 {
        info!("* Latency:    {latency_micro:9.0} µs/pk");
    } else {
        warn!("* Latency:    {latency_micro:9.0} µs/pk");
    }

    if recv_packets == 0 {
        error!("* Throughput: {pps:9.0} pk/s  ({recv_packets} pk /  {elapsed:.3} s)");
    } else if recv_packets > 10000 {
        let pps = pps / 1000.0;
        warn!("* Throughput: {pps:9.0} kpk/s  ({recv_packets:.0} pk / {elapsed:.3} s)");
    } else {
        warn!("* Throughput: {pps:9.0} pk/s  ({recv_packets} pk /  {elapsed:.3} s)");
    }

    if lost_packets == 0 {
        info!("* Lost:       {lost_packets:9} pk");
    } else {
        let lost_percent = 100.0 * LOST_PACKETS.load(Relaxed) as f64 / total_packets as f64;
        error!("* Lost:       {lost_percent:9.6} pk%  ({lost_packets:9} pk)");
    }

    info!("* Idle:       {idle_cycles:9} cycles");

    if sys_ms < 100.0 {
        info!("* CPU sys-time: {sys_ms:7.1} ms/s");
    } else {
        error!("* CPU sys-time: {sys_ms:7.1} ms/s");
    }

    if usr_ms < 100.0 {
        info!("* CPU usr-time: {usr_ms:7.1} ms/s");
    } else {
        error!("* CPU usr-time: {usr_ms:7.1} ms/s");
    }
}

fn init_with_single_xdp(bee: &str, iface: &str) -> anyhow::Result<Ebpf> {
    kit::system::legacy_memlock_rlimit_remove()?;

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc")))?;

    kit::init_aya_log(&mut ebpf).expect("init aya-log");

    let program: &mut Xdp = ebpf.program_mut(bee).unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}
