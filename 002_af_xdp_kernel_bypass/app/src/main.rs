#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod bpf_helper;
mod cli;
mod logger;
mod utils;

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{MapData, PerCpuArray, PerCpuValues, RingBuf, XskMap},
    programs::{Xdp, XdpFlags},
    util::online_cpus,
};
use aya_log::EbpfLogger;
use clap::Parser;
use core::slice;
use log::{debug, error, info, trace, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use poc_common::Stat;
use std::{mem::MaybeUninit, net::Ipv4Addr};
use std::{
    mem::{self, offset_of},
    os::fd::AsRawFd,
    ptr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::{
    signal,
    time::{self},
};
use utils::{RX_QUEUE_SIZE, UMEM_SIZE};
use xdpilone::{Umem, UmemConfig, xdp::XdpDesc};

const QUEUE_ID: u32 = 0;

const BEE: &str = "poc_redirect_to_afxdp";

static SENT_PACKETS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));
static EXIT_FLAG: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

#[repr(C, align(4096))]
struct PacketMap(MaybeUninit<[u8; UMEM_SIZE]>);

#[tokio::main]
async fn main() -> Result<()> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");

    let args = cli::parse();

    logger::init();

    println!("=======================");
    println!("app:        {}", BEE);
    println!("log-level:  {}", log::max_level());
    println!("iface:      {}", args.iface);
    println!("args:       {:?}", args);
    println!("=======================");

    let mut ebpf = init_bpf(&args.iface, BEE)?;

    let xsks = XskMap::try_from(ebpf.take_map("XSKS").context("XSKS")?).context("XSKS-2")?;

    let stats =
        PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS")?).context("STATS-2")?;

    let iface = args.iface.to_owned();

    tokio::task::spawn(async move {
        if let Err(e) = run_redir(&iface, xsks) {
            error!("{e}");
        }
    });

    // wait for the end
    if let Some(millis) = args.timeout {
        debug!("Waiting {} ms", millis);
        time::sleep(tokio::time::Duration::from_millis(millis)).await;
    } else {
        debug!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
    }

    EXIT_FLAG.store(true, Relaxed);

    let stat = stats.get(&0, 0)?;

    print_report(&args, stat);
    Ok(())
}

fn run_redir(iface: &str, mut xsks: XskMap<MapData>) -> Result<()> {
    let mut alloc = Box::new(PacketMap(MaybeUninit::zeroed()));
    let umem_pool = unsafe { alloc.0.assume_init_mut() }.as_mut();
    let umem = unsafe { Umem::new(UmemConfig::default(), umem_pool.into()) }.unwrap();

    let (mut rx, mut tx, mut dev) = utils::bind_xsk_umem(iface, QUEUE_ID, &umem);

    xsks.set(QUEUE_ID, rx.as_raw_fd(), 0).unwrap();

    utils::fill_frames_for_kernel(&mut dev)?;
    info!("AF_XDP prepared Fill-Queue: {}", dev.pending());

    let mut was_rx_used = u32::MAX;
    let mut was_rx_free = u32::MAX;
    let mut was_dropped = 0;
    let mut counter = 0;
    let mut was_counter = 0;
    let mut descs = Vec::with_capacity(RX_QUEUE_SIZE as usize);

    while !EXIT_FLAG.load(Relaxed) {
        // Ring stats
        // trace!("loop");
        {
            if was_rx_used != rx.available() || was_rx_free != dev.pending() {
                was_rx_used = rx.available();
                was_rx_free = dev.pending();
                assert!(!dev.needs_wakeup());
                trace!("RX (used/free): {}/{}", rx.available(), dev.pending());
            }
            if was_dropped != dev.statistics_v2().unwrap().rx_dropped {
                was_dropped = dev.statistics_v2().unwrap().rx_dropped;
                error!("Dropped: {:?}", dev.statistics_v2().unwrap().rx_dropped);
            }
        }

        // 1. Receive a batch of packets from the rx ring
        let mut received = rx.receive(RX_QUEUE_SIZE);

        // 2. Process all received packets
        while let Some(desc) = received.read() {
            descs.push(desc);

            let ptr = &umem_pool[desc.addr as usize] as *const u8;
            // print_packet(ptr, &desc);

            // Swap port (checksums?)
            {
                let ptr2 = ptr as usize as *mut u8;
                let ip4_ptr = ptr.wrapping_add(EthHdr::LEN);
                let udp_ptr = ip4_ptr.wrapping_add(Ipv4Hdr::LEN) as *mut u8;

                let mut tmp = 0_u8;
                let tmp = &mut tmp as *mut u8;

                unsafe { std::ptr::copy_nonoverlapping(udp_ptr.wrapping_add(2), tmp, 2) };
                unsafe { std::ptr::copy_nonoverlapping(udp_ptr, udp_ptr.wrapping_add(2), 2) };
                unsafe { std::ptr::copy_nonoverlapping(tmp, udp_ptr, 2) };
            }

            // print_packet(ptr, &desc);
        }

        if descs.is_empty() {
            if was_counter != counter {
                was_counter = counter;
                info!("Packets out: {:?}", counter);
            }
            // std::thread::sleep(std::time::Duration::from_micros(1));
            continue;
        }

        // 3. Release rx descriptors
        // received.release(); //FIXME: Moved

        // 4. Submit modified packets to tx ring
        {
            let mut tx_reserved = tx.transmit(descs.len() as u32); // TX queue submission

            for desc in descs.iter() {
                tx_reserved.insert_once(*desc);
            }

            tx_reserved.commit(); // Commit to the kernel
        }

        received.release(); //FIXME: Moved here. Is this correct?

        assert!(tx.needs_wakeup());
        tx.wake(); // Wake up the transmit queue

        // 5. Process completions and recycle buffers
        {
            let mut tx_complete = dev.complete(RX_QUEUE_SIZE);
            while let Some(tx_desc) = tx_complete.read() {
                counter += 1;
            }
            tx_complete.release();
        }

        // back to fill queue
        {
            let mut writer = dev.fill(descs.len() as u32);
            for desc in descs.iter() {
                writer.insert_once(desc.addr);
            }
            writer.commit();
        }

        SENT_PACKETS.fetch_add(descs.len(), Relaxed);
        descs.clear();
    }

    info!("END =================================");
    info!("{:?}", dev.statistics_v2());

    Ok(())
}

fn init_bpf(iface: &str, bee: &str) -> Result<Ebpf> {
    bpf_helper::legacy_memlock_rlimit_remove()?;

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc")))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = ebpf.program_mut(bee).unwrap().try_into()?;
    program.load()?;
    program
        .attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}

fn print_report(args: &cli::Opt, stat: PerCpuValues<Stat>) {
    let total_packets = stat.iter().fold(0, |acc, x| acc + x.total_packets);
    let redir_packets = stat.iter().fold(0, |acc, x| acc + x.redir_packets);
    let redir_failed_packets = stat.iter().fold(0, |acc, x| acc + x.redir_failed_packets);

    let sent = SENT_PACKETS.load(Relaxed);

    info!("************");
    info!("* received: {total_packets} pk");
    info!("* redirected: {redir_packets} pk");
    error!("* redir-fail: {redir_failed_packets} pk");
    info!("* sent: {sent} pk");
    info!("************");
}

#[inline(always)]
unsafe fn read_unchecked<T>(pos: usize) -> T {
    let ptr = pos as *const T;
    unsafe { ptr.read_unaligned() }
}

fn print_packet(ptr: *const u8, desc: &XdpDesc) {
    let ip4_ptr = ptr as usize + EthHdr::LEN;
    let udp_ptr = ip4_ptr + Ipv4Hdr::LEN;
    let wg_ptr = udp_ptr + UdpHdr::LEN;
    let ip4: Ipv4Hdr = unsafe { read_unchecked(ip4_ptr) };
    let udp: UdpHdr = unsafe { read_unchecked(udp_ptr) };

    let saddr: Ipv4Addr = u32::to_be(ip4.src_addr).into();
    let daddr: Ipv4Addr = u32::to_be(ip4.dst_addr).into();
    let sport: u16 = u16::to_be(udp.source).into();
    let dport: u16 = u16::to_be(udp.dest).into();

    // 51820
    trace!(
        "[APP] {saddr}:{sport} -> {daddr}:{dport}  [x{:x}]",
        desc.addr,
    );
}
