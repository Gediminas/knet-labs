// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

mod cli;

use anyhow::{Context as _, Result};
use aya::maps::RingBuf;
use aya::{
    Ebpf, include_bytes_aligned,
    programs::{Xdp, XdpFlags},
};
use log::{debug, info, warn};
use pcap_file_tokio::pcap::{PcapPacket, PcapWriter};
use poc_common::RingEventHeader;
use std::{
    mem, slice,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter, unix::AsyncFd},
    signal,
};

const BEE: &str = "poc_xdp_ring";

#[tokio::main]
async fn main() -> Result<()> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    kit::logger::init();
    let args = cli::parse();

    println!("=======================");
    println!("app:        {}", env!("CARGO_CRATE_NAME"));
    println!("bpf:        {}", BEE);
    println!("log-level:  {}", log::max_level());
    println!("iface:      {}", args.iface);
    println!("out:        {}", args.out);
    println!("args:       {:?}", args);
    println!("=======================");

    let mut ebpf = init_with_single_xdp(BEE, &args.iface)?;

    let ring = RingBuf::try_from(ebpf.take_map("RING").expect("RING")).expect("RING-2");
    let mut ring_fd = AsyncFd::new(ring).unwrap();

    let out = File::create(args.out).await.expect("FILE");
    let stream = BufWriter::with_capacity(8192, out); // BufWriter reduces syscalls
    let mut pcap_writer = PcapWriter::new(stream).await.expect("PCAP");

    loop {
        tokio::select! {
            _ = ring_fd.readable_mut() => {

                let mut guard = ring_fd.readable_mut().await.unwrap();
                let guarded_ring = guard.get_inner_mut();

                while let Some(read) = guarded_ring.next() {
                    let ptr = read.as_ptr();

                    // SAFETY: The ringbuf entry contains at least RingEventHeader.
                    //         ringbuf's internal alignment is guaranteed.
                    let header = unsafe { &*(ptr as *const RingEventHeader) };
                    let len = header.packet_len;
                    // let timestamp = header.timestamp;

                    // The packet data starts exactly after the header (16 bytes in)
                    let packet = unsafe {
                        let data_ptr = ptr.add(mem::size_of::<RingEventHeader>());
                        slice::from_raw_parts(data_ptr, len as usize)
                    };


                    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                    info!("Packet: len {len}, timestamp {timestamp:?}");

                    let packet = PcapPacket::new(timestamp, len as u32, packet);
                    pcap_writer.write_packet(&packet).await.unwrap();
                }

                guard.clear_ready();
            },
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, closing...");
                break;
            },
        }
    }

    let mut buf_writer = pcap_writer.into_writer();
    buf_writer.flush().await.unwrap();
    info!("Finished");
    Ok(())
}
pub fn init_with_single_xdp(bee: &str, iface: &str) -> Result<Ebpf> {
    kit::system::legacy_memlock_rlimit_remove()?;

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
    program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}
