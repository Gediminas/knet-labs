// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

mod bpf_helper;
mod cli;
mod logger;
mod utils;

use crate::utils::init_with_single_xdp;
use aya::maps::RingBuf;
use pcap_file_tokio::pcap::{PcapPacket, PcapWriter};
use poc_common::RingEventHeader;
use std::{
    mem, slice,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::File,
    io::{unix::AsyncFd, AsyncWriteExt, BufWriter},
    signal,
};

const BEE: &str = "poc_xdp_ring";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    logger::init();
    let args = cli::parse();

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
                    log::info!("Packet: len {len}, timestamp {timestamp:?}");

                    let packet = PcapPacket::new(timestamp, len as u32, packet);
                    pcap_writer.write_packet(&packet).await.unwrap();
                }

                guard.clear_ready();
            },
            _ = signal::ctrl_c() => {
                println!("Ctrl-C received, shutting down...");
                break;
            },
        }
    }

    let mut buf_writer = pcap_writer.into_writer();
    buf_writer.flush().await.unwrap();
    Ok(())
}
