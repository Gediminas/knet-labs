use anyhow::Context as _;
use anyhow::Result;
use aya::{
    Ebpf, include_bytes_aligned,
    programs::{Xdp, XdpFlags},
};
use log::info;
use log::{debug, warn};
use std::num::NonZeroU32;
use xdpilone::{DeviceQueue, IfInfo, RingRx, RingTx, Socket, SocketConfig, Umem, User};

const PACKET_RING_SIZE: u32 = 16 * 8;
pub const RX_QUEUE_SIZE: u32 = 8; // 1 << 14
const TX_QUEUE_SIZE: u32 = 8; // 1 << 14

const PACKET_LEN: u32 = 4096; // Could be smaller but must be equal to alignment below, x86_64 requires 4KB+

pub const UMEM_SIZE: usize = PACKET_RING_SIZE as usize * PACKET_LEN as usize;

pub fn bind_xsk_umem(iface: &str, queue: u32, umem: &Umem) -> (RingRx, RingTx, DeviceQueue) {
    info!("Creating XSK");
    let ifinfo = new_if_info(iface, queue);
    let sock = Socket::with_shared(&ifinfo, umem).unwrap(); // Same fd: buff ops on iface & Umem + Fill/Complete + Rx/Tx

    let device = umem.fq_cq(&sock).unwrap(); // Get the fill/completion device (which handles the 'device queue').
    let rxtx = configure_socket(&sock, umem);
    let rx = rxtx.map_rx().unwrap();
    let tx = rxtx.map_tx().unwrap();

    umem.bind(&rxtx).unwrap(); // start kernel doing things on the ring

    (rx, tx, device)
}

fn configure_socket(sock: &Socket, umem: &Umem) -> User {
    // SocketConfig::XDP_BIND_NEED_WAKEUP;

    // {
    //     let sock_cfg = SocketConfig {
    //         rx_size: NonZeroU32::new(RX_QUEUE_SIZE),
    //         tx_size: NonZeroU32::new(TX_QUEUE_SIZE),
    //         bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
    //     };

    //     if let Ok(rxtx) = umem.rx_tx(&sock, &sock_cfg) {
    //         info!("AF_XDP created in ZERO-COPY mode :)");
    //         return rxtx;
    //     }
    // }

    let sock_cfg = SocketConfig {
        rx_size: NonZeroU32::new(RX_QUEUE_SIZE),
        tx_size: NonZeroU32::new(TX_QUEUE_SIZE),
        bind_flags: SocketConfig::XDP_BIND_COPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
    };

    if let Ok(rxtx) = umem.rx_tx(sock, &sock_cfg) {
        info!("AF_XDP created in COPY mode :(");
        return rxtx;
    }

    panic!("AF_XDP could not be created");
}

/// Trasffer all umem frames ownership to kernel?
pub fn fill_frames_for_kernel(device: &mut DeviceQueue) -> Result<()> {
    assert!(!device.needs_wakeup());

    let mut writer = device.fill(PACKET_RING_SIZE);
    for i in 0..PACKET_RING_SIZE {
        let offset = i as u64 * PACKET_LEN as u64; // Each frame is 4096 bytes; compute offset
        let added = writer.insert_once(offset);
        anyhow::ensure!(added, "Failed initial ring setup");
    }
    writer.commit();
    Ok(())
}

fn new_if_info(iface: &str, queue: u32) -> xdpilone::IfInfo {
    use std::ffi::CString;
    let iface_cstr = CString::new(iface).unwrap();
    let mut info = IfInfo::invalid();
    info.from_name(iface_cstr.as_c_str()).unwrap();
    info.set_queue(queue);
    info
}

pub fn init_with_single_xdp(bee: &str, iface: &str) -> anyhow::Result<Ebpf> {
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
