use crate::bpf_helper;
use anyhow::Context as _;
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use libc::{clock_gettime, getrusage, rusage, timespec, CLOCK_MONOTONIC, RUSAGE_SELF};
use log::{debug, warn};

#[allow(dead_code)]
pub fn now_ns() -> u64 {
    let mut t: timespec = unsafe { std::mem::zeroed() };

    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut t as *mut timespec) } != 0 {
        panic!("clock_gettime failed");
    }

    (t.tv_sec as u64) * 1_000_000_000 + (t.tv_nsec as u64)
}

#[allow(dead_code)]
pub fn cpu_time_ms() -> (u64, u64) {
    let mut r: rusage = unsafe { std::mem::zeroed() };

    if unsafe { getrusage(RUSAGE_SELF, &mut r) } != 0 {
        panic!("clock_gettime failed");
    }

    let user = (r.ru_utime.tv_sec as u64) * 1_000_000 + (r.ru_utime.tv_usec as u64);
    let sys = (r.ru_stime.tv_sec as u64) * 1_000_000 + (r.ru_stime.tv_usec as u64);
    (user, sys)
}

pub fn init_with_single_xdp(bee: &str, iface: &str) -> anyhow::Result<Ebpf> {
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
    program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    debug!("eBPF loaded: {bee}");
    Ok(ebpf)
}
