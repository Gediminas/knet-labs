#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod cli;

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    programs::{KProbe, Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use tokio::signal;

const HOOK_1: &str = "ip_tunnel_parse_protocol";
const BEEE_1: &str = "ip_tunnel_parse_protocol";
const HOOK_2: &str = "napi_gro_receive";
const BEEE_2: &str = "napi_gro_receive";
const HOOK_3: &str = "wg_allowedips_insert_v4";
const BEEE_3: &str = "wg_allowedips_insert_v4";

// wg_allowedips_insert_v4
// ip_tunnel_parse_protocol

#[tokio::main]
async fn main() -> Result<()> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    kit::logger::init();
    let args = cli::parse();

    println!("=======================");
    println!("app:        {}", env!("CARGO_CRATE_NAME"));
    println!("bpf1:       {:25}  {}", HOOK_1, BEEE_1);
    println!("bpf2:       {:25}  {}", HOOK_2, BEEE_2);
    println!("bpf3:       {:25}  {}", HOOK_3, BEEE_3);
    println!("log-level:  {}", log::max_level());
    println!("args:       {:?}", args);
    println!("=======================");

    // let mut _ebpf = init_with_single_xdp(BEE, &args.iface)?;
    kit::system::legacy_memlock_rlimit_remove()?;
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc")))?;
    init_with_kprobe(&mut ebpf)?;
    // let stat: PerCpuArray<MapData, Stat> =
    //     PerCpuArray::try_from(ebpf.take_map("STAT").expect("STAT-1")).expect("STAT-2");

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    info!("Finished");
    Ok(())
}

fn init_with_kprobe(ebpf: &mut Ebpf) -> Result<()> {
    match EbpfLogger::init(ebpf) {
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

    {
        info!("Loading '{HOOK_1}' (kprobe: {BEEE_1})");
        let prog: &mut KProbe = ebpf
            .program_mut(BEEE_1)
            .expect("Missing eBPF program")
            .try_into()
            .expect("Wrong eBPF program type");

        prog.load()?;
        prog.attach(HOOK_1, 0)?;
        info!("Hooked  '{HOOK_1}' (kprobe: {BEEE_1})");
    }

    {
        info!("Loading '{HOOK_2}' (kprobe: {BEEE_2})");
        let prog: &mut KProbe = ebpf
            .program_mut(BEEE_2)
            .expect("Missing eBPF program")
            .try_into()
            .expect("Wrong eBPF program type");

        prog.load()?;
        prog.attach(HOOK_2, 0)?;
        info!("Hooked  '{HOOK_2}' (kprobe: {BEEE_2})");
    }

    {
        info!("Loading '{HOOK_3}' (kprobe: {BEEE_3})");
        let prog: &mut KProbe = ebpf
            .program_mut(BEEE_3)
            .expect("Missing eBPF program")
            .try_into()
            .expect("Wrong eBPF program type");

        prog.load()?;
        prog.attach(HOOK_3, 0)?;
        info!("Hooked  '{HOOK_3}' (kprobe: {BEEE_3})");
    }

    {
        const IFACE: &str = "lo";
        const BEE: &str = "poc_xdp_test";

        info!("Loading XDP: {BEE}, to {IFACE}");
        let program: &mut Xdp = ebpf
            .program_mut(BEE)
            .expect("xdp-1")
            .try_into()
            .expect("xdp-2");
        program.load()?;
        program.attach(IFACE, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

        info!("Hooked  XDP: {BEE}, to {IFACE}");
    }

    Ok(())
}
