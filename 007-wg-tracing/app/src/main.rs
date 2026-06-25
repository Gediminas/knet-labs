#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod cli;

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::Array,
    programs::{KProbe, Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use kit::caps::Cap;
use log::{debug, info, warn};
use std::{os::unix::fs::MetadataExt, time::Duration};
use tokio::signal;

use kmod_btf::attach_fentry;

// const HOOK_1: &str = "ip_tunnel_parse_protocol";
// const BEEE_1: &str = "ip_tunnel_parse_protocol";
// const HOOK_2: &str = "napi_gro_receive";
// const BEEE_2: &str = "napi_gro_receive";
const HOOK_2: &str = "wg_packet_decrypt_worker";
const BEEE_2: &str = "wg_packet_decrypt_worker";
const HOOK_3: &str = "wg_packet_encrypt_worker";
const BEEE_3: &str = "wg_packet_encrypt_worker";

// wg_allowedips_insert_v4
// ip_tunnel_parse_protocol

#[tokio::main]
async fn main() -> Result<()> {
    // kit::caps::require(&[Cap::Bpf, Cap::NetAdmin, Cap::Perfmon])?;
    // anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    kit::logger::init();
    let args = cli::parse();

    println!("=======================");
    println!("app:        {}", env!("CARGO_CRATE_NAME"));
    // println!("bpf1:       {:25}  {}", HOOK_1, BEEE_1);
    println!("bpf2:       {:25}  {}", HOOK_2, BEEE_2);
    println!("bpf3:       {:25}  {}", HOOK_3, BEEE_3);
    println!("log-level:  {}", log::max_level());
    println!("args:       {:?}", args);
    println!("=======================");
    // std::thread::sleep(Duration::from_secs(1));

    // let mut _ebpf = init_with_single_xdp(BEE, &args.iface)?;
    let elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc"));
    let mut ebpf = Ebpf::load(elf)?;

    let ns_inum = std::fs::metadata("/proc/self/ns/net")?.ino() as u32;
    println!("netns:      {ns_inum}");
    {
        let map = ebpf.map_mut("TARGET_NS").expect("TARGET_NS map");
        let mut target: Array<_, u32> = Array::try_from(map)?;
        target.set(0, ns_inum, 0)?;
    }

    init_xdp(&mut ebpf, "inbound_wg_xdp", &args.wg)?;
    init_xdp(&mut ebpf, "inbound_eth_xdp", &args.iface)?;

    // fentry on the WireGuard module function `wg_xmit`, loaded via raw bpf()
    // syscalls (aya can't target a module function). Its map/.rodata refs are
    // relocated against aya's loaded maps, so this MUST run before EbpfLogger::init
    // (inside init_with_kprobe) does `take_map("AYA_LOGS")`.
    let _wg_xmit_fentry = attach_fentry(&ebpf, elf, "wg_xmit", "wg_xmit", "wireguard")?;

    init_with_kprobe(&mut ebpf)?;

    // let stat: PerCpuArray<MapData, Stat> =
    //     PerCpuArray::try_from(ebpf.take_map("STAT").expect("STAT-1")).expect("STAT-2");

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    info!("Finished");
    Ok(())
}

pub fn init_xdp(ebpf: &mut Ebpf, bee: &str, iface: &str) -> Result<()> {
    log::info!("Loading XDP on '{iface}'...");

    let program: &mut Xdp = ebpf.program_mut(bee).unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    Ok(())
}

/// Sets up `EbpfLogger` and spawns a task that drains the `AYA_LOGS` map to the
/// host logger. Safe to call once; the fentry program shares this same map.
fn init_logger(ebpf: &mut Ebpf) -> Result<()> {
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
    Ok(())
}

fn init_with_kprobe(ebpf: &mut Ebpf) -> Result<()> {
    init_logger(ebpf)?;

    // {
    //     info!("Loading '{HOOK_1}' (kprobe: {BEEE_1})");
    //     let prog: &mut KProbe = ebpf
    //         .program_mut(BEEE_1)
    //         .expect("Missing eBPF program")
    //         .try_into()
    //         .expect("Wrong eBPF program type");

    //     prog.load()?;
    //     prog.attach(HOOK_1, 0)?;
    //     info!("Hooked  '{HOOK_1}' (kprobe: {BEEE_1})");
    // }

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

    // {
    //     const IFACE: &str = args.wg;
    //     const BEE: &str = "poc_xdp_test";

    //     info!("Loading XDP: {BEE}, to {IFACE}");
    //     let program: &mut Xdp = ebpf
    //         .program_mut(BEE)
    //         .expect("xdp-1")
    //         .try_into()
    //         .expect("xdp-2");
    //     program.load()?;
    //     program.attach(IFACE, XdpFlags::default())
    //     .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    //     info!("Hooked  XDP: {BEE}, to {IFACE}");
    // }

    Ok(())
}
