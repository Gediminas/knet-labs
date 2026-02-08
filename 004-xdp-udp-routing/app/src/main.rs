#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod api;
mod cli;

use anyhow::{Context as _, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, HashMap, MapData},
    programs::{Xdp, XdpFlags},
};
use log::info;
use log::{debug, warn};
// use poc_common::{GlobalRule, HalfRoute};
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    signal,
    sync::Mutex,
};

const BEE: &str = "poc_xdp_router";

#[tokio::main]
async fn main() -> Result<()> {
    anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    let args = cli::parse();
    kit::logger::init();

    println!("=======================");
    println!("app:        {}", env!("CARGO_CRATE_NAME"));
    println!("bpf:        {}", BEE);
    println!("log-level:  {}", log::max_level());
    println!("iface:      {}", args.iface);
    println!("args:       {:?}", args);
    println!("=======================");

    let ebpf = init_with_single_xdp(BEE, &args.iface)?;

    info!("Starting API server...");
    tokio::spawn(api::run(ebpf, args.bind));

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    Ok(())
}

// async fn serve_request(stream: &mut TcpStream, bpf: Arc<Mutex<Ebpf>>) -> Result<()> {
//     let remote = stream.peer_addr()?;
//     let mut json = String::new();
//     stream.read_to_string(&mut json).await?;

//     info!("From {remote}: {json}");

//     let res = match serde_json::from_str(&json)? {
//         RouteCmd::SetPolicy { policy } => {
//             let mut bpf = (*bpf).lock().await;
//             let mut globals: Array<&mut MapData, u8> =
//                 Array::try_from(bpf.map_mut("XDP_ROUTER_GLOBAL").unwrap())?;
//             info!("New policy: {policy:?}");
//             globals.set(GlobalRule::Policy as u32, policy as u8, 0)?;
//             "OK"
//         }
//         RouteCmd::AddMirror { port } => {
//             let mut bpf = (*bpf).lock().await;
//             let mut mirrors: HashMap<&mut MapData, u16, u8> =
//                 HashMap::try_from(bpf.map_mut("XDP_ROUTER_MIRRORS").unwrap())?;
//             mirrors.insert(port.to_be(), 1u8, 0)?;
//             "OK"
//         }
//         RouteCmd::RemMirror { port } => {
//             let mut bpf = (*bpf).lock().await;
//             let mut mirrors: HashMap<&mut MapData, u16, u8> =
//                 HashMap::try_from(bpf.map_mut("XDP_ROUTER_MIRRORS").unwrap())?;
//             mirrors.remove(&port.to_be())?;
//             "OK"
//         }
//         RouteCmd::ListMirrors => "Not implemented",
//         RouteCmd::AddRoute { half1, half2 } => {
//             let mut bpf = (*bpf).lock().await;
//             let mut routes: HashMap<&mut MapData, HalfRoute, HalfRoute> =
//                 HashMap::try_from(bpf.map_mut("XDP_ROUTER_ROUTES").unwrap())?;
//             routes.insert(half1.to_be(), half2.to_be(), 0)?;
//             routes.insert(half2.to_be(), half1.to_be(), 0)?;
//             "OK"
//         }
//         RouteCmd::RemRoute { half1, half2 } => {
//             let mut bpf = (*bpf).lock().await;
//             let mut routes: HashMap<&mut MapData, HalfRoute, HalfRoute> =
//                 HashMap::try_from(bpf.map_mut("XDP_ROUTER_ROUTES").unwrap())?;
//             routes.remove(&half1.to_be())?;
//             routes.remove(&half2.to_be())?;
//             "OK"
//         }
//     };

//     stream.write_all(res.as_bytes()).await?;
//     Ok(())
// }

pub fn init_with_single_xdp(bee: &str, iface: &str) -> Result<Ebpf> {
    kit::system::legacy_memlock_rlimit_remove()?;

    log::info!("Loading XDP on '{iface}'...");
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc")))?;
    log::info!("XDP loaded");

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("Failed to initialize eBPF logger: {e}");
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
