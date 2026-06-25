mod cli;

use anyhow::Result;
use aya::{Ebpf, include_bytes_aligned};
use aya_log::EbpfLogger;
use log::{info, warn};
use tokio::signal;

use kmod_btf::attach_fentry;

#[tokio::main]
async fn main() -> Result<()> {
    // kit::caps::require(&[Cap::Bpf, Cap::NetAdmin, Cap::Perfmon, Cap::SysAdmin])?;
    // anyhow::ensure!(unsafe { libc::getuid() == 0 }, "Requires root privileges");
    kit::logger::init();
    let args = cli::parse();

    println!("=======================");
    println!("app:        {}", env!("CARGO_CRATE_NAME"));
    println!("fentry:     {}:{}", args.module, args.func);
    println!("log-level:  {}", log::max_level());
    println!("=======================");

    let elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/poc"));
    let mut ebpf = Ebpf::load(elf)?;

    // fentry on a kernel-module function. aya can't target a module function
    // (split BTF), so the program is loaded via raw bpf() syscalls, relocating
    // its map/.rodata refs against aya's already-loaded maps. The returned
    // handle owns the prog/link fds; dropping it detaches.
    //
    // Must run BEFORE init_logger: `EbpfLogger::init` does `take_map("AYA_LOGS")`,
    // removing that map from `ebpf`, but the relocation needs to look it up here.
    let _fentry = attach_fentry(&ebpf, elf, "wg_xmit", &args.func, &args.module)?;

    // Drain eBPF logs (incl. the fentry's `warn!`) to the host logger.
    init_logger(&mut ebpf)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;

    info!("Finished");
    Ok(())
}

/// Sets up `EbpfLogger` and spawns a task that drains the `AYA_LOGS` map to the
/// host logger. The fentry program shares this same map.
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
