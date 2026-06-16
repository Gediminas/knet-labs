//! Effective-capability preflight. Pass the caps a tool actually needs; this
//! passes both as root (has all) and inside a shell that granted them (e.g.
//! `just caps`), and bails on the first missing one with an actionable message.

/// Linux capabilities used across these labs, value = capability bit number.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Cap {
    NetAdmin = 12, // CAP_NET_ADMIN — attach XDP/tc, configure networking
    NetRaw = 13,   // CAP_NET_RAW   — AF_XDP / raw sockets
    IpcLock = 14,  // CAP_IPC_LOCK  — bypass RLIMIT_MEMLOCK (AF_XDP UMEM)
    SysAdmin = 21, // CAP_SYS_ADMIN — setns, misc
    Perfmon = 38,  // CAP_PERFMON   — kprobe/fentry/perf_event
    Bpf = 39,      // CAP_BPF       — load BPF programs/maps
}

impl Cap {
    fn name(self) -> &'static str {
        match self {
            Cap::NetAdmin => "cap_net_admin",
            Cap::NetRaw => "cap_net_raw",
            Cap::IpcLock => "cap_ipc_lock",
            Cap::SysAdmin => "cap_sys_admin",
            Cap::Perfmon => "cap_perfmon",
            Cap::Bpf => "cap_bpf",
        }
    }
}

/// Check if process holds each of `needed` in its effective set.
pub fn require(needed: &[Cap]) -> anyhow::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let hdr = Header {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let mut data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let rc = unsafe { libc::syscall(libc::SYS_capget, &hdr as *const Header, data.as_mut_ptr()) };
    anyhow::ensure!(rc == 0, "capget failed (rc {rc})");

    let eff = (data[0].effective as u64) | ((data[1].effective as u64) << 32);
    for &c in needed {
        anyhow::ensure!(
            eff & (1u64 << (c as u8)) != 0,
            "missing {} — run as root or in a shell that grants it",
            c.name()
        );
    }
    Ok(())
}
