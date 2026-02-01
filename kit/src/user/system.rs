use libc::{CLOCK_MONOTONIC, RUSAGE_SELF, clock_gettime, getrusage, rusage, timespec};

pub fn legacy_memlock_rlimit_remove() -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    anyhow::ensure!(ret == 0, "Failed to remove locked-memory limit: {ret}");
    Ok(())
}

pub fn now_ns() -> u64 {
    let mut t: timespec = unsafe { core::mem::zeroed() };

    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut t as *mut timespec) } != 0 {
        panic!("clock_gettime failed");
    }

    (t.tv_sec as u64) * 1_000_000_000 + (t.tv_nsec as u64)
}

pub fn cpu_time_ms() -> (u64, u64) {
    let mut r: rusage = unsafe { core::mem::zeroed() };

    if unsafe { getrusage(RUSAGE_SELF, &mut r) } != 0 {
        panic!("clock_gettime failed");
    }

    let user = (r.ru_utime.tv_sec as u64) * 1_000_000 + (r.ru_utime.tv_usec as u64);
    let sys = (r.ru_stime.tv_sec as u64) * 1_000_000 + (r.ru_stime.tv_usec as u64);
    (user, sys)
}
