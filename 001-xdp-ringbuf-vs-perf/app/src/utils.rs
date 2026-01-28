use libc::{clock_gettime, getrusage, rusage, timespec, CLOCK_MONOTONIC, RUSAGE_SELF};
use std::time::Duration;

pub fn now_ns() -> u64 {
    let mut t: timespec = unsafe { std::mem::zeroed() };

    if unsafe { clock_gettime(CLOCK_MONOTONIC, &mut t as *mut timespec) } != 0 {
        panic!("clock_gettime failed");
    }

    (t.tv_sec as u64) * 1_000_000_000 + (t.tv_nsec as u64)
}

pub fn cpu_time_ms() -> (u64, u64) {
    let mut r: rusage = unsafe { std::mem::zeroed() };

    if unsafe { getrusage(RUSAGE_SELF, &mut r) } != 0 {
        panic!("clock_gettime failed");
    }

    let user = (r.ru_utime.tv_sec as u64) * 1_000_000 + (r.ru_utime.tv_usec as u64);
    let sys = (r.ru_stime.tv_sec as u64) * 1_000_000 + (r.ru_stime.tv_usec as u64);
    (user, sys)
}
