#![no_std]

/////////////////////////////////////
// Stat

#[repr(C, align(8))]
#[derive(Debug, Copy, Clone)]
pub struct Stat {
    pub total_packets: u64,
    pub redir_packets: u64,
    pub redir_failed_packets: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stat {}
