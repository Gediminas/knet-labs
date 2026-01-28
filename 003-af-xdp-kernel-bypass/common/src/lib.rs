#![no_std]

/////////////////////////////////////
// Stat

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Stat {
    pub total_packets: usize,
    pub redir_packets: usize,
    pub redir_failed_packets: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stat {}
