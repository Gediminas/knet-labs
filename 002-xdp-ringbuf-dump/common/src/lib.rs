#![no_std]

/////////////////////////////////////
// RingEventHeader

#[repr(C, align(8))]
// #[derive(Debug, Copy, Clone)]
pub struct RingEventHeader {
    pub timestamp: u64,
    pub packet_len: u64,
}

/////////////////////////////////////
// Stat

#[repr(C, align(8))]
#[derive(Debug, Copy, Clone)]
pub struct Stat {
    pub total_packets: u64,
    pub ring_submitted: u64,
    pub ring_discarded: u64,
    pub ring_failed_reservations: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stat {}
