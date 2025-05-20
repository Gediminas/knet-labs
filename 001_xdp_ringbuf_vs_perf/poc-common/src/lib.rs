#![no_std]

pub const MAX_MTU: usize = 1500;

/////////////////////////////////////
// PacketBuffer

#[repr(C, align(8))]
#[derive(Debug, Copy, Clone)]
pub struct PerfEvent {
    pub time: u64,
    pub len: usize,
}

#[repr(C, align(8))]
#[derive(Debug, Copy, Clone)]
pub struct RingEvent {
    // Kernel adds 8 byte bpf_ringbuf_hdr https://elixir.bootlin.com/linux/v6.11.11/source/kernel/bpf/ringbuf.c#L84
    pub time: u64,
    pub len: usize,
    pub buf: [u8; MAX_MTU],
}

/////////////////////////////////////
// Stat

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Stat {
    pub total_packets: usize,
    pub ring_lost_packets: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stat {}
