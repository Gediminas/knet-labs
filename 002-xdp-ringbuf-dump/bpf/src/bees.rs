// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

use aya_ebpf::{
    bindings::{xdp_action::XDP_PASS, BPF_F_RDONLY},
    helpers,
    macros::{map, xdp},
    maps::{PerCpuArray, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::error;
use core::mem;
use network_types::eth::EthHdr;
use poc_common::{RingEventHeader, Stat};

const RING_SIZE: u32 = 1 << 26; // 64 MB
const EVENT_HDR: usize = mem::size_of::<RingEventHeader>();

const BUCKET_SMALL: usize = 1 << 8; // 256
const BUCKET_MEDIUM: usize = 1 << 10; // 1024
const BUCKET_LARGE: usize = 1 << 11; // 2048; MTU fits (1500 + 2)
const BUCKET_JUMBO: usize = 1 << 14; // 16384; Jumbo fits (9000 + 2)

const LIMIT_INVALID: usize = EthHdr::LEN;
const LIMIT_SMALL: usize = BUCKET_SMALL - EVENT_HDR;
const LIMIT_MEDIUM: usize = BUCKET_MEDIUM - EVENT_HDR;
const LIMIT_LARGE: usize = BUCKET_LARGE - EVENT_HDR;
const LIMIT_JUMBO: usize = BUCKET_JUMBO - EVENT_HDR;

#[map]
static RING: RingBuf = RingBuf::with_byte_size(RING_SIZE, 0);

#[map]
static STAT: PerCpuArray<Stat> = PerCpuArray::with_max_entries(1, BPF_F_RDONLY);

#[xdp]
pub fn poc_xdp_ring(ctx: XdpContext) -> u32 {
    let Some(stat) = STAT.get_ptr_mut(0) else {
        error!(&ctx, "STAT failed");
        return XDP_PASS;
    };

    unsafe { (*stat).total_packets += 1 };

    // Verifier safer perhaps:
    // if !aya_ebpf::check_bounds_signed(len as i64, 1, MAX_MTU as i64) {
    //     return XDP_PASS;
    // }

    let len = ctx.data_end() - ctx.data();
    let reservation_size = match len {
        ..LIMIT_INVALID => return XDP_PASS, // Verifier is happy with this!
        ..=LIMIT_SMALL => BUCKET_SMALL,
        ..=LIMIT_MEDIUM => BUCKET_MEDIUM,
        ..=LIMIT_LARGE => BUCKET_LARGE,
        ..=LIMIT_JUMBO => BUCKET_JUMBO,
        _ => return XDP_PASS, // Verifier is happy with this!
    };

    if let Some(mut reservation) = RING.reserve_bytes(reservation_size, 0) {
        let ptr = reservation.as_mut_ptr();

        // SAFETY: Ringbuf reservations are 8-byte aligned.
        //         RingEventHeader alignment is 8, so casting the pointer is safe.
        let header = unsafe { &mut *(ptr as *mut RingEventHeader) };
        header.timestamp = unsafe { helpers::bpf_ktime_get_ns() };
        header.packet_len = len as u64;

        // SAFETY: dst is 8-byte aligned (ptr + 16-byte header).
        //         load_bytes is safe as len is bounded by the reservation size.
        let res = unsafe {
            let dst = ptr.byte_add(EVENT_HDR) as _;
            helpers::bpf_xdp_load_bytes(ctx.ctx, 0, dst, len as u32)
        };

        if res != 0 {
            reservation.discard(0);
            unsafe { (*stat).ring_discarded += 1 };
            return XDP_PASS;
        }

        reservation.submit(0);
        unsafe { (*stat).ring_submitted += 1 };
    } else {
        unsafe { (*stat).ring_failed_reservations += 1 };
    }

    XDP_PASS
}
