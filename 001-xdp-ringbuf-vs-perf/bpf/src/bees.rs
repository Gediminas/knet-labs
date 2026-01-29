#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use core::{mem, ptr};

use aya_ebpf::{
    bindings::{
        BPF_F_CURRENT_CPU, BPF_F_RDONLY, BPF_F_RDONLY_PROG, BPF_F_WRONLY, BPF_F_WRONLY_PROG,
        BPF_RB_FORCE_WAKEUP, BPF_RB_NO_WAKEUP, xdp_action::XDP_PASS,
    },
    macros::{map, xdp},
    maps::{PerCpuArray, PerfEventArray, RingBuf},
    programs::XdpContext,
};
use aya_ebpf_bindings::helpers;
use aya_log_ebpf::{error, info, trace};
use network_types::eth::{EthHdr, EtherType};
use poc_common::{MAX_MTU, PerfEvent, RingEvent, Stat};

const SEND_NOT: u8 = 0;
const SEND_VIA_PERF: u8 = 1;
const SEND_VIA_RING_WITH_DELAY: u8 = 2;
const SEND_VIA_RING_WITH_EPOLL: u8 = 3;

const RING_SIZE: u32 = 1 << 26; // 64 MB
const TESTING_PACKET_LEN: usize = 165; // eth(14) + ipv4(20) + udp(8) + payload(123)

#[map]
static PERF: PerfEventArray<PerfEvent> = PerfEventArray::new(0);

#[map]
static RING: RingBuf = RingBuf::with_byte_size(RING_SIZE, 0);

#[map]
static STAT: PerCpuArray<Stat> = PerCpuArray::with_max_entries(1, BPF_F_RDONLY);

#[xdp]
pub fn poc_none(ctx: XdpContext) -> u32 {
    process::<SEND_NOT>(&ctx)
}

#[xdp]
pub fn poc_perf(ctx: XdpContext) -> u32 {
    process::<SEND_VIA_PERF>(&ctx)
}

#[xdp]
pub fn poc_ring_with_delay(ctx: XdpContext) -> u32 {
    process::<SEND_VIA_RING_WITH_DELAY>(&ctx)
}

#[xdp]
pub fn poc_ring_with_epoll(ctx: XdpContext) -> u32 {
    process::<SEND_VIA_RING_WITH_EPOLL>(&ctx)
}

#[inline(always)]
fn process<const MODE: u8>(ctx: &XdpContext) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = end - start;

    // For benchmark use
    if len != TESTING_PACKET_LEN {
        return XDP_PASS;
    }

    // For normal use
    // if !aya_ebpf::check_bounds_signed(len as i64, 1, MAX_MTU as i64) {
    //     return XDP_PASS;
    // }

    if let Some(stat) = STAT.get_ptr_mut(0) {
        unsafe { (*stat).total_packets += 1 };
    }

    let time = unsafe { helpers::bpf_ktime_get_ns() };

    match MODE {
        SEND_VIA_PERF => {
            PERF.output(ctx, &(PerfEvent { time, len }), len as u32);
        }
        SEND_VIA_RING_WITH_DELAY | SEND_VIA_RING_WITH_EPOLL => {
            if let Some(mut event) = RING.reserve::<RingEvent>(0) {
                let evt_ptr = event.as_mut_ptr();

                let res = unsafe {
                    (*evt_ptr).time = time;
                    (*evt_ptr).len = len;

                    let evt_buf = (*evt_ptr).buf.as_mut_ptr() as _;
                    helpers::bpf_xdp_load_bytes(ctx.ctx, 0, evt_buf, len as u32)
                };

                if res == 0 {
                    event.submit(BPF_RB_FORCE_WAKEUP as u64) // event.submit(0)
                } else {
                    event.discard(0)
                }
            } else {
                if let Some(stat) = STAT.get_ptr_mut(0) {
                    unsafe { (*stat).ring_lost_packets += 1 };
                }
            }
        }
        _ => {}
    }

    XDP_PASS
}
