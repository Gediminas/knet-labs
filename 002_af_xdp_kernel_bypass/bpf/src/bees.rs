#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use crate::bpf_utils::read_unchecked;
use aya_ebpf::{
    bindings::{
        xdp_action::{XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX},
        BPF_F_RDONLY, BPF_F_WRONLY_PROG, BPF_RB_FORCE_WAKEUP, BPF_RB_NO_WAKEUP, TC_ACT_PIPE,
    },
    macros::{classifier, map, xdp},
    maps::{PerCpuArray, PerfEventArray, RingBuf, XskMap},
    programs::{TcContext, XdpContext},
};
use aya_ebpf_bindings::helpers;
use aya_log_ebpf::{debug, error, info, trace, warn};
use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use poc_common::Stat;

const WG_PORT: u16 = 12345_u16.to_be();
const WG_REDIR_ETHER_LEN: usize = 165; // Lengths: ETH 165, IP4 151, UDP 131, Payload 123

#[map]
static STATS: PerCpuArray<Stat> = PerCpuArray::with_max_entries(1, BPF_F_RDONLY);

#[map]
static XSKS: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn poc_redirect_to_afxdp(ctx: XdpContext) -> u32 {
    inc_stat_total();

    if should_redirect(&ctx) {
        inc_stat_redir();

        let rx_queue_index = unsafe { (*ctx.ctx).rx_queue_index };

        match XSKS.redirect(rx_queue_index, XDP_PASS as _) {
            Ok(action) => {
                if action != XDP_REDIRECT {
                    inc_stat_redir_failed();
                    error!(&ctx, "AF_XDP redirection failed, action is {}", action);
                }
                return action;
            }
            Err(e) => {
                inc_stat_redir_failed();
                error!(&ctx, "XDP ERROR {}", e)
            }
        }
    }

    XDP_PASS
}

#[inline(always)]
pub fn should_redirect(ctx: &XdpContext) -> bool {
    // Required to pass eBPF-verifier
    if ctx.data() + WG_REDIR_ETHER_LEN > ctx.data_end() {
        return false;
    }

    if ctx.data_end() - ctx.data() != WG_REDIR_ETHER_LEN {
        return false;
    }

    // FIXME EtherType is limited enum, which is UB when parsing packet, drop EthHdr (but works for now)
    let eth: EthHdr = unsafe { read_unchecked(ctx.data()) };
    if let EtherType::Ipv4 = eth.ether_type {
    } else {
        return false;
    }

    let ip4_ptr = ctx.data() + EthHdr::LEN;
    let ip4: Ipv4Hdr = unsafe { read_unchecked(ip4_ptr) };
    if ip4.proto != IpProto::Udp {
        return false;
    }

    let udp_ptr = ip4_ptr + Ipv4Hdr::LEN;
    let udp: UdpHdr = unsafe { read_unchecked(udp_ptr) };
    if udp.dest != WG_PORT {
        return false;
    }

    trace!(
        ctx,
        "[XDP] {:i}:{} -> {:i}:{} ===> AF_XDP",
        u32::from_be(ip4.src_addr),
        u16::from_be(udp.source),
        u32::from_be(ip4.dst_addr),
        u16::from_be(udp.dest),
    );

    true
}

fn inc_stat_total() {
    if let Some(stat) = STATS.get_ptr_mut(0) {
        unsafe { (*stat).total_packets += 1 };
    }
}

fn inc_stat_redir() {
    if let Some(stat) = STATS.get_ptr_mut(0) {
        unsafe { (*stat).redir_packets += 1 };
    }
}

fn inc_stat_redir_failed() {
    if let Some(stat) = STATS.get_ptr_mut(0) {
        unsafe { (*stat).redir_failed_packets += 1 };
    }
}
