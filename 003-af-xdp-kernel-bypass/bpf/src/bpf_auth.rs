#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_REDIRECT, XDP_TX};
use aya_ebpf::bindings::TC_ACT_PIPE;
use aya_ebpf::macros::{classifier, map};
use aya_ebpf::maps::XskMap;
use aya_ebpf::programs::TcContext;
use aya_ebpf::{
    bindings::xdp_action::XDP_PASS,
    // macros::{classifier, map},
    // programs::TcContext,
};
use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, error, info, trace, warn};
use common::WgMessageType;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::udp::UdpHdr;

const WG_PORT: u16 = 51820_u16.to_be();
const WG_HANDSHAKE_INIT_ETHER_LEN: usize = 190; // Lengths: ETH 190, IP4 176, UDP 156, WG 148

#[map]
static XSOCKS: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn bpf_auth(ctx: XdpContext) -> u32 {
    let redirect = is_wg_handshake_initiation(&ctx);

    if redirect {
        trace!(&ctx, "[XDP] ---➤ packet: {}", ctx.data_end() - ctx.data());
    } else {
        // trace!(&ctx, "[XDP] ···➤ packet: {}", ctx.data_end() - ctx.data());
    }

    if redirect {
        let queue_index = unsafe { (*ctx.ctx).rx_queue_index };

        match XSOCKS.redirect(queue_index, XDP_PASS as _) {
            Ok(action) => {
                if action != XDP_REDIRECT {
                    error!(&ctx, "Not redirected, action returned {}", action);
                }
                return action;
            }
            Err(e) => error!(&ctx, "ERROR {}", e),
        }
    }

    XDP_PASS
}

#[xdp]
pub fn bpf_hairpin(ctx: XdpContext) -> u32 {
    // info!(&ctx, "CHECK xdp PACKET: {}", ctx.data_end() - ctx.data());
    if is_wg_handshake_initiation(&ctx) {
        warn!(
            &ctx,
            "*****************  xdp PACKET: {}",
            ctx.data_end() - ctx.data()
        );
        return XDP_TX;
    }

    XDP_PASS
}

#[classifier]
pub fn bpf_auth_ingress_checker(ctx: TcContext) -> i32 {
    if is_wg_handshake_initiation_tc(&ctx) {
        info!(
            &ctx,
            "-->> TC-INGRESS packet: {}",
            ctx.data_end() - ctx.data()
        );
    }

    TC_ACT_PIPE
}

#[classifier]
pub fn bpf_auth_egress_checker(ctx: TcContext) -> i32 {
    // info!(&ctx, "CHECK xdp PACKET: {}", ctx.data_end() - ctx.data());
    if is_wg_handshake_initiation_tc(&ctx) {
        warn!(
            &ctx,
            "!!!!!!!!! BACK  tc-egress PACKET: {}",
            ctx.data_end() - ctx.data()
        );
        // return XDP_TX;
        // return bpf_redirect_peer(ctx.0->ifindex, 0);
    }

    // info!(
    //     &ctx,
    //     "<<-- TC-EGRESS packet: {}",
    //     ctx.data_end() - ctx.data()
    // );

    TC_ACT_PIPE
}

#[inline(always)]
pub fn is_wg_handshake_initiation(ctx: &XdpContext) -> bool {
    // // This check is optimization & "obsfucated" from eBPF-verifier
    // if ctx.data_end() - ctx.data() != WG_HANDSHAKE_INIT_ETHER_LEN {
    //     return false;
    // }

    // eBPF-verifier still requires this check (with `>`)
    if ctx.data() + WG_HANDSHAKE_INIT_ETHER_LEN > ctx.data_end() {
        return false;
    }

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

    let wg_ptr = udp_ptr + UdpHdr::LEN;
    let wg_type: WgMessageType = unsafe { read_unchecked(wg_ptr) };
    if wg_type != WgMessageType::HandshakeInitiation {
        return false;
    }

    // let wg = unsafe { read_unchecked::<WgHandshakeInitiation>(wg_ptr) };
    // let wg_sender: u32 = unsafe { read_unchecked(wg_ptr + 4) };
    //
    // debug!(ctx, "XDP: ---> Redirecting wg-hs-init {:i}:{}->{:i}:{} [0x{:x}]",
    //     u32::from_be(ip4.src_addr), u16::from_be(udp.source),
    //     u32::from_be(ip4.dst_addr), u16::from_be(udp.dest),
    //     u32::from_be(wg_sender) );

    true
}

#[inline(always)]
pub fn is_wg_handshake_initiation_tc(ctx: &TcContext) -> bool {
    // // This check is optimization & "obsfucated" from eBPF-verifier
    // if ctx.data_end() - ctx.data() != WG_HANDSHAKE_INIT_ETHER_LEN {
    //     return false;
    // }

    // eBPF-verifier still requires this check (with `>`)
    if ctx.data() + WG_HANDSHAKE_INIT_ETHER_LEN > ctx.data_end() {
        return false;
    }

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

    let wg_ptr = udp_ptr + UdpHdr::LEN;
    let wg_type: WgMessageType = unsafe { read_unchecked(wg_ptr) };
    if wg_type != WgMessageType::HandshakeInitiation {
        return false;
    }

    // let wg = unsafe { read_unchecked::<WgHandshakeInitiation>(wg_ptr) };
    // let wg_sender: u32 = unsafe { read_unchecked(wg_ptr + 4) };
    //
    // debug!(ctx, "XDP: ---> Redirecting wg-hs-init {:i}:{}->{:i}:{} [0x{:x}]",
    //     u32::from_be(ip4.src_addr), u16::from_be(udp.source),
    //     u32::from_be(ip4.dst_addr), u16::from_be(udp.dest),
    //     u32::from_be(wg_sender) );

    true
}

#[inline(always)]
unsafe fn read_unchecked<T>(pos: usize) -> T {
    let ptr = pos as *const T;
    unsafe { ptr.read_unaligned() }
}
