#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use aya_ebpf::bindings::BPF_F_WRONLY_PROG;
use aya_ebpf::cty::c_void;
use aya_ebpf::helpers;
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::programs::{ProbeContext, XdpContext};
use aya_ebpf::{
    bindings::{BPF_F_RDONLY, xdp_action::XDP_PASS},
    maps::PerCpuArray,
};
use aya_log_ebpf::{debug, error, warn};
// use common::{Cidrv4, MAX_PEERS, WgKey};
use poc_common::Stat;

const WG_KEY_SIZE: usize = 32;
pub type WgKey = [u8; WG_KEY_SIZE];

#[map]
static STAT: PerCpuArray<Stat> = PerCpuArray::with_max_entries(1, BPF_F_RDONLY);

#[xdp]
fn poc_xdp(ctx: XdpContext) -> u32 {
    // match process(&ctx) {
    //     Ok(ret) => ret,
    //     Err(e) => {
    //         let msg = match e {
    //             XdpError::Outside => "Offset is outside of the packet",
    //         };
    //         error!(&ctx, "{} => XDP_ABORTED", msg);
    //         XDP_ABORTED
    //     }
    // }
    warn!(&ctx, "XDP");
    XDP_PASS
}

/////////////////////////////////////////////
// https://elixir.bootlin.com/linux/v6.14/source/include/uapi/linux/if_tunnel.h#L48
// struct ip_tunnel_parm {
//     char			name[IFNAMSIZ];
//     int			link;
//     __be16			i_flags;
//     __be16			o_flags;
//     __be32			i_key;
//     __be32			o_key;
//     struct iphdr		iph;
// };
// https://elixir.bootlin.com/linux/v6.14/source/include/net/ip_tunnels.h#L420
// __be16 ip_tunnel_parse_protocol(const struct sk_buff *skb);
#[kprobe]
pub fn ip_tunnel_parse_protocol(ctx: ProbeContext) -> u32 {
    debug!(&ctx, "kprobe: ip_tunnel_parse_protocol()");

    let skb: *const c_void = ctx.arg(0).unwrap();
    // let pid = unsafe { bpf_probe_read(core::ptr::addr_of!(skb)) }.map_err(|err| err as u32)?;
    //
    let mut buf = [0u8; 124];
    let bbb = buf.as_mut_ptr();
    let bbb = bbb as *mut c_void;

    let x = unsafe { helpers::generated::bpf_probe_read_kernel(bbb, 120, skb) };

    debug!(&ctx, "{}", bbb as u32);

    // let peer_ptr: *const u8 = ctx.arg(ARG_PEER).unwrap();
    // let key_ptr = unsafe { peer_ptr.offset(WG_PEER_PUB_KEY_OFFSET) } as *const [u8; 32];
    // let key = unsafe { bpf_probe_read(key_ptr).unwrap_or_default() };
    // warn!(ctx, "key: {}", key[0]);

    // let Some(stat) = STAT.get_ptr_mut(0) else {
    //     error!(&ctx, "STAT failed");
    //     return 0;
    // };

    // unsafe { (*stat).total_packets += 1 };

    // // if let Some((key, ip)) = parse_fn_args(&ctx) {
    // //     // if let Err(e) = update_mapping(key, ip) {
    // //     //     warn!(&ctx, "ip2key: {}", e);
    // //     // }
    // // }

    0
}

// https://elixir.bootlin.com/linux/v6.14/source/net/core/gro.c#L623
// gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
#[kprobe]
pub fn napi_gro_receive(ctx: ProbeContext) -> u32 {
    debug!(&ctx, "kprobe: napi_gro_receive()");
    0
}

#[kprobe]
pub fn wg_packet_encrypt_worker(ctx: ProbeContext) -> u32 {
    debug!(&ctx, "kprobe: wg_packet_encrypt_worker()");
    // parse_fn_args(&ctx);
    0
}

use aya_ebpf::macros::xdp;

#[xdp]
fn poc_xdp_test(ctx: XdpContext) -> u32 {
    // warn!(&ctx, "xdp");
    XDP_PASS
}

// const LOCAL_NETWORK: Cidrv4 = Cidrv4::from_prefix(common::LOCAL_NETWORK, 0);

/// Offset to "wg_peer.handshake.remote_static"
/// - WireGuard: https://elixir.bootlin.com/linux/v6.1.131/source/drivers/net/wireguard/peer.h#L37
const WG_PEER_PUB_KEY_OFFSET: isize = 328;

// Parses arguments to `wg_allowedips_insert_v4`:
//    int wg_allowedips_insert_v4( struct allowedips *table,
//                                 const struct in_addr *ip,
//                                 u8 cidr,
//                                 struct wg_peer *peer,
//                                 struct mutex *lock)
//
// https://elixir.bootlin.com/linux/v6.1.131/source/drivers/net/wireguard/allowedips.c#L281
#[inline(always)]
fn parse_fn_args(ctx: &ProbeContext) {
    const ARG_IP: usize = 1;
    const ARG_CIDR: usize = 2;
    const ARG_PEER: usize = 3;

    // let cidr: u8 = ctx.arg(ARG_CIDR)?;
    // if cidr != 32 {
    //     return None;
    // }

    let ip_ptr: *const u32 = ctx.arg(ARG_IP).unwrap();
    let ip_net = unsafe { helpers::bpf_probe_read(ip_ptr).unwrap_or_default() };
    let ip_host = u32::from_be(ip_net);
    warn!(ctx, "host: {}", ip_host);

    let peer_ptr: *const u8 = ctx.arg(ARG_PEER).unwrap();
    let key_ptr = unsafe { peer_ptr.offset(WG_PEER_PUB_KEY_OFFSET) } as *const [u8; 32];
    let key = unsafe { helpers::bpf_probe_read(key_ptr).unwrap_or_default() };
    warn!(ctx, "key: {}", key[0]);
}

// Updates mapping:
//     local tunnel IPv4 address -> wg peer public key
// #[inline(always)]
// fn update_mapping(key: WgKey, ip: u32) -> Result<()> {
//     // LOCAL_IP_TO_KEY
//     //     .insert(&ip, &key, 0)
//     //     .map_err(|_| "Failed to insert key")?;
//     Ok(())
// }
