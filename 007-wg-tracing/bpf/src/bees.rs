#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use core::mem::offset_of;
use core::net::Ipv4Addr;

use aya_ebpf::bindings::{BPF_F_WRONLY_PROG, task_struct};
use aya_ebpf::cty::c_void;
use aya_ebpf::helpers::generated::bpf_get_current_task;
use aya_ebpf::helpers::{self, bpf_probe_read_kernel};
use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::programs::{ProbeContext, XdpContext};
use aya_ebpf::{
    bindings::{BPF_F_RDONLY, xdp_action::XDP_PASS},
    maps::{Array, PerCpuArray},
};
use aya_log_ebpf::{debug, error, info, warn};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::Ipv4Hdr;
// use common::{Cidrv4, MAX_PEERS, WgKey};
use poc_common::Stat;

const IPV4_VERSION: u8 = 4;
const WG_KEY_SIZE: usize = 32;
pub type WgKey = [u8; WG_KEY_SIZE];

// Kernel struct offsets (BTF: kernel 6.17, wireguard module)
// bpftool btf dump file /sys/kernel/btf/wireguard
const OFF_MCW_WORK: usize = 8; // multicore_worker.work (after void *ptr)
const OFF_ENCRYPT_Q: usize = 64; // wg_device.encrypt_queue
const OFF_DECRYPT_Q: usize = 320; // wg_device.decrypt_queue
const OFF_ND_NET: usize = 264; // net_device.nd_net
const OFF_NS: usize = 152; // net.ns
const OFF_INUM: usize = 16; // ns_common.inum

#[map]
static STAT: PerCpuArray<Stat> = PerCpuArray::with_max_entries(1, BPF_F_RDONLY);

#[map]
static TARGET_NS: Array<u32> = Array::with_max_entries(1, 0);

#[xdp]
fn inbound_wg_xdp(ctx: XdpContext) -> u32 {
    if ctx.data() + Ipv4Hdr::LEN > ctx.data_end() {
        return XDP_PASS; //Too small IPv4 packet
    }

    let version = unsafe { kit::read_unchecked::<u8>(ctx.data()) >> 4 };

    if version != IPV4_VERSION {
        return XDP_PASS; //Not an IPv4 packet
    }

    let saddr_pos = ctx.data() + offset_of!(Ipv4Hdr, src_addr);
    let daddr_pos = ctx.data() + offset_of!(Ipv4Hdr, dst_addr);
    let saddr = u32::from_be(unsafe { kit::read_unchecked(saddr_pos) });
    let daddr = u32::from_be(unsafe { kit::read_unchecked(daddr_pos) });
    let bytes = (ctx.data_end() - ctx.data()) as u64;

    let ii = ctx.ingress_ifindex();
    let q = ctx.rx_queue_index();

    warn!(
        &ctx,
        "XDP-WG: {}: {:i} -> {:i}  {} bytes", ii, saddr, daddr, bytes
    );

    // Some((local_ip.into(), bytes))

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

    XDP_PASS
}

#[xdp]
fn inbound_eth_xdp(ctx: XdpContext) -> u32 {
    if ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN > ctx.data_end() {
        return XDP_PASS; //Too small IPv4 packet
    }

    let ether_type_pos = ctx.data() + offset_of!(EthHdr, ether_type);
    let ether_type: u16 = unsafe { kit::read_unchecked(ether_type_pos) };

    if ether_type != EtherType::Ipv4 as u16 {
        // warn!(&ctx, "XDP: IPv4");
        return XDP_PASS;
    }

    let iph_pos = ctx.data() + EthHdr::LEN;
    let saddr_pos = iph_pos + offset_of!(Ipv4Hdr, src_addr);
    let daddr_pos = iph_pos + offset_of!(Ipv4Hdr, dst_addr);
    let saddr: u32 = u32::from_be_bytes(unsafe { kit::read_unchecked(saddr_pos) });
    let daddr: u32 = u32::from_be_bytes(unsafe { kit::read_unchecked(daddr_pos) });
    let ii = ctx.ingress_ifindex();

    info!(&ctx, "XDP-ET: {}: {:i} -> {:i}", ii, saddr, daddr);

    // get wg receicer index

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

// work_struct → multicore_worker.ptr → crypt_queue
//   → container_of(wg_device, queue) → wg_device.dev
//   → net_device.nd_net.net → net.ns.inum
#[inline(always)]
unsafe fn device_netns_inum(work: *const c_void, queue_offset: usize) -> Result<u32, i32> {
    unsafe {
        let queue: *const c_void = bpf_probe_read_kernel(
            (work as usize - OFF_MCW_WORK) as *const *const c_void,
        )?;
        let dev: *const c_void = bpf_probe_read_kernel(
            (queue as usize - queue_offset) as *const *const c_void,
        )?;
        let net: *const c_void = bpf_probe_read_kernel(
            (dev as usize + OFF_ND_NET) as *const *const c_void,
        )?;
        bpf_probe_read_kernel((net as usize + OFF_NS + OFF_INUM) as *const u32)
    }
}

#[inline(always)]
fn is_target_ns(inum: u32) -> bool {
    match TARGET_NS.get(0) {
        Some(&target) if target > 0 => inum == target,
        _ => true,
    }
}

#[kprobe]
pub fn wg_packet_encrypt_worker(ctx: ProbeContext) -> u32 {
    let work: *const c_void = match ctx.arg(0) {
        Some(w) => w,
        None => return 0,
    };
    match unsafe { device_netns_inum(work, OFF_ENCRYPT_Q) } {
        Ok(inum) if is_target_ns(inum) => {
            info!(&ctx, "encrypt  netns={}", inum);
        }
        _ => {}
    }
    0
}

#[kprobe]
pub fn wg_packet_decrypt_worker(ctx: ProbeContext) -> u32 {
    let work: *const c_void = match ctx.arg(0) {
        Some(w) => w,
        None => return 0,
    };
    match unsafe { device_netns_inum(work, OFF_DECRYPT_Q) } {
        Ok(inum) if is_target_ns(inum) => {
            info!(&ctx, "decrypt  netns={}", inum);
        }
        _ => {}
    }
    0
}

use aya_ebpf::macros::xdp;

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
