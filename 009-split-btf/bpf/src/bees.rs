use aya_ebpf::{macros::fentry, programs::FEntryContext};
use aya_log_ebpf::info;

#[fentry(function = "wg_xmit")]
pub fn wg_xmit(ctx: FEntryContext) -> i32 {
    info!(&ctx, "fentry:wireguard:wg_xmit fired");
    0
}
