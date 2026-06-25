use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    /// Kernel module whose split BTF holds the target function.
    #[clap(short, long, default_value = "wireguard")]
    pub module: String,

    /// Function within `module` to attach the fentry to.
    #[clap(short, long, default_value = "wg_xmit")]
    pub func: String,
}

pub fn parse() -> Opt {
    Opt::parse()
}
