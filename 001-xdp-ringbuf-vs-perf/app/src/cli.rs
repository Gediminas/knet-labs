use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = None)]
    pub timeout: Option<u64>,

    #[clap(short, long, default_value = "eth0")]
    pub iface: String,

    #[clap(short, long, default_value = "false")]
    pub perf: bool,

    #[clap(short, long, default_value = "false")]
    pub ring: bool,

    #[clap(long, default_value = None)]
    pub ring_delay: Option<u32>,
}

pub fn parse() -> Opt {
    Opt::parse()
}
