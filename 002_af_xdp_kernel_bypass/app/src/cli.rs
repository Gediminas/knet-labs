use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = None)]
    pub timeout: Option<u64>,

    #[clap(short, long, default_value = "eth0")]
    pub iface: String,
}

pub fn parse() -> Opt {
    Opt::parse()
}
