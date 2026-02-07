use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "eth0")]
    pub iface: String,

    #[clap(short, long, default_value = "dump.pcap")]
    pub out: String,
}

pub fn parse() -> Opt {
    Opt::parse()
}
