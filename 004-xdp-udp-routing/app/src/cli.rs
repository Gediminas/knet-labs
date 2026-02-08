use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "eth0")]
    pub iface: String,

    #[clap(short, long, default_value = "127.0.0.1:6707")]
    pub bind: String,
}

pub fn parse() -> Opt {
    Opt::parse()
}
