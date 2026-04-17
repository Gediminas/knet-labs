use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "wg0")]
    pub wg: String,

    #[clap(short, long, default_value = "eth0")]
    pub iface: String,

    #[clap(short, long, default_value = "51820")]
    pub port: u16,
}

pub fn parse() -> Opt {
    Opt::parse()
}
