use clap::Parser;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "any")]
    pub anything: String,
}

pub fn parse() -> Opt {
    Opt::parse()
}
