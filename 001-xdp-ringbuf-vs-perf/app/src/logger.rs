use clap::builder::styling::AnsiColor;
use log::Level::{Debug, Info, Trace};
use std::io::Write;

pub fn init() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .format(|buf, record| {
            let _s1 = AnsiColor::Blue.on_default();
            let s2 = match record.level() {
                Info => AnsiColor::White.on_default(),
                Debug => AnsiColor::Green.on_default(),
                Trace => AnsiColor::Blue.on_default(),
                _ => buf.default_level_style(record.level()),
            };
            let l = &record.level().as_str()[..1];
            let a = record.args();
            // let t = buf.timestamp_millis();
            // let t = buf.timestamp_micros();
            // let t = t.to_string().split_at(14).1.to_string(); // Remove date && hour
            // let t = t.to_string().replace("T", " ");
            // let t = t.to_string().replace("Z", "");

            // writeln!(buf, "{s1}{t}{s1:#} {s2}[{l}] {a}{s2:#}")
            writeln!(buf, "[{l}] {s2}{a}{s2:#}")
        })
        .init();
}

#[allow(dead_code)]
pub fn test() {
    log::error!("This is error");
    log::warn!("This is warning");
    log::info!("This is info");
    log::debug!("This is debug");
    log::trace!("This is trace");
}
