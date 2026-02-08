extern crate std;

use crate::user::logger::std::string::ToString;
use clap::builder::styling::AnsiColor;
use log::{Level, LevelFilter};
use std::io::Write;

pub fn init() {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .format(|buf, record| {
            let s1 = AnsiColor::Blue.on_default();
            let s2 = match record.level() {
                Level::Info => AnsiColor::White.on_default(),
                Level::Debug => AnsiColor::Green.on_default(),
                Level::Trace => AnsiColor::Blue.on_default(),
                _ => buf.default_level_style(record.level()),
            };
            let l = &record.level().as_str()[..1];
            let a = record.args();

            // Use millis or micros
            // let t = buf.timestamp_micros();
            let t = buf.timestamp_millis();

            // Remove date && hour
            let t = t.to_string().split_at(14).1.to_string();

            let t = t.to_string().replace("T", " ");
            let t = t.to_string().replace("Z", "");

            writeln!(buf, "{s1}{t}{s1:#} {s2}[{l}] {a}{s2:#}")
            // writeln!(buf, "[{l}] {s2}{a}{s2:#}")
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
