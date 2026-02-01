#![no_std] // Always no_std for BPF compatibility

#[cfg(feature = "kernel")]
mod kernel;

#[cfg(feature = "kernel")]
pub use kernel::*;

#[cfg(feature = "user")]
mod user;

#[cfg(feature = "user")]
pub use user::*;
