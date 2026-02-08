#![no_std]

/////////////////////////////////////
// Policy

#[repr(u32)]
pub enum GlobalRule {
    Policy,
    Size,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(serde::Deserialize, serde::Serialize))]
pub enum Policy {
    Accept = 0,
    Drop,
}

/////////////////////////////////////
// Route

#[repr(C, align(4))]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(serde::Deserialize, serde::Serialize))]
pub struct HalfRoute {
    pub reflexive_addr: u32,
    pub reflexive_port: u16,
    pub router_port: u16,
}

impl HalfRoute {
    pub fn new(reflexive_addr: u32, reflexive_port: u16, router_port: u16) -> Self {
        Self {
            reflexive_addr,
            reflexive_port,
            router_port,
        }
    }

    pub fn to_be(&self) -> HalfRoute {
        HalfRoute {
            reflexive_addr: self.reflexive_addr.to_be(),
            reflexive_port: self.reflexive_port.to_be(),
            router_port: self.router_port.to_be(),
        }
    }

    pub fn from_be(&self) -> HalfRoute {
        HalfRoute {
            reflexive_addr: u32::from_be(self.reflexive_addr),
            reflexive_port: u16::from_be(self.reflexive_port),
            router_port: u16::from_be(self.router_port),
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HalfRoute {}

/////////////////////////////////////
// RouteCmd

// #[cfg(feature = "user")]
// #[derive(serde::Serialize, serde::Deserialize, Debug)]
// pub enum RouteCmd {
//     SetPolicy { policy: Policy },
//     AddMirror { port: u16 },
//     RemMirror { port: u16 },
//     ListMirrors,
//     AddRoute { half1: HalfRoute, half2: HalfRoute },
//     RemRoute { half1: HalfRoute, half2: HalfRoute },
// }

/////////////////////////////////////
// Stat

// #[repr(C, align(8))]
// #[derive(Debug, Copy, Clone)]
// pub struct Stat {
//     pub total_packets: u64,
//     pub ring_submitted: u64,
//     pub ring_discarded: u64,
//     pub ring_failed_reservations: u64,
// }

// #[cfg(feature = "user")]
// unsafe impl aya::Pod for Stat {}
