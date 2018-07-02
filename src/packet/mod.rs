///! This module handles everything in relation ship to packets.
pub mod tags;
pub mod types;

mod many;
mod single;

pub use self::many::parser;
