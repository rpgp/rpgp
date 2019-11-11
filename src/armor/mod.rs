//! # Armor module
//!
//! Armor module provides implementation of ASCII Armor as specified in RFC 4880.

mod reader;
mod writer;

pub use self::reader::*;
pub use self::writer::*;
