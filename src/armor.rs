//! Handling of OpenPGP ASCII Armor
//!
//! Armor module provides implementation of ASCII Armor as specified in RFC 9580.
//! <https://www.rfc-editor.org/rfc/rfc9580.html#name-forming-ascii-armor>

mod checksum;
mod reader;
mod writer;

pub(crate) use self::checksum::Crc24Hasher;
pub use self::{reader::*, writer::*};
