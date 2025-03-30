//! # Armor module
//!
//! Armor module provides implementation of ASCII Armor as specified in RFC 9580.
//! <https://www.rfc-editor.org/rfc/rfc9580.html#name-forming-ascii-armor>

mod reader;
mod writer;

pub use self::{reader::*, writer::*};
