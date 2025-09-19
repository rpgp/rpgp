//! Handle base64, as used in [`crate::armor`]

mod decoder;
mod reader;

pub use self::{decoder::Base64Decoder, reader::Base64Reader};
