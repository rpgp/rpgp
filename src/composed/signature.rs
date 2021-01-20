use std::collections::BTreeMap;
use std::iter::Peekable;

use try_from::TryInto;

use crate::armor;
use crate::composed::Deserializable;
use crate::errors::Result;
use crate::packet::{Packet, Signature};
use crate::ser::Serialize;
use crate::types::PublicKeyTrait;
use crate::types::Tag;

/// Standalone signature as defined by the cleartext framework.
#[derive(Debug, Clone)]
pub struct StandaloneSignature {
    pub signature: Signature,
}

impl StandaloneSignature {
    pub fn new(signature: Signature) -> Self {
        StandaloneSignature { signature }
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl std::io::Write,
        headers: Option<&BTreeMap<String, String>>,
    ) -> Result<()> {
        armor::write(self, armor::BlockType::Signature, writer, headers)
    }

    pub fn to_armored_bytes(&self, headers: Option<&BTreeMap<String, String>>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, headers)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, headers: Option<&BTreeMap<String, String>>) -> Result<String> {
        Ok(::std::str::from_utf8(&self.to_armored_bytes(headers)?)?.to_string())
    }

    /// Verify this signature.
    pub fn verify(&self, key: &impl PublicKeyTrait, content: &[u8]) -> Result<()> {
        self.signature.verify(key, content)
    }
}

impl Serialize for StandaloneSignature {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::packet::write_packet(writer, &self.signature)
    }
}

impl Deserializable for StandaloneSignature {
    /// Parse a signature.
    fn from_packets<'a>(
        packets: impl Iterator<Item = Packet> + 'a,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignatureParser {
            source: packets.peekable(),
        })
    }
}

pub struct SignatureParser<I: Sized + Iterator<Item = Packet>> {
    source: Peekable<I>,
}

impl<I: Sized + Iterator<Item = Packet>> Iterator for SignatureParser<I> {
    type Item = Result<StandaloneSignature>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

fn next<I: Iterator<Item = Packet>>(
    packets: &mut Peekable<I>,
) -> Option<Result<StandaloneSignature>> {
    if let Some(packet) = packets.by_ref().next() {
        match packet.tag() {
            Tag::Signature => return Some(packet.try_into().map(StandaloneSignature::new)),
            _ => return Some(Err(format_err!("unexpected packet {:?}", packet.tag()))),
        }
    }
    None
}
