use std::iter::Peekable;

use crate::{
    armor,
    composed::{ArmorOptions, Deserializable},
    errors::{format_err, Result},
    packet::{Packet, PacketTrait, Signature},
    ser::Serialize,
    types::{PublicKeyTrait, Tag},
};

/// An OpenPGP data signature that occurs outside an OpenPGP Message,
/// as a "detached signature":
///
/// <https://www.rfc-editor.org/rfc/rfc9580.html#detached-signatures>.
///
/// All [DetachedSignature]s are either of type [SignatureType::Binary] or [SignatureType::Text].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    pub signature: Signature,
}

impl DetachedSignature {
    pub fn new(signature: Signature) -> Self {
        DetachedSignature { signature }
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl std::io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        armor::write(
            self,
            armor::BlockType::Signature,
            writer,
            opts.headers,
            opts.include_checksum,
        )
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, opts)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }

    /// Verify this signature.
    pub fn verify(&self, key: &impl PublicKeyTrait, content: &[u8]) -> Result<()> {
        self.signature.verify(key, content)
    }
}

impl Serialize for DetachedSignature {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.signature.to_writer_with_header(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.signature.write_len_with_header()
    }
}

impl Deserializable for DetachedSignature {
    /// Parse a signature.
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignatureParser { source: packets })
    }

    fn matches_block_type(typ: armor::BlockType) -> bool {
        matches!(typ, armor::BlockType::Signature)
    }
}

pub struct SignatureParser<I: Sized + Iterator<Item = Result<Packet>>> {
    source: Peekable<I>,
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for SignatureParser<I> {
    type Item = Result<DetachedSignature>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

fn next<I: Iterator<Item = Result<Packet>>>(
    packets: &mut Peekable<I>,
) -> Option<Result<DetachedSignature>> {
    match packets.by_ref().next() {
        Some(Ok(packet)) => match packet.tag() {
            Tag::Signature => Some(packet.try_into().map(DetachedSignature::new)),
            _ => Some(Err(format_err!("unexpected packet {:?}", packet.tag()))),
        },
        Some(Err(e)) => Some(Err(e)),
        None => None,
    }
}
