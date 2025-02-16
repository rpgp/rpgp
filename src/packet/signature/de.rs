use std::str;

use bytes::{Buf, Bytes};
use chrono::{DateTime, Duration, TimeZone, Utc};
use log::{debug, warn};
use smallvec::SmallVec;

use crate::crypto::aead::AeadAlgorithm;
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::crypto::sym::SymmetricKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{
    Notation, PacketHeader, RevocationCode, Subpacket, SubpacketData, SubpacketLength,
    SubpacketType,
};
use crate::parsing::BufParsing;
use crate::types::{
    CompressionAlgorithm, Fingerprint, KeyId, KeyVersion, MpiBytes, PacketHeaderVersion,
    PacketLength, RevocationKey, SignatureBytes, Tag,
};

use super::{Signature, SignatureType, SignatureVersion};

impl Signature {
    /// Parses a `Signature` packet from the given buffer
    ///
    /// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-packet-type-id-2>
    pub fn from_buf<B: Buf>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        let version = i.read_u8().map(SignatureVersion::from)?;

        let signature = match version {
            SignatureVersion::V2 | SignatureVersion::V3 => v3_parser(packet_header, version, i)?,
            SignatureVersion::V4 | SignatureVersion::V5 => v4_parser(packet_header, version, i)?,
            SignatureVersion::V6 => v6_parser(packet_header, i)?,
            _ => unsupported_err!("signature version {:?}", version),
        };

        Ok(signature)
    }
}

/// Parse a v2 or v3 signature packet
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-version-3-signature-packet-
fn v3_parser<B: Buf>(
    packet_header: PacketHeader,
    version: SignatureVersion,
    mut i: B,
) -> Result<Signature> {
    // One-octet length of following hashed material. MUST be 5.
    i.read_tag(&[5])?;
    // One-octet signature type.
    let typ = i.read_u8().map(SignatureType::from)?;
    // Four-octet creation time.
    let created = i
        .read_be_u32()
        .map(|v| Utc.timestamp_opt(i64::from(v), 0).single())?
        .ok_or_else(|| format_err!("invalid creation time"))?;
    // Eight-octet Key ID of signer.
    let issuer = i.read_array::<8>().map(KeyId::from)?;
    // One-octet public-key algorithm.
    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    // One-octet hash algorithm.
    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
    // Two-octet field holding left 16 bits of signed hash value.
    let ls_hash = i.read_array::<2>()?;

    // The SignatureBytes comprising the signature.
    let sig = actual_signature(&pub_alg, &mut i)?;

    match version {
        SignatureVersion::V2 => Ok(Signature::v2(
            packet_header,
            typ,
            pub_alg,
            hash_alg,
            created,
            issuer,
            ls_hash,
            sig,
        )),
        SignatureVersion::V3 => Ok(Signature::v3(
            packet_header,
            typ,
            pub_alg,
            hash_alg,
            created,
            issuer,
            ls_hash,
            sig,
        )),
        _ => unreachable!("must only be called for V2/V3"),
    }
}

/// Parse a v4 signature packet
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-versions-4-and-6-signature-
fn v4_parser<B: Buf>(
    packet_header: PacketHeader,
    version: SignatureVersion,
    mut i: B,
) -> Result<Signature> {
    debug_assert_eq!(version, SignatureVersion::V4);

    // One-octet signature type.
    let typ = i.read_u8().map(SignatureType::from)?;
    // One-octet public-key algorithm.
    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    // One-octet hash algorithm.
    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

    // Two-octet scalar octet count for following hashed subpacket data.
    // Hashed subpacket data set (zero or more subpackets).
    let hsub_len: usize = i.read_be_u16()?.into();
    let hsub_raw = i.read_take(hsub_len)?;
    let hsub = subpackets(packet_header.version(), hsub_raw)?;
    debug!(
        "found {} hashed subpackets in {} bytes",
        hsub.len(),
        hsub_len
    );

    // Two-octet scalar octet count for the following unhashed subpacket data.
    // Unhashed subpacket data set (zero or more subpackets).
    let usub_len: usize = i.read_be_u16()?.into();
    let usub_raw = i.read_take(usub_len)?;
    let usub = subpackets(packet_header.version(), usub_raw)?;
    debug!(
        "found {} unhashed subpackets in {} bytes",
        usub.len(),
        usub_len
    );
    // Two-octet field holding the left 16 bits of the signed hash value.
    let ls_hash = i.read_array::<2>()?;

    // The SignatureBytes comprising the signature.
    let sig = actual_signature(&pub_alg, i)?;

    Ok(Signature::v4(
        packet_header,
        typ,
        pub_alg,
        hash_alg,
        ls_hash,
        sig,
        hsub,
        usub,
    ))
}

/// Parse a v6 signature packet
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-versions-4-and-6-signature-
fn v6_parser<B: Buf>(packet_header: PacketHeader, mut i: B) -> Result<Signature> {
    // One-octet signature type.
    let typ = i.read_u8().map(SignatureType::from)?;
    // One-octet public-key algorithm.
    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    // One-octet hash algorithm.
    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

    // Four-octet scalar octet count for following hashed subpacket data.
    // Hashed subpacket data set (zero or more subpackets).
    let hsub_len: usize = i.read_be_u32()?.try_into()?;
    let hsub_raw = i.read_take(hsub_len)?;
    let hsub = subpackets(packet_header.version(), hsub_raw)?;
    debug!(
        "found {} hashed subpackets in {} bytes",
        hsub.len(),
        hsub_len
    );

    // Four-octet scalar octet count for the following unhashed subpacket data.
    // Unhashed subpacket data set (zero or more subpackets).
    let usub_len: usize = i.read_be_u32()?.try_into()?;
    let usub_raw = i.read_take(usub_len)?;
    let usub = subpackets(packet_header.version(), usub_raw)?;
    debug!(
        "found {} unhashed subpackets in {} bytes",
        usub.len(),
        usub_len
    );

    // Two-octet field holding the left 16 bits of the signed hash value.
    let ls_hash = i.read_array::<2>()?;

    // A variable-length field containing:
    // A one-octet salt size. The value MUST match the value defined for the hash algorithm as specified in Table 23.
    // The salt; a random value of the specified size.
    let salt_len = i.read_u8()?;
    let salt = i.read_take(salt_len.into())?;

    if hash_alg.salt_len() != Some(salt.len()) {
        bail!(
            "Illegal salt length {} found for {:?}",
            salt.len(),
            hash_alg
        );
    }

    // The SignatureBytes comprising the signature.
    let sig = actual_signature(&pub_alg, i)?;
    Ok(Signature::v6(
        packet_header,
        typ,
        pub_alg,
        hash_alg,
        ls_hash,
        sig,
        hsub,
        usub,
        salt.to_vec(),
    ))
}

fn subpackets<B: Buf>(packet_version: PacketHeaderVersion, mut i: B) -> Result<Vec<Subpacket>> {
    let mut packets = Vec::new();
    while i.has_remaining() {
        // the subpacket length (1, 2, or 5 octets)
        let packet_len = SubpacketLength::from_buf(&mut i)?;
        ensure!(!packet_len.is_empty(), "empty subpacket is not allowed");
        // the subpacket type (1 octet)
        let (typ, is_critical) = i.read_u8().map(SubpacketType::from_u8)?;
        let len = packet_len.len() - 1;
        debug!(
            "reading subpacket {:?}: critical? {}, len: {}",
            typ, is_critical, len
        );

        let mut body = i.read_take(len)?;
        let packet = subpacket(typ, is_critical, packet_len, packet_version, &mut body)?;
        if !body.is_empty() {
            warn!("failed to fully process subpacket: {:?}", typ);
            if is_critical {
                bail!("invalid subpacket: {:?}", typ);
            }
        }
        packets.push(packet);
    }
    Ok(packets)
}

fn subpacket<B: Buf>(
    typ: SubpacketType,
    is_critical: bool,
    packet_len: SubpacketLength,
    packet_version: PacketHeaderVersion,
    mut body: B,
) -> Result<Subpacket> {
    use super::subpacket::SubpacketType::*;

    debug!("parsing subpacket: {:?}", typ);

    let res = match typ {
        SignatureCreationTime => signature_creation_time(body),
        SignatureExpirationTime => signature_expiration_time(body),
        ExportableCertification => exportable_certification(body),
        TrustSignature => trust_signature(body),
        RegularExpression => regular_expression(body),
        Revocable => revocable(body),
        KeyExpirationTime => key_expiration(body),
        PreferredSymmetricAlgorithms => pref_sym_alg(body),
        RevocationKey => revocation_key(body),
        Issuer => issuer(body),
        Notation => notation_data(body),
        PreferredHashAlgorithms => pref_hash_alg(body),
        PreferredCompressionAlgorithms => pref_com_alg(body),
        KeyServerPreferences => key_server_prefs(body),
        PreferredKeyServer => preferred_key_server(body),
        PrimaryUserId => primary_userid(body),
        PolicyURI => policy_uri(body),
        KeyFlags => key_flags(body),
        SignersUserID => signers_userid(body),
        RevocationReason => rev_reason(body),
        Features => features(body),
        SignatureTarget => sig_target(body),
        EmbeddedSignature => embedded_sig(packet_version, body),
        IssuerFingerprint => issuer_fingerprint(body),
        PreferredEncryptionModes => preferred_encryption_modes(body),
        IntendedRecipientFingerprint => intended_recipient_fingerprint(body),
        PreferredAead => pref_aead_alg(body),
        Experimental(n) => Ok(SubpacketData::Experimental(n, body.rest())),
        Other(n) => Ok(SubpacketData::Other(n, body.rest())),
    };

    let res = res.map(|data| Subpacket {
        is_critical,
        data,
        len: packet_len,
    });

    if res.is_err() {
        warn!("invalid subpacket: {:?} {:?}", typ, res);
    }

    res
}

fn actual_signature<B: Buf>(typ: &PublicKeyAlgorithm, mut i: B) -> Result<SignatureBytes> {
    match typ {
        PublicKeyAlgorithm::RSA | &PublicKeyAlgorithm::RSASign => {
            let v = MpiBytes::from_buf(&mut i)?;
            Ok(SignatureBytes::Mpis(vec![v.to_owned()]))
        }
        PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::ECDSA | &PublicKeyAlgorithm::EdDSALegacy => {
            let a = MpiBytes::from_buf(&mut i)?;
            let b = MpiBytes::from_buf(&mut i)?;

            Ok(SignatureBytes::Mpis(vec![a.to_owned(), b.to_owned()]))
        }

        &PublicKeyAlgorithm::Ed25519 => {
            let sig = i.read_take(64)?;
            Ok(SignatureBytes::Native(sig))
        }

        &PublicKeyAlgorithm::Private100
        | &PublicKeyAlgorithm::Private101
        | &PublicKeyAlgorithm::Private102
        | &PublicKeyAlgorithm::Private103
        | &PublicKeyAlgorithm::Private104
        | &PublicKeyAlgorithm::Private105
        | &PublicKeyAlgorithm::Private106
        | &PublicKeyAlgorithm::Private107
        | &PublicKeyAlgorithm::Private108
        | &PublicKeyAlgorithm::Private109
        | &PublicKeyAlgorithm::Private110 => {
            let v = MpiBytes::from_buf(&mut i)?;
            Ok(SignatureBytes::Mpis(vec![v.to_owned()]))
        }
        _ => {
            // don't assume format, could be non-MPI
            Ok(SignatureBytes::Native(Bytes::new()))
        }
    }
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::from(ts), 0)
}

/// Convert a u32 to a `Duration`
fn duration_from_timestamp(ts: u32) -> Option<Duration> {
    Duration::try_seconds(i64::from(ts))
}

/// Parse a Signature Creation Time subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-creation-time
fn signature_creation_time<B: Buf>(mut i: B) -> Result<SubpacketData> {
    // 4-octet time field
    let date = i.read_be_u32()?;
    let created = dt_from_timestamp(date).ok_or_else(|| format_err!("invalid creation time"))?;

    Ok(SubpacketData::SignatureCreationTime(created))
}

/// Parse an Issuer Key ID subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-key-id
fn issuer<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let key_id = i.read_array::<8>().map(KeyId::from)?;

    Ok(SubpacketData::Issuer(key_id))
}

/// Parse a Key Expiration Time subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time
fn key_expiration<B: Buf>(mut i: B) -> Result<SubpacketData> {
    // 4-octet time field
    let duration = i.read_be_u32()?;
    let duration =
        duration_from_timestamp(duration).ok_or_else(|| format_err!("invalid expiration time"))?;

    Ok(SubpacketData::KeyExpirationTime(duration))
}

/// Parse a Preferred Symmetric Ciphers for v1 SEIPD subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#preferred-v1-seipd
fn pref_sym_alg<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[SymmetricKeyAlgorithm; 8]>::new();
    while i.has_remaining() {
        let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredSymmetricAlgorithms(list))
}

/// Parse a Preferred AEAD Ciphersuites subpacket (for SEIPD v2)
///
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites
fn pref_aead_alg<B: Buf>(mut i: B) -> Result<SubpacketData> {
    ensure!(
        i.remaining() % 2 == 0,
        "Illegal preferred aead subpacket len {} must be a multiple of 2",
        i.remaining()
    );

    let mut list = SmallVec::<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>::new();
    while i.has_remaining() {
        let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
        let aead = i.read_u8().map(AeadAlgorithm::from)?;
        list.push((alg, aead));
    }

    Ok(SubpacketData::PreferredAeadAlgorithms(list))
}

/// Parse a Preferred Hash Algorithms subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-hash-algorithms
fn pref_hash_alg<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[HashAlgorithm; 8]>::new();
    while i.has_remaining() {
        let alg = i.read_u8().map(HashAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredHashAlgorithms(list))
}

/// Parse a Preferred Compression Algorithms subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-compression-algor
fn pref_com_alg<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[CompressionAlgorithm; 8]>::new();
    while i.has_remaining() {
        let alg = i.read_u8().map(CompressionAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredCompressionAlgorithms(list))
}

/// Parse a Signature Expiration Time subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-expiration-time
fn signature_expiration_time<B: Buf>(mut i: B) -> Result<SubpacketData> {
    // 4-octet time field
    let duration = i.read_be_u32()?;
    let duration =
        duration_from_timestamp(duration).ok_or_else(|| format_err!("invalid expiration time"))?;

    Ok(SubpacketData::SignatureExpirationTime(duration))
}

/// Parse an Exportable Certification subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-exportable-certification
fn exportable_certification<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let is_exportable = i.read_u8()? == 1;

    Ok(SubpacketData::ExportableCertification(is_exportable))
}

/// Parse a Revocable subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocable
fn revocable<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let is_revocable = i.read_u8()? == 1;

    Ok(SubpacketData::Revocable(is_revocable))
}

/// Parse a Trust Signature subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-trust-signature
fn trust_signature<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let depth = i.read_u8()?;
    let value = i.read_u8()?;

    Ok(SubpacketData::TrustSignature(depth, value))
}

/// Parse a Regular Expression subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-regular-expression
fn regular_expression<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let regex = i.rest();

    Ok(SubpacketData::RegularExpression(regex))
}

/// Parse a Revocation Key subpacket (Deprecated)
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key-deprecated
fn revocation_key<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let class = i
        .read_u8()?
        .try_into()
        .map_err(|e| format_err!("invalid revocation class: {:?}", e))?;
    let algorithm = i.read_u8().map(PublicKeyAlgorithm::from)?;
    // TODO: V5 Keys have 32 octets here
    let fp = i.read_array::<20>()?;
    let key = RevocationKey::new(class, algorithm, &fp);

    Ok(SubpacketData::RevocationKey(key))
}

/// Parse a Notation Data subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-notation-data
fn notation_data<B: Buf>(mut i: B) -> Result<SubpacketData> {
    // Flags
    let readable = i.read_u8().map(|v| v == 0x80)?;
    i.read_tag(&[0, 0, 0])?;
    let name_len = i.read_be_u16()?;
    let value_len = i.read_be_u16()?;
    let name = i.read_take(name_len.into())?;
    let value = i.read_take(value_len.into())?;

    Ok(SubpacketData::Notation(Notation {
        readable,
        name,
        value,
    }))
}

/// Parse a Key Server Preferences subpacket
/// https://www.rfc-editor.org/rfc/rfc9580.html#name-key-server-preferences
fn key_server_prefs<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let prefs = SmallVec::from_slice(&i.rest());

    Ok(SubpacketData::KeyServerPreferences(prefs))
}

/// Parse a Preferred Key Server subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-key-server
fn preferred_key_server<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let body = i.rest();
    let body_str = str::from_utf8(&body)?;

    Ok(SubpacketData::PreferredKeyServer(body_str.to_string()))
}

/// Parse a Primary User ID subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-primary-user-id
fn primary_userid<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let is_primary = i.read_u8()? == 1;

    Ok(SubpacketData::IsPrimary(is_primary))
}

/// Parse a Policy URI subpacket.
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-policy-uri
fn policy_uri<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let body = i.rest();
    let body_str = str::from_utf8(&body)?;

    Ok(SubpacketData::PolicyURI(body_str.to_string()))
}

/// Parse a Key Flags subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags
fn key_flags<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let flags = SmallVec::from_slice(&i.rest());

    Ok(SubpacketData::KeyFlags(flags))
}

/// Parse a Signer's User ID subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags
fn signers_userid<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let userid = i.rest();

    Ok(SubpacketData::SignersUserID(userid))
}

/// Parse a Reason for Revocation subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-key-flags
fn rev_reason<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let code = i.read_u8().map(RevocationCode::from)?;
    let reason = i.rest();

    Ok(SubpacketData::RevocationReason(code, reason))
}

/// Parse a Features subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-features
fn features<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let features = SmallVec::from_slice(&i.rest());

    Ok(SubpacketData::Features(features))
}

/// Parse a Signature Target subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-target
fn sig_target<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let pub_alg = i.read_u8().map(PublicKeyAlgorithm::from)?;
    let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
    let hash = i.rest();

    Ok(SubpacketData::SignatureTarget(pub_alg, hash_alg, hash))
}

/// Parse an Embedded Signature subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-embedded-signature
fn embedded_sig<B: Buf>(packet_version: PacketHeaderVersion, mut i: B) -> Result<SubpacketData> {
    // copy to bytes, to avoid recursive type explosion
    let signature_bytes = i.rest();
    let header = PacketHeader::from_parts(
        packet_version,
        Tag::Signature,
        PacketLength::Fixed(signature_bytes.len()),
    )?;
    let sig = Signature::from_buf(header, signature_bytes)?;

    Ok(SubpacketData::EmbeddedSignature(Box::new(sig)))
}

/// Parse an Issuer Fingerprint subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-fingerprint
fn issuer_fingerprint<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let version = i.read_u8().map(KeyVersion::from)?;

    // This subpacket is only used for v4 and newer fingerprints
    if version != KeyVersion::V4 && version != KeyVersion::V5 && version != KeyVersion::V6 {
        unsupported_err!("invalid key version {version:?}");
    }

    if let Some(fingerprint_len) = version.fingerprint_len() {
        let fingerprint = i.read_take(fingerprint_len)?;
        let fp = Fingerprint::new(version, &fingerprint)?;

        return Ok(SubpacketData::IssuerFingerprint(fp));
    }
    unsupported_err!("invalid key version {version:?}");
}

/// Parse a preferred encryption modes subpacket (non-RFC subpacket for GnuPG "OCB" mode)
fn preferred_encryption_modes<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let mut list = SmallVec::<[AeadAlgorithm; 2]>::new();
    while i.has_remaining() {
        let alg = i.read_u8().map(AeadAlgorithm::from)?;
        list.push(alg);
    }

    Ok(SubpacketData::PreferredEncryptionModes(list))
}

/// Parse an Intended Recipient Fingerprint subpacket
/// Ref: https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr
fn intended_recipient_fingerprint<B: Buf>(mut i: B) -> Result<SubpacketData> {
    let version = i.read_u8().map(KeyVersion::from)?;

    // This subpacket is only used for v4 and newer fingerprints
    if version != KeyVersion::V4 && version != KeyVersion::V5 && version != KeyVersion::V6 {
        unsupported_err!("invalid key version {version:?}");
    }

    if let Some(fingerprint_len) = version.fingerprint_len() {
        let fingerprint = i.read_take(fingerprint_len)?;
        let fp = Fingerprint::new(version, &fingerprint)?;

        return Ok(SubpacketData::IntendedRecipientFingerprint(fp));
    }
    unsupported_err!("invalid key version {version:?}");
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{Deserializable, StandaloneSignature};

    #[test]
    fn test_subpacket_pref_sym_alg() {
        let input = vec![9, 8, 7, 3, 2];
        let res = pref_sym_alg(input.as_slice()).unwrap();
        assert_eq!(
            res,
            SubpacketData::PreferredSymmetricAlgorithms(
                input
                    .iter()
                    .map(|i| SymmetricKeyAlgorithm::from(*i))
                    .collect()
            )
        );
    }

    #[test]
    fn test_unknown_revocation_code() {
        let revocation = "-----BEGIN PGP SIGNATURE-----

wsASBCAWCgCEBYJlrwiYCRACvMqAWdPpHUcUAAAAAAAeACBzYWx0QG5vdGF0aW9u
cy5zZXF1b2lhLXBncC5vcmfPfjVZJ9PXSt4854s05WU+Tj5QZwuhA5+LEHEUborP
PxQdQnJldm9jYXRpb24gbWVzc2FnZRYhBKfuT6/w5BLl1XTGUgK8yoBZ0+kdAABi
lQEAkpvZ3A2RGtRdCne/dOZtqoX7oCCZKCPyfZS9I9roc5oBAOj4aklEBejYuTKF
SW+kj0jFDKC2xb/o8hbkTpwPtsoI
=0ajX
-----END PGP SIGNATURE-----";

        let (sig, _) = StandaloneSignature::from_armor_single(revocation.as_bytes()).unwrap();

        let rc = sig.signature.revocation_reason_code();

        assert!(rc.is_some());
        assert!(matches!(rc.unwrap(), RevocationCode::Other(0x42)));
    }
}
