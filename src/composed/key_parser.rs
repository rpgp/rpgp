use std::iter::IntoIterator;

use itertools::Itertools;
use try_from::TryInto;

use composed::key::{PrivateKey, PrivateSubKey, PublicKey, PublicSubKey};
use composed::Deserializable;
use errors::Result;
use packet::{self, Packet, Signature, SignatureType, UserAttribute, UserId};
use types::{KeyVersion, SignedUser, SignedUserAttribute, Tag};

/// This macro generates the parsers matching to the two different types of keys,
/// public and private.
macro_rules! key_parser {
    ( $key_type:ty, $subkey_type:ty, $key_tag:expr, $subkey_tag:expr, $inner_key_type:ty, $inner_subkey_type:ty ) => {
        impl Deserializable for $key_type {
            /// Parse a transferable key from packets.
            /// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
            fn from_packets(packets: impl IntoIterator<Item = Packet>) -> Result<Vec<$key_type>> {
                // This counter tracks which top level key we are in.
                let mut ctr = 0;

                packets
                    .into_iter()
                    .group_by(|packet| {
                        if packet.tag() == $key_tag {
                            ctr += 1;
                        }

                        ctr
                    })
                    .into_iter()
                    .map(|(_, packets)| Self::from_packets_single(packets))
                    // TODO: better error handling
                    .filter(|v| v.is_ok())
                    .collect()
            }
        }

        impl $key_type {
            /// Parse a single transferable key from packets.
            /// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
            /// Currently skips packets it fails to parse.
            fn from_packets_single(packets: impl IntoIterator<Item = Packet>) -> Result<$key_type> {
                let mut packets = packets.into_iter();

                // -- One Public-Key packet
                // idea: use Error::UnexpectedPacket(actual, expected)
                let primary_key: $inner_key_type = packets
                    .next()
                    .ok_or_else(|| format_err!("missing primary key"))?
                    .try_into()?;

                // -- Zero or more revocation signatures
                // -- followed by zero or more direct signatures in V4 keys

                let mut revocation_signatures = Vec::new();
                let mut direct_signatures = Vec::new();

                while let Some(packet) = packets.next() {
                    if packet.tag() == Tag::Signature {
                        let sig: Signature = packet.try_into()?;
                        let typ = sig.typ();

                        if typ == SignatureType::KeyRevocation {
                            revocation_signatures.push(sig);
                        } else {
                            if primary_key.version() != &KeyVersion::V4 {
                                // no direct signatures on V2|V3 keys
                                info!("WARNING: unexpected signature: {:?}", typ);
                            }
                            direct_signatures.push(sig);
                        }
                    } else {
                        break;
                    }
                }

                // -- Zero or more User ID packets
                // -- Zero or more User Attribute packets

                let mut users = Vec::new();
                let mut user_attributes = Vec::new();

                while let Some(packet) = packets.next() {
                    let tag = packet.tag();
                    match tag {
                        Tag::UserId => {
                            let id: UserId = packet.try_into()?;
                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let mut sigs = Vec::new();
                            while let Some(packet) = packets.next() {
                                if packet.tag() == Tag::Signature {
                                    sigs.push(packet.try_into()?);
                                } else {
                                    break;
                                }
                            }

                            users.push(SignedUser::new(id, sigs));
                        }
                        Tag::UserAttribute => {
                            let attr: UserAttribute = packet.try_into()?;

                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let mut sigs = Vec::new();
                            while let Some(packet) = packets.next() {
                                if packet.tag() == Tag::Signature {
                                    sigs.push(packet.try_into()?);
                                } else {
                                    break;
                                }
                            }

                            user_attributes.push(SignedUserAttribute::new(attr, sigs));
                        }
                        _ => break,
                    }
                }

                // -- Zero or more Subkey packets
                let mut subkeys = vec![];

                if let Some(packet) = packets.next() {
                    // -- Only V4 keys should have sub keys
                    if primary_key.version() != &KeyVersion::V4 {
                        bail!("only V4 keys can have subkeys");
                    }

                    // Process the element we just pulled out
                    {
                        let subkey: $inner_subkey_type = packet.try_into()?;

                        let mut sigs = Vec::new();
                        while let Some(packet) = packets.next() {
                            if packet.tag() == Tag::Signature {
                                sigs.push(packet.try_into()?);
                            } else {
                                break;
                            }
                        }

                        // TODO: better error handling
                        if sigs.is_empty() {
                            info!("WARNING: missing signature");
                        }

                        subkeys.push(<$subkey_type>::new(subkey, sigs));
                    }

                    while let Some(packet) = packets.next() {
                        if packet.tag() != $subkey_tag {
                            break;
                        }

                        let subkey: $inner_subkey_type = packet.try_into()?;
                        let mut sigs = Vec::new();
                        while let Some(packet) = packets.next() {
                            if packet.tag() == Tag::Signature {
                                sigs.push(packet.try_into()?);
                            } else {
                                break;
                            }
                        }

                        // TODO: better error handling
                        if sigs.is_empty() {
                            info!("WARNING: missing signature");
                        }

                        subkeys.push(<$subkey_type>::new(subkey, sigs));
                    }
                    ensure!(packets.next().is_none(), "failed to process all packets");
                }

                ensure!(!users.is_empty(), "missing user ids");

                Ok(<$key_type>::new(
                    primary_key,
                    revocation_signatures,
                    direct_signatures,
                    users,
                    user_attributes,
                    subkeys,
                ))
            }
        }
    };
}

key_parser!(
    PrivateKey,
    PrivateSubKey,
    Tag::SecretKey,
    Tag::SecretSubkey,
    packet::SecretKey,
    packet::SecretSubkey
);
key_parser!(
    PublicKey,
    PublicSubKey,
    Tag::PublicKey,
    Tag::PublicSubkey,
    packet::PublicKey,
    packet::PublicSubkey
);
