use std::iter::IntoIterator;

use itertools::Itertools;
use nom::Err::Incomplete;
use nom::Needed;
use try_from::TryFrom;

use composed::key::{PrivateKey, PrivateSubKey, PublicKey, PublicSubKey};
use composed::Deserializable;
use errors::{Error, Result};
use packet::{self, Packet, Signature, SignatureType, UserAttribute, UserId};
use types::{KeyVersion, SignedUser, Tag};

/// Take as many consecutive signatures as we can find and try to parse them.
/// Skips the ones that are not parsed, but they are reflected in the `processed` count that is returned.
fn take_sigs(packets: &[Packet]) -> Result<(usize, Vec<Signature>)> {
    let mut processed = 0;

    let sigs: Vec<Signature> = packets
        .into_iter()
        .take_while(|packet| packet.tag == Tag::Signature)
        .map(|packet| packet.try_into())
        .collect::<Result<_>>()?;

    Ok((processed, sigs))
}

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
                        if packet.tag == $key_tag {
                            ctr += 1;
                        }

                        ctr
                    })
                    .into_iter()
                    .map(|(_, packets)| Self::from_packets_single(&packets.collect::<Vec<_>>()))
                    // TODO: better error handling
                    .filter(|v| v.is_ok())
                    .collect()
            }
        }

        impl $key_type {
            /// Parse a single transferable key from packets.
            /// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
            /// Currently skips packets it fails to parse.
            fn from_packets_single(packets: &[Packet]) -> Result<$key_type> {
                let mut ctr = 0;
                let packets_len = packets.len();

                // -- One Public-Key packet
                // idea: use Error::UnexpectedPacket(actual, expected)
                ensure_eq!(packets[ctr].tag, $key_tag);

                let primary_key: $inner_key_type = packets[ctr].try_into()?;
                ctr += 1;

                let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                ctr += cnt;

                // -- Zero or more revocation signatures
                // -- followed by zero or more direct signatures in V4 keys

                let mut grouped_sigs: Vec<_> = sigs
                    .into_iter()
                    .group_by(|sig| sig.typ.clone())
                    .into_iter()
                    .map(|(typ, sigs)| {
                        match typ {
                            SignatureType::KeyRevocation => sigs.collect(),
                            _ => {
                                if primary_key.version() != &KeyVersion::V4 {
                                    // no direct signatures on V2|V3 keys
                                    info!("WARNING: unexpected signature: {:?}", typ);
                                }
                                sigs.collect()
                            }
                        }
                    })
                    .collect();

                let revocation_signatures = grouped_sigs.pop().unwrap_or_else(Vec::new);
                let direct_signatures = grouped_sigs.pop().unwrap_or_else(Vec::new);

                // -- Zero or more User ID packets
                // -- Zero or more User Attribute packets

                let mut users = vec![];
                let mut user_attributes = vec![];

                while ctr < packets_len {
                    let tag = packets[ctr].tag();
                    match tag {
                        Tag::UserID => {
                            let id: UserId = packets[ctr].try_into()?;
                            ctr += 1;

                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                            ctr += cnt;

                            users.push(SignedUser::new(id, sigs));
                        }
                        Tag::UserAttribute => {
                            let attr: UserAttribute = packets[ctr].try_into()?;
                            ctr += 1;

                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                            ctr += cnt;

                            user_attributes.push(SignedUser::new(attr, sigs));
                        }
                        _ => break,
                    }
                }

                // -- Only V4 keys should have sub keys

                if ctr != packets_len && primary_key.version() != &KeyVersion::V4 {
                    bail!("only V4 keys can have subkeys");
                }

                // -- Zero or more Subkey packets
                let mut subkeys = vec![];
                while ctr < packets_len && packets[ctr].tag == $subkey_tag {
                    let subkey: $inner_subkey_type = packets[ctr].try_into()?;
                    ctr += 1;

                    let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                    ctr += cnt;

                    // TODO: better error handling
                    if sigs.is_empty() {
                        info!("WARNING: missing signature");
                    }

                    subkeys.push(<$subkey_type>::new(subkey, sigs));
                }

                ensure!(!users.is_empty(), "missing user ids");

                ensure_eq!(ctr, packets_len, "failed to process all packets");

                Ok(<$key_type>::new(
                    primary_key,
                    revocation_signatures,
                    direct_signatures,
                    users,
                    user_attributes,
                    subkeys,
                ))
            }

            fn key_parser(packet: &Packet) -> Result<$inner_key_type> {
                let (_, key) = Self::key_packet_parser(packet.body.as_slice()).map_err(|err| {
                    info!("WARNING: failed to parse key {:?}", err);
                    match err {
                        Incomplete(n) => {
                            // a size larger than the packet was requested, always invalid
                            if let Needed::Size(size) = n {
                                if size > packet.body.len() {
                                    Error::RequestedSizeTooLarge
                                } else {
                                    err.into()
                                }
                            } else {
                                err.into()
                            }
                        }
                        _ => err.into(),
                    }
                })?;

                Ok(key)
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
