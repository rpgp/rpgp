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
    ( $key_type:ty, $key_tag:expr, $inner_key_type:ty, $( ($subkey_tag:ident, $inner_subkey_type:ty, $subkey_type:ty, $subkey_container:ident) ),* ) => {
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
                    .filter(|packet| packet.is_ok())
                    .collect::<Result<_>>()
            }
        }

        impl $key_type {
            /// Parse a single transferable key from packets.
            /// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
            /// Currently skips packets it fails to parse.
            fn from_packets_single(packets: impl IntoIterator<Item = Packet>) -> Result<$key_type> {
                info!("parsing key");
                let mut packets = packets.into_iter().peekable();

                // -- One Public-Key packet
                // idea: use Error::UnexpectedPacket(actual, expected)
                let next = packets
                    .next()
                    .ok_or_else(|| format_err!("missing primary key"))?;
                info!("  primary key: {:?}", next);
                let primary_key: Result<$inner_key_type> = next.try_into();
                info!("{:?}", primary_key);
                let primary_key = primary_key?;

                // -- Zero or more revocation signatures
                // -- followed by zero or more direct signatures in V4 keys
                info!("  signatures");
                let mut revocation_signatures = Vec::new();
                let mut direct_signatures = Vec::new();

                while let Some(true) = packets.peek().map(|packet| packet.tag() == Tag::Signature) {
                    let packet = packets.next().expect("peeked");
                    info!("parsing signature {:?}", packet.tag());
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
                }

                // -- Zero or more User ID packets
                // -- Zero or more User Attribute packets
                info!("  user");
                let mut users = Vec::new();
                let mut user_attributes = Vec::new();

                while let Some(true) = packets
                    .peek()
                    .map(|packet| packet.tag() == Tag::UserId || packet.tag() == Tag::UserAttribute)
                {
                    let packet = packets.next().expect("peeked");
                    let tag = packet.tag();
                    info!("parsing user data: {:?}", tag);
                    match tag {
                        Tag::UserId => {
                            let id: UserId = packet.try_into()?;
                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let mut sigs = Vec::new();
                            while let Some(true) =
                                packets.peek().map(|packet| packet.tag() == Tag::Signature)
                            {
                                let packet = packets.next().expect("peeked");
                                sigs.push(packet.try_into()?);
                            }

                            users.push(SignedUser::new(id, sigs));
                        }
                        Tag::UserAttribute => {
                            let attr: UserAttribute = packet.try_into()?;

                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let mut sigs = Vec::new();
                            while let Some(true) =
                                packets.peek().map(|packet| packet.tag() == Tag::Signature)
                            {
                                let packet = packets.next().expect("peeked");
                                sigs.push(packet.try_into()?);
                            }

                            user_attributes.push(SignedUserAttribute::new(attr, sigs));
                        }
                        _ => break,
                    }
                }

                ensure!(!users.is_empty(), "missing user ids");

                // -- Zero or more Subkey packets
                $(
                    let mut $subkey_container = vec![];
                )*

                info!("  subkeys");
                if packets.peek().is_some() {
                    // -- Only V4 keys should have sub keys
                    if primary_key.version() != &KeyVersion::V4 {
                        bail!("only V4 keys can have subkeys");
                    }

                    while let Some(true) = packets.peek().map(|packet| {
                        $( packet.tag() == Tag::$subkey_tag || )* false
                    })
                    {
                        let packet = packets.next().expect("peeked");
                        match packet.tag() {
                            $(
                                Tag::$subkey_tag => {
                                    let subkey: $inner_subkey_type = packet.try_into()?;
                                    let mut sigs = Vec::new();
                                    while let Some(true) =
                                        packets.peek().map(|packet| packet.tag() == Tag::Signature)
                                    {
                                        let packet = packets.next().expect("peeked");
                                        sigs.push(packet.try_into()?);
                                    }

                                    // TODO: better error handling
                                    if sigs.is_empty() {
                                        info!("WARNING: missing signature");
                                    }

                                    $subkey_container.push(<$subkey_type>::new(subkey, sigs));
                                }
                            )*
                             _ => unreachable!()
                        }
                    }

                    if packets.peek().is_some() {
                        info!("rest packets");
                        for packet in packets {
                            info!("{:?}", packet);
                        }
                        bail!("failed to process all packets")
                    }
                }

                Ok(<$key_type>::new(
                    primary_key,
                    revocation_signatures,
                    direct_signatures,
                    users,
                    user_attributes,
                    $( $subkey_container, )*
                ))
            }
        }
    };
}

key_parser!(
    PrivateKey,
    Tag::SecretKey,
    packet::SecretKey,
    // secret keys, can contain both public and secret subkeys
    (
        PublicSubkey,
        packet::PublicSubkey,
        PublicSubKey,
        public_subkeys
    ),
    (
        SecretSubkey,
        packet::SecretSubkey,
        PrivateSubKey,
        private_subkeys
    )
);

key_parser!(
    PublicKey,
    Tag::PublicKey,
    packet::PublicKey,
    (
        PublicSubkey,
        packet::PublicSubkey,
        PublicSubKey,
        public_subkeys
    )
);
