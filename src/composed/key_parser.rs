use std::iter::Peekable;

use try_from::TryInto;

use composed::key::{PrivateKey, PrivateSubKey, PublicKey, PublicSubKey};
use composed::Deserializable;
use errors::Result;
use packet::{self, Packet, Signature, SignatureType, UserAttribute, UserId};
use types::{KeyVersion, SignedUser, SignedUserAttribute, Tag};

macro_rules! err_opt {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => return Some(Err(err)),
        }
    };
}

/// This macro generates the parsers matching to the two different types of keys,
/// public and private.
macro_rules! key_parser {
    ( $key_type:ty, $key_type_parser: ident, $key_tag:expr, $inner_key_type:ty, $( ($subkey_tag:ident, $inner_subkey_type:ty, $subkey_type:ty, $subkey_container:ident) ),* ) => {
        /// Parse a transferable keys from the given packets.
        /// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
        pub struct $key_type_parser<I: Sized + Iterator<Item = Packet>> {
            inner: Peekable<I>,
        }

        impl<I: Sized + Iterator<Item = Packet>> Iterator for $key_type_parser<I> {
            type Item = Result<$key_type>;

            fn next(&mut self) -> Option<Self::Item> {
                let packets = self.inner.by_ref();

                // -- One Public-Key packet
                // idea: use Error::UnexpectedPacket(actual, expected)
                match packets.peek() {
                    Some(p) => {
                        if p.tag() != $key_tag {
                            return Some(Err(format_err!("unexpected packet: expected {:?}, got {:?}", $key_tag, p.tag())));
                        }
                    }
                    None => return None
                }

                let next = packets.next().expect("peeked");
                info!("  primary key: {:?}", next);
                let primary_key: $inner_key_type = err_opt!(next.try_into());

                // -- Zero or more revocation signatures
                // -- followed by zero or more direct signatures in V4 keys
                info!("  signatures");
                let mut revocation_signatures = Vec::new();
                let mut direct_signatures = Vec::new();

                while let Some(true) = packets.peek().map(|packet| packet.tag() == Tag::Signature) {
                    let packet = packets.next().expect("peeked");
                    info!("parsing signature {:?}", packet.tag());
                    let sig: Signature = err_opt!(packet.try_into());
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
                            let id: UserId = err_opt!(packet.try_into());
                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let mut sigs = Vec::new();
                            while let Some(true) =
                                packets.peek().map(|packet| packet.tag() == Tag::Signature)
                            {
                                let packet = packets.next().expect("peeked");
                                sigs.push(err_opt!(packet.try_into()));
                            }

                            users.push(SignedUser::new(id, sigs));
                        }
                        Tag::UserAttribute => {
                            let attr: UserAttribute = err_opt!(packet.try_into());

                            // --- zero or more signature packets

                            // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                            let mut sigs = Vec::new();
                            while let Some(true) =
                                packets.peek().map(|packet| packet.tag() == Tag::Signature)
                            {
                                let packet = packets.next().expect("peeked");
                                sigs.push(err_opt!(packet.try_into()));
                            }

                            user_attributes.push(SignedUserAttribute::new(attr, sigs));
                        }
                        _ => break,
                    }
                }

                if users.is_empty() {
                    return Some(Err(format_err!("missing user ids")));
                }

                // -- Zero or more Subkey packets
                $(
                    let mut $subkey_container = vec![];
                )*

                info!("  subkeys");

                while let Some(true) = packets.peek().map(|packet| {
                    $( packet.tag() == Tag::$subkey_tag || )* false
                })
                {
                    // -- Only V4 keys should have sub keys
                    if primary_key.version() != &KeyVersion::V4 {
                        return Some(Err(format_err!("only V4 keys can have subkeys")));
                    }

                    let packet = packets.next().expect("peeked");
                    match packet.tag() {
                        $(
                            Tag::$subkey_tag => {
                                let subkey: $inner_subkey_type = err_opt!(packet.try_into());
                                let mut sigs = Vec::new();
                                while let Some(true) =
                                    packets.peek().map(|packet| packet.tag() == Tag::Signature)
                                {
                                    let packet = packets.next().expect("peeked");
                                    sigs.push(err_opt!(packet.try_into()));
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

                Some(Ok(<$key_type>::new(
                    primary_key,
                    revocation_signatures,
                    direct_signatures,
                    users,
                    user_attributes,
                    $( $subkey_container, )*
                )))
            }
        }

        impl Deserializable for $key_type {
            /// Parse a transferable key from packets.
            /// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
            fn from_packets<'a>(
                packets: impl Iterator<Item = Packet> + 'a,
            ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
                Box::new($key_type_parser {
                    inner: packets.peekable(),
                })
            }
        }
    };
}

key_parser!(
    PrivateKey,
    PrivateKeyParser,
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
    PublicKeyParser,
    Tag::PublicKey,
    packet::PublicKey,
    (
        PublicSubkey,
        packet::PublicSubkey,
        PublicSubKey,
        public_subkeys
    )
);
