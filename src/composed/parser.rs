use composed::key::{PrivateKey, PrivateSubKey, PublicKey, PublicSubKey};
use errors::{Error, Result};
use itertools::Itertools;
use nom::Err::Incomplete;
use nom::Needed;
use packet::tags;
use packet::types::{key, KeyVersion, Packet, Signature, SignatureType, Tag, User, UserAttribute};
use std::iter::IntoIterator;

/// Take as many consecutive signatures as we can find and try to parse them.
/// Skips the ones that are not parsed, but they are reflected in the `processed` count that is returned.
fn take_sigs(packets: &[&Packet]) -> Result<(usize, Vec<Signature>)> {
    let mut processed = 0;

    let sigs: Vec<Signature> = packets
        .iter()
        .take_while(|packet| packet.tag == Tag::Signature)
        .map(|packet| {
            processed += 1;
            tags::sig::parser(packet.body.as_slice()).map(|(_, sig)| sig).map_err(|err| err.into())
        })
        // TODO: better error handling
        .filter(|sig| sig.is_ok())
        .collect::<Result<_>>()?;

    Ok((processed, sigs))
}

/// Parse a single transferable public or private key.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
/// Currently skips packets it fails to parse.
fn single<K>(
    key_tag: Tag,
    subkey_tag: Tag,
    packets: &[&Packet],
    key_parser: fn(&[&Packet]) -> Result<K>,
) -> Result<()> {
    // TODO: actually return errors, don't silently fail (idea, return Result<Vec<Key>> at `parse` level)

    let mut ctr = 0;
    let packets_len = packets.len();

    // -- One Public-Key packet
    // TODO: better error management
    // idea: use Error::UnexpectedPacket(actual, expected)
    assert_eq!(packets[ctr].tag, key_tag);

    let primary_key = key_parser(packets[ctr])?;
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
                        println!("WARNING: unexpected signature: {:?}", typ);
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
    let mut user_attrs = vec![];

    while ctr < packets_len {
        match packets[ctr].tag {
            Tag::UserID => {
                // TODO: better erorr handling
                let id = tags::userid::parser(packets[ctr].body.as_slice());
                ctr += 1;

                // --- zero or more signature packets

                // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                ctr += cnt;

                users.push(User::new(id, sigs));
            }
            Tag::UserAttribute => {
                // TODO: better error handling
                let a = tags::userattr::parser(packets[ctr].body.as_slice());
                if a.is_err() {
                    println!("failed to parse {:?}\n{:?}", packets[ctr], a);
                }

                let (_, attr) = a?;
                ctr += 1;

                // --- zero or more signature packets

                // TODO: validate signature types: https://tools.ietf.org/html/rfc4880#section-5.2.1
                let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                ctr += cnt;

                user_attrs.push(UserAttribute::new(attr, sigs));
            }
            _ => break,
        }
    }

    // -- Only V4 keys should have sub keys

    // TODO: better error handling
    if ctr != packets_len && primary_key.version() != &KeyVersion::V4 {
        panic!(
            "no more packets expected {} {} {:?}",
            ctr,
            packets_len,
            &packets[ctr..]
        );
    }

    // -- Zero or more Subkey packets
    let mut subkeys = vec![];
    while ctr < packets_len && packets[ctr].tag == subkey_tag {
        let subkey = key_parser(packets[ctr])?;
        ctr += 1;

        let (cnt, sigs) = take_sigs(&packets[ctr..])?;
        ctr += cnt;

        // TODO: better error handling
        if sigs.is_empty() {
            println!("WARNING: missing signature");
        }

        subkeys.push((subkey, sigs));
    }

    // TODO: better error handling
    if users.is_empty() {
        println!("WARNING: missing user ids");
    }

    // TODO: better error handling
    if ctr != packets_len {
        panic!(
            "failed to process all packets, processed {}/{}\n{:?}",
            ctr,
            packets_len,
            &packets[ctr..]
        )
    }

    Ok((
        primary_key,
        users,
        user_attrs,
        subkeys,
        revocation_signatures,
        direct_signatures,
    ))
}

fn private_single<K: key::PrivateKey>(
    key_tag: Tag,
    subkey_tag: Tag,
    packets: &[&Packet],
) -> Result<PrivateKey<K>> {
    let (primary_key, users, user_attributes, subkeys, revoaction_signatures, direct_signatures) =
        single(key_tag, subkey_tag, packets, private_key_parser)?;

    Ok(PrivateKey {
        primary_key,
        users,
        user_attributes,
        subkeys: subkeys
            .iter()
            .map(|(key, signatures)| PrivateSubKey { key, signatures })
            .collect(),
        revoaction_signatures,
        direct_signatures,
    })
}

fn public_single<K: key::PublicKey>(
    key_tag: Tag,
    subkey_tag: Tag,
    packets: &[&Packet],
) -> Result<PublicKey<K>> {
    let (primary_key, users, user_attributes, subkeys, revoaction_signatures, direct_signatures) =
        single(key_tag, subkey_tag, packets, private_key_parser)?;

    Ok(PublicKey {
        primary_key,
        users,
        user_attributes,
        subkeys: subkeys
            .iter()
            .map(|(key, signatures)| PublicSubKey { key, signatures })
            .collect(),
        revoaction_signatures,
        direct_signatures,
    })
}

pub fn private_many<'a, K>(
    packets: impl IntoIterator<Item = &'a Packet>,
) -> Result<Vec<PrivateKey<K>>>
where
    K: key::PrivateKey,
{
    many::<PrivateKey<K>, PrivateSubKey<K>>(
        Tag::SecretKey,
        Tag::SecretSubkey,
        packets,
        private_single,
    )
}

pub fn public_many<'a, K>(
    packets: impl IntoIterator<Item = &'a Packet>,
) -> Result<Vec<PublicKey<K>>>
where
    K: key::PublicKey,
{
    many::<PublicKey<K>, PublicSubKey<K>>(Tag::SecretKey, Tag::SecretSubkey, packets, public_single)
}

/// Parse a transferable public or private key
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
fn many<'a, K, SK>(
    key_tag: Tag,
    subkey_tag: Tag,
    packets: impl IntoIterator<Item = &'a Packet>,
    single: fn(Tag, Tag, &[&Packet]) -> Result<K>,
) -> Result<Vec<K>> {
    // This counter tracks which top level key we are in.
    let mut ctr = 0;

    packets
        .into_iter()
        .group_by(|packet| {
            if packet.tag == key_tag{
                ctr += 1;
            }

            ctr
        })
        .into_iter()
        .map(|(_, packets)| single::<K, SK>(key_tag, subkey_tag, &packets.collect::<Vec<_>>()))
    // TODO: better error handling
        .filter(|v| v.is_ok())
        .collect()
}

fn private_key_parser<K: key::PrivateKey>(packet: &Packet) -> Result<PrivateKey<K>> {
    let (_, key) = tags::privkey::parser(packet.body.as_slice()).map_err(|err| {
        println!("WARNING: failed to parse pubkey {:?}", err);
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

fn public_key_parser<K: key::PublicKey>(packet: &Packet) -> Result<PublicKey<K>> {
    let (_, key) = tags::pubkey::parser(packet.body.as_slice()).map_err(|err| {
        println!("WARNING: failed to parse pubkey {:?}", err);
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
