use errors::{Error, Result};
use itertools::Itertools;
use key::{Key, SubKey};
use nom::Err::Incomplete;
use nom::Needed;
use packet::tags;
use packet::types::{Packet, PrimaryKey, Signature, Tag, User, UserAttribute};

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

fn parse_pubkey(packet: &Packet) -> Result<PrimaryKey> {
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

/// Parse a single transferable public key.
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
/// Currently skips packets it fails to parse.
fn parse_single(packets: &[&Packet]) -> Result<Key> {
    let mut ctr = 0;
    let packets_len = packets.len();

    // -- One Public-Key packet
    // TODO: better error management
    assert_eq!(packets[ctr].tag, Tag::PublicKey);

    let primary_key = parse_pubkey(packets[ctr])?;

    ctr += 1;

    // -- Zero or more revocation signatures
    let (cnt, revocation_signatures) = take_sigs(&packets[ctr..])?;
    ctr += cnt;

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
                let (cnt, sigs) = take_sigs(&packets[ctr..])?;
                ctr += cnt;

                user_attrs.push(UserAttribute::new(attr, sigs));
            }
            _ => break,
        }
    }

    // -- Zero or more Subkey packets
    let mut subkeys = vec![];
    while ctr < packets_len && packets[ctr].tag == Tag::PublicSubkey {
        // TODO: parse subkey
        let subkey = parse_pubkey(packets[ctr])?;
        ctr += 1;

        let (cnt, sigs) = take_sigs(&packets[ctr..])?;
        ctr += cnt;

        // TODO: better error handling
        if sigs.is_empty() {
            println!("WARNING: missing signature");
        }

        subkeys.push(SubKey {
            key: subkey,
            signatures: sigs,
        });
    }

    // TODO: better error handling
    if users.is_empty() {
        println!("WARNING: missing user ids");
    }

    Ok(Key {
        primary_key,
        users,
        user_attributes: user_attrs,
        subkeys,
        revocation_signatures,
    })
}

/// Parse a transferable public key
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
pub fn parse(packets: &[Packet]) -> Result<Vec<Key>> {
    // This counter tracks which top level key we are in.
    let mut ctr = 0;

    packets
        .into_iter()
        .group_by(|packet| {
            if packet.tag == Tag::PublicKey {
                ctr += 1;
            }

            ctr
        })
        .into_iter()
        .map(|(_, packets)| parse_single(&packets.collect::<Vec<_>>()))
        // TODO: better error handling
        .filter(|v| v.is_ok())
        .collect()
}
