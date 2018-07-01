use errors::{Error, Result};
use key::Key;
use nom::Err::Incomplete;
use nom::Needed;
use packet::types::{Signature, User, UserAttribute};
use packet::{tags, Packet, Tag};

fn take_sigs(packets: &[Packet], ctr: &mut usize) -> Vec<Signature> {
    let mut res = vec![];
    while *ctr < packets.len() && packets[*ctr].tag == Tag::Signature {
        match tags::sig::parser(packets[*ctr].body.as_slice()) {
            Ok((_, sig)) => {
                res.push(sig);
            }
            Err(err) => {
                println!("WARNING: failed to parse sig: {:?}", err);
            }
        }
        *ctr += 1;
    }

    res
}

/// Parse a transferable public key
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
fn parse_single(ctr: &mut usize, packets: &[Packet]) -> Result<Key> {
    let packets_len = packets.len();

    // -- One Public-Key packet
    // TODO: better error management
    assert_eq!(packets[*ctr].tag, Tag::PublicKey);

    let body = packets[*ctr].body.as_slice();
    let (_, primary_key) = tags::pubkey::parser(body).map_err(|err| {
        println!("failed to parse pubkey {:?}", err);
        println!("{:?}", packets[*ctr]);
        match err {
            Incomplete(n) => {
                // a size larger than the packet was requested, always invalid
                if let Needed::Size(size) = n {
                    if size > body.len() {
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

    *ctr += 1;

    // -- Zero or more revocation signatures
    let _rev_sigs = take_sigs(packets, ctr);

    // -- Zero or more User ID packets
    // -- Zero or more User Attribute packets

    let mut users = vec![];
    let mut user_attrs = vec![];

    while *ctr < packets_len {
        match packets[*ctr].tag {
            Tag::UserID => {
                // TODO: better erorr handling
                let id = tags::userid::parser(packets[*ctr].body.as_slice());
                *ctr += 1;

                // --- zero or more signature packets
                let sigs = take_sigs(packets, ctr);

                users.push(User::new(id, sigs));
            }
            Tag::UserAttribute => {
                // TODO: better error handling
                let a = tags::userattr::parser(packets[*ctr].body.as_slice());
                if a.is_err() {
                    println!("failed to parse {:?}\n{:?}", packets[*ctr], a);
                }

                let (_, attr) = a?;
                *ctr += 1;

                // --- zero or more signature packets
                let sigs = take_sigs(packets, ctr);

                user_attrs.push(UserAttribute::new(attr, sigs));
            }
            _ => break,
        }
    }

    // -- Zero or more Subkey packets
    let mut subkeys = vec![];
    while *ctr < packets_len && packets[*ctr].tag == Tag::PublicSubkey {
        // TODO: parse subkey
        let subkey = &packets[*ctr];
        *ctr += 1;

        let sigs = take_sigs(packets, ctr);

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

    Ok(Key {
        primary_key,
        users,
        user_attributes: user_attrs,
        // TODO: subkeys
    })
}

/// Parse a transferable public key
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
pub fn parse(packets: &[Packet]) -> Result<Vec<Key>> {
    let mut ctr = 0;
    let mut keys = Vec::new();

    while ctr < packets.len() {
        // println!("{}/{}", ctr, packets.len());
        match parse_single(&mut ctr, packets) {
            Ok(key) => {
                keys.push(key);
            }
            Err(err) => {
                println!("failed to parse key: {:?}", err);
                // skipping packets until we find a pubkey again
                ctr += 1;
                while ctr < packets.len() && packets[ctr].tag != Tag::PublicKey {
                    ctr += 1;
                }
            }
        }
    }

    // TODO: better error handling
    assert_eq!(ctr, packets.len(), "failed to process all packets");

    Ok(keys)
}
