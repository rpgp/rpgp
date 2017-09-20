use nom::IResult;
use std::str;

use packet::types::{Key, User, Signature, UserAttribute};
use packet::{Tag, Packet, tags};

fn take_sigs<'a>(packets: &'a Vec<Packet>, mut ctr: usize) -> Vec<Signature> {
    let mut res = vec![];
    while ctr < packets.len() && packets[ctr].tag == Tag::Signature {
        // TODO: error handling
        let (_, sig) = tags::sig::parser(packets[ctr].body.as_slice()).unwrap();
        res.push(sig);
        ctr += 1;
    }

    res
}


/// Parse a transferable public key
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-11.1
pub fn parse<'a>(packets: Vec<Packet>) -> IResult<&'a [u8], Key> {
    println!("parsing packets {}", packets.len());
    let packets_len = packets.len();
    let mut ctr = 0;

    // -- One Public-Key packet
    // TODO: better error management
    assert_eq!(packets[ctr].tag, Tag::PublicKey);
    let res = tags::pubkey::parser(packets[ctr].body.as_slice());
    if !res.is_done() {
        println!("failed to parse pubkey {:?}", &res);
    }
    let (_, primary_key) = res.unwrap();

    ctr += 1;

    // -- Zero or more revocation signatures
    let rev_sigs = take_sigs(&packets, ctr);
    ctr += rev_sigs.len();

    // -- Zero or more User ID packets
    // -- Zero or more User Attribute packets

    let mut users = vec![];
    let mut user_attrs = vec![];

    while ctr < packets_len {
        match packets[ctr].tag {
            Tag::UserID => {
                // TODO: better erorr handling
                let id =
                    tags::userid::parser(packets[ctr].body.as_slice()).expect("invalid user id");
                ctr += 1;

                // --- zero or more signature packets
                let sigs = take_sigs(&packets, ctr);
                ctr += sigs.len();

                users.push(User::new(id.to_string(), sigs));
            }
            Tag::UserAttribute => {
                // TODO: better error handling
                let (_, attr) = tags::userattr::parser(packets[ctr].body.as_slice()).unwrap();
                ctr += 1;

                // --- zero or more signature packets
                let sigs = take_sigs(&packets, ctr);
                ctr += sigs.len();

                user_attrs.push(UserAttribute::new(attr, sigs));
            }
            _ => break,
        }
    }

    // -- Zero or more Subkey packets
    let mut subkeys = vec![];
    while ctr < packets_len && packets[ctr].tag == Tag::PublicSubkey {
        // --- one Signature packet,
        // TODO: better error handling
        assert_eq!(packets[ctr + 1].tag, Tag::Signature, "Missing signature");

        let subkey = &packets[ctr];
        let (_, sig) = tags::sig::parser(packets[ctr + 1].body.as_slice()).unwrap();
        ctr += 2;

        // --- optionally a revocation
        let rev = if packets_len > ctr && packets[ctr].tag == Tag::Signature {
            let (_, sig) = tags::sig::parser(packets[ctr].body.as_slice()).unwrap();
            ctr += 1;
            // TODO: assert sig is revocation
            Some(sig)
        } else {
            None
        };

        subkeys.push((subkey, sig, rev));
    }

    // TODO: better error handling
    assert!(users.len() > 0, "Missing user ids");

    // TODO: better error handling
    assert_eq!(ctr, packets_len, "failed to process all packets");

    IResult::Done(
        &b""[..],
        Key {
            primary_key: primary_key,
            users: users,
            user_attributes: user_attrs,
        },
    )
}
