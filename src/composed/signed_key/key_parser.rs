use crate::errors::Result;
use crate::packet::{self, Packet, Signature, SignatureType, UserAttribute, UserId};
use crate::types::{KeyVersion, PublicKeyTrait, SignedUser, SignedUserAttribute, Tag};
use crate::{SignedKeyDetails, SignedPublicSubKey, SignedSecretSubKey};

#[allow(clippy::complexity)]
pub fn next<I, IKT>(
    packets: &mut std::iter::Peekable<I>,
    key_tag: Tag,
    parse_secrect_subkeys: bool,
) -> Option<
    Result<(
        IKT,
        SignedKeyDetails,
        Vec<SignedPublicSubKey>,
        Vec<SignedSecretSubKey>,
    )>,
>
where
    I: Sized + Iterator<Item = Result<Packet>>,
    IKT: TryFrom<packet::Packet, Error = crate::errors::Error> + PublicKeyTrait,
{
    let packets = packets.by_ref();

    // Check if we are done
    packets.peek()?;

    // -- One Public-Key packet

    // ignore random other packets until we find something useful
    while let Some(packet) = packets.next_if(|p| p.as_ref().is_ok_and(|p| p.tag() != key_tag)) {
        match packet {
            Ok(p) => {
                warn!(
                    "ignoring unexpected packet: expected {:?}, got {:?}",
                    key_tag,
                    p.tag()
                );
                // FIXME: return error?
            }
            Err(e) => return Some(Err(e)),
        }
    }

    let next = match packets.next() {
        Some(Ok(n)) => n,
        Some(Err(e)) => return Some(Err(e)),
        None => return None,
    };
    let primary_key: IKT = match next.try_into() {
        Ok(key) => key,
        Err(err) => {
            return Some(Err(err));
        }
    };
    debug!("primary key: {:?}", primary_key.key_id());

    // -- Zero or more revocation signatures
    // -- followed by zero or more direct signatures in V4 keys
    debug!("  signatures");
    let mut revocation_signatures = Vec::new();
    let mut direct_signatures = Vec::new();

    while let Some(packet) =
        packets.next_if(|p| p.as_ref().is_ok_and(|p| p.tag() == Tag::Signature))
    {
        match packet {
            Ok(packet) => {
                debug!("parsing signature {:?}", packet.tag());
                let sig: Signature = err_opt!(packet.try_into());
                let typ = sig.typ();

                if typ == SignatureType::KeyRevocation {
                    revocation_signatures.push(sig);
                } else {
                    if primary_key.version() != KeyVersion::V4 {
                        // no direct signatures on V2|V3 keys
                        warn!("unexpected signature: {:?}", typ);
                    }
                    direct_signatures.push(sig);
                }
            }
            Err(e) => return Some(Err(e)),
        }
    }

    // -- Zero or more User ID packets
    // -- Zero or more User Attribute packets
    debug!("  user");
    let mut users = Vec::new();
    let mut user_attributes = Vec::new();

    while let Some(packet) = packets.next_if(|p| {
        p.as_ref().is_ok_and(|p| {
            debug!("peek {:?}", p.tag());
            p.tag() == Tag::UserId || p.tag() == Tag::UserAttribute
        })
    }) {
        let packet = match packet {
            Ok(packet) => packet,
            Err(err) => return Some(Err(err)),
        };

        let tag = packet.tag();
        debug!("  user data: {:?}", tag);
        match tag {
            Tag::UserId => {
                let id: UserId = err_opt!(packet.try_into());

                // --- zero or more signature packets

                let mut sigs = Vec::new();

                while let Some(res) =
                    packets.next_if(|p| p.as_ref().is_ok_and(|p| p.tag() == Tag::Signature))
                {
                    let packet = match res {
                        Ok(packet) => packet,
                        Err(e) => return Some(Err(e)),
                    };
                    let sig: Signature = err_opt!(packet.try_into());

                    sigs.push(sig);
                }

                users.push(SignedUser::new(id, sigs));
            }
            Tag::UserAttribute => {
                let attr: UserAttribute = err_opt!(packet.try_into());

                // --- zero or more signature packets

                let mut sigs = Vec::new();
                while let Some(res) =
                    packets.next_if(|p| p.as_ref().is_ok_and(|p| p.tag() == Tag::Signature))
                {
                    let packet = match res {
                        Ok(packet) => packet,
                        Err(e) => return Some(Err(e)),
                    };
                    let sig: Signature = err_opt!(packet.try_into());

                    sigs.push(sig);
                }

                user_attributes.push(SignedUserAttribute::new(attr, sigs));
            }
            _ => break,
        }
    }

    if users.is_empty() {
        warn!("missing user ids");
    }

    // -- Zero or more Subkey packets

    let mut public_subkey_container = Vec::new();
    let mut secret_subkey_container = Vec::new();
    debug!("  subkeys");

    while let Some(res) = packets.next_if(|p| {
        p.as_ref().is_ok_and(|p| {
            debug!("  peek {:?}", p.tag());
            p.tag() == Tag::PublicSubkey || (parse_secrect_subkeys && p.tag() == Tag::SecretSubkey)
        })
    }) {
        // -- Only V4 keys should have sub keys
        if primary_key.version() != KeyVersion::V4 {
            return Some(Err(format_err!("only V4 keys can have subkeys")));
        }

        let packet = match res {
            Ok(packet) => packet,
            Err(e) => return Some(Err(e)),
        };

        match packet.tag() {
            Tag::PublicSubkey => {
                let subkey: packet::PublicSubkey = err_opt!(packet.try_into());
                let mut sigs = Vec::new();
                while let Some(res) = packets.next_if(|packet| {
                    packet.is_ok() && packet.as_ref().expect("just checked").tag() == Tag::Signature
                }) {
                    match res {
                        Ok(packet) => {
                            let sig: Signature = err_opt!(packet.try_into());
                            sigs.push(sig);
                        }
                        Err(e) => return Some(Err(e)),
                    }
                }
                public_subkey_container.push(SignedPublicSubKey::new(subkey, sigs));
            }
            Tag::SecretSubkey => {
                if parse_secrect_subkeys {
                    let subkey: packet::SecretSubkey = err_opt!(packet.try_into());
                    let mut sigs = Vec::new();
                    while let Some(res) = packets.next_if(|packet| {
                        packet.is_ok()
                            && packet.as_ref().expect("just checked").tag() == Tag::Signature
                    }) {
                        match res {
                            Ok(packet) => {
                                let sig: Signature = err_opt!(packet.try_into());
                                sigs.push(sig);
                            }
                            Err(e) => return Some(Err(e)),
                        }
                    }
                    secret_subkey_container.push(SignedSecretSubKey::new(subkey, sigs));
                }
            }
            _ => unreachable!(),
        }
    }

    Some(Ok((
        primary_key,
        SignedKeyDetails::new(
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes,
        ),
        public_subkey_container,
        secret_subkey_container,
    )))
}
