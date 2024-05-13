use std::io;

use crate::errors::Result;
use crate::packet::{write_packet, Signature, UserAttribute, UserId};
use crate::ser::Serialize;
use crate::types::{PublicKeyTrait, Tag};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedUser {
    pub id: UserId,
    pub signatures: Vec<Signature>,
}

impl SignedUser {
    pub fn new(id: UserId, signatures: Vec<Signature>) -> Self {
        let signatures = signatures
            .into_iter()
            .filter(|sig| {
                if !sig.is_certification() {
                    warn!(
                        "ignoring unexpected signature {:?} after User ID packet",
                        sig.typ()
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        SignedUser { id, signatures }
    }

    /// Verify all signatures (for self-signatures). If signatures is empty, this fails.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        debug!("verify signed user {:#?}", self);
        ensure!(!self.signatures.is_empty(), "no signatures found");

        for signature in &self.signatures {
            signature.verify_certification(key, Tag::UserId, &self.id)?;
        }

        Ok(())
    }

    /// Verify all signatures (for third-party signatures). If signatures is empty, this fails.
    pub fn verify_third_party(
        &self,
        signee: &impl PublicKeyTrait,
        signer: &impl PublicKeyTrait,
    ) -> Result<()> {
        debug!("verify signed user {:#?} with signer {:#?}", self, signer);
        ensure!(!self.signatures.is_empty(), "no signatures found");

        for signature in &self.signatures {
            signature.verify_third_party_certification(signee, signer, Tag::UserId, &self.id)?;
        }

        Ok(())
    }

    pub fn is_primary(&self) -> bool {
        self.signatures.iter().any(Signature::is_primary)
    }
}

impl Serialize for SignedUser {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.id)?;
        for sig in &self.signatures {
            write_packet(writer, sig)?;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedUserAttribute {
    pub attr: UserAttribute,
    pub signatures: Vec<Signature>,
}

impl SignedUserAttribute {
    pub fn new(attr: UserAttribute, signatures: Vec<Signature>) -> Self {
        let signatures = signatures
            .into_iter()
            .filter(|sig| {
                if !sig.is_certification() {
                    warn!(
                        "ignoring unexpected signature {:?} after User Attribute packet",
                        sig.typ()
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        SignedUserAttribute { attr, signatures }
    }

    /// Verify all signatures (for self-signatures). If signatures is empty, this fails.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        debug!("verify signed attribute {:?}", self);
        ensure!(!self.signatures.is_empty(), "no signatures found");

        for signature in &self.signatures {
            signature.verify_certification(key, Tag::UserAttribute, &self.attr)?;
        }

        Ok(())
    }

    /// Verify all signatures (for third-party signatures). If signatures is empty, this fails.
    pub fn verify_third_party(
        &self,
        signee: &impl PublicKeyTrait,
        signer: &impl PublicKeyTrait,
    ) -> Result<()> {
        debug!(
            "verify signed attribute {:#?} with signer {:#?}",
            self, signer
        );
        ensure!(!self.signatures.is_empty(), "no signatures found");

        for signature in &self.signatures {
            signature.verify_third_party_certification(
                signee,
                signer,
                Tag::UserAttribute,
                &self.attr,
            )?;
        }

        Ok(())
    }
}

impl Serialize for SignedUserAttribute {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.attr)?;
        for sig in &self.signatures {
            write_packet(writer, sig)?;
        }

        Ok(())
    }
}
