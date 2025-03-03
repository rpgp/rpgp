use std::io;

use log::{debug, warn};

use crate::errors::Result;
use crate::packet::{PacketTrait, Signature, UserAttribute, UserId};
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
    pub fn verify<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        debug!("verify signed user {:#?}", self);
        ensure!(!self.signatures.is_empty(), "no signatures found");

        for signature in &self.signatures {
            signature.verify_certification(key, Tag::UserId, &self.id)?;
        }

        Ok(())
    }

    /// Verify all signatures (for third-party signatures). If signatures is empty, this fails.
    pub fn verify_third_party<P, K>(&self, signee: &P, signer: &K) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
        K: PublicKeyTrait + Serialize,
    {
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
        self.id.to_writer_with_header(writer)?;
        for sig in &self.signatures {
            sig.to_writer_with_header(writer)?;
        }

        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = self.id.write_len_with_header();
        for sig in &self.signatures {
            sum += sig.write_len_with_header();
        }
        sum
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
    pub fn verify<P>(&self, key: &P) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
    {
        debug!("verify signed attribute {:?}", self);
        ensure!(!self.signatures.is_empty(), "no signatures found");

        for signature in &self.signatures {
            signature.verify_certification(key, Tag::UserAttribute, &self.attr)?;
        }

        Ok(())
    }

    /// Verify all signatures (for third-party signatures). If signatures is empty, this fails.
    pub fn verify_third_party<P, K>(&self, signee: &P, signer: &K) -> Result<()>
    where
        P: PublicKeyTrait + Serialize,
        K: PublicKeyTrait + Serialize,
    {
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
        self.attr.to_writer_with_header(writer)?;
        for sig in &self.signatures {
            sig.to_writer_with_header(writer)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.attr.write_len_with_header();
        for sig in &self.signatures {
            sum += sig.write_len_with_header();
        }
        sum
    }
}
