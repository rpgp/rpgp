use errors::Result;
use packet::{Signature, UserAttribute, UserId};
use types::PublicKeyTrait;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedUser {
    pub id: UserId,
    pub signatures: Vec<Signature>,
}

impl SignedUser {
    pub fn new(id: UserId, signatures: Vec<Signature>) -> Self {
        SignedUser { id, signatures }
    }

    /// Verify all signatures. If signatures is empty, this fails.
    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        info!("verify signed user {:?}", self);
        ensure!(self.signatures.len() > 0, "no signatures found");

        for signature in &self.signatures {
            signature.verify_user_id_certificate(key, &self.id)?;
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
        SignedUserAttribute { attr, signatures }
    }
}
