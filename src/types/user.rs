use std::io;

use log::{debug, warn};

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
            if Signature::match_identity(signature, key) {
                // We can (and should) only check self-signatures, here
                signature.verify_certification(key, Tag::UserId, &self.id)?;
            }
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
            if Signature::match_identity(signature, key) {
                // We can (and should) only check self-signatures, here
                signature.verify_certification(key, Tag::UserAttribute, &self.attr)?;
            }
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

#[cfg(test)]
mod tests {
    use crate::{Deserializable, SignedPublicKey};

    #[test]
    /// SignedPublicKey::verify should not fail on third party User ID certifications
    fn test_verify_ignores_third_party_sig() {
        // Alice has a third party User ID certification
        const ALICE: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEZ2XJeBYJKwYBBAHaRw8BAQdAE8TRtg2u7+FmKnWM340pc7vOxWDS/MA/cjVu
pBFuLaPNBWFsaWNlwo8EEBYIADcCGQEFAmdlyXgCGwMICwkIBwoNDAsFFQoJCAsC
FgIBJxYhBOPRPeq3601db0WyneKiB6KRHwGaAAoJEOKiB6KRHwGa+BcA/i+OZFLi
g6xWAoXj41/g1kIFVm8RLfYgcHE/B17fI+NWAP9d/bnsePyZth7pjNrcIGK4koC+
dHJoOKwtkwI7xSWACsK9BBMWCgBvBYJnZcmaCRAM+ckRhKDOUUcUAAAAAAAeACBz
YWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeeQTvS9hWNSc7k/ZAMBM5YAQGW
9OCylwH4vZLcOSU8CRYhBGQv0Lepp6IABopGEAz5yRGEoM5RAACgQAEAnkYVVL2W
9fYA4i1mly1W9yA5m2CYMtDpb3aJ5fMgvc4BAN6pCVpRzdbIDP66J2Jj2nhTg/jy
H7jJIG6RoZq2/v0LzjgEZ2XJeBIKKwYBBAGXVQEFAQEHQJuf4ZOjlkgUEXId9cAm
pq77Hp7KRB78piUKKRvfyHteAwEIB8J4BBgWCAAgBQJnZcl4AhsMFiEE49E96rfr
TV1vRbKd4qIHopEfAZoACgkQ4qIHopEfAZqsJwEAxkX531d/aXkWjeCxLiGukm1j
JNN0jSXNnUr6S+1zP8QA/1bxZxOp5BoK3rdBUxScIyO2oeGCczggHCCHk0KnMqII
=fPDT
-----END PGP PUBLIC KEY BLOCK-----";

        let (alice, _headers) = SignedPublicKey::from_string(ALICE).expect("can parse alice");

        alice.verify().expect("verify should not error");
    }
}
