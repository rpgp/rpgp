use std::io;

use crypto::hash::HashAlgorithm;
use errors::Result;
use types::KeyTrait;

pub trait PublicKeyTrait: KeyTrait {
    /// Verify a signed message.
    /// Data will be hashed using `hash`, before verifying.
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Vec<u8>]) -> Result<()>;

    // TODO: figure out a better place for this
    /// This is the data used for hashing in a signature. Only uses the public portion of the key.
    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()>;
}

impl<'a, T: PublicKeyTrait> PublicKeyTrait for &'a T {
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Vec<u8>]) -> Result<()> {
        (*self).verify_signature(hash, data, sig)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        (*self).to_writer_old(writer)
    }
}
