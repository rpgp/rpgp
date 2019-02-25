use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};

use crypto::{ECCCurve, HashAlgorithm, PublicParams, SymmetricKeyAlgorithm};
use types::PlainSecretParams;

/// Generate an ECDH KeyPair.
/// Currently only support ED25519.
pub fn generate_key<R: Rng + CryptoRng>(rng: &mut R) -> (PublicParams, PlainSecretParams) {
    let secret = StaticSecret::new(rng);
    let public = PublicKey::from(&secret);

    // public key
    let mut p = Vec::with_capacity(33);
    p.push(0x40);
    p.extend_from_slice(&public.as_bytes()[..]);

    // secret key
    let q = secret.to_bytes().iter().cloned().rev().collect::<Vec<u8>>();

    // TODO: make these configurable and/or check for good defaults
    let hash = HashAlgorithm::default();
    let alg_sym = SymmetricKeyAlgorithm::AES128;
    (
        PublicParams::ECDH {
            curve: ECCCurve::Curve25519,
            p,
            hash,
            alg_sym,
        },
        PlainSecretParams::ECDH(q),
    )
}
