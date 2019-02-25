use ed25519_dalek::Keypair;
use rand::{CryptoRng, Rng};

use crypto::{ECCCurve, PublicParams};
use types::PlainSecretParams;

/// Generate an EdDSA KeyPair.
pub fn generate_key<R: Rng + CryptoRng>(rng: &mut R) -> (PublicParams, PlainSecretParams) {
    let keypair = Keypair::generate(rng);
    let bytes = keypair.to_bytes();

    // public key
    let mut q = Vec::with_capacity(33);
    q.push(0x40);
    q.extend_from_slice(&bytes[32..]);

    // secret key
    let p = &bytes[..32];

    (
        PublicParams::EdDSA {
            curve: ECCCurve::Ed25519,
            q,
        },
        PlainSecretParams::EdDSA(p.to_vec()),
    )
}
