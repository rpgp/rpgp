use block_padding::{Padding, Pkcs7};
use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};

use crypto::{aes_kw, ECCCurve, HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use errors::Result;
use types::{ECDHSecretKey, PlainSecretParams, PublicParams};

/// 20 octets representing "Anonymous Sender    ".
const ANON_SENDER: [u8; 20] = [
    0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72,
    0x20, 0x20, 0x20, 0x20,
];

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

/// Build param for ECDH algorithm (as defined in RFC 6637)
/// https://tools.ietf.org/html/rfc6637#section-8
pub fn build_ecdh_param(
    oid: &[u8],
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
) -> Vec<u8> {
    let kdf_params = vec![
        0x03, // length of the following fields
        0x01, // reserved for future extensions
        hash as u8,
        alg_sym as u8,
    ];

    let oid_len = [oid.len() as u8];

    let values: Vec<&[u8]> = vec![
        &oid_len,
        oid,
        &[PublicKeyAlgorithm::ECDH as u8],
        &kdf_params,
        &ANON_SENDER[..],
        fingerprint,
    ];

    values.concat()
}

/// ECDH decryption.
pub fn decrypt(priv_key: &ECDHSecretKey, mpis: &[Vec<u8>], fingerprint: &[u8]) -> Result<Vec<u8>> {
    info!("ECDH decrypt");

    let param = build_ecdh_param(&priv_key.oid, priv_key.alg_sym, priv_key.hash, fingerprint);

    // 33 = 0x40 + 32bits
    ensure_eq!(mpis.len(), 2);
    ensure_eq!(mpis[0].len(), 33, "invalid public point");
    ensure_eq!(priv_key.secret.len(), 32, "invalid secret point");

    // encrypted and wrapped value derived from the session key
    let encrypted_session_key = &mpis[1];

    let their_public = {
        // public part of the ephemeral key (removes 0x40 prefix)
        let ephemeral_public_key = &mpis[0][1..];

        // create montgomery point
        let mut ephemeral_public_key_arr = [0u8; 32];
        ephemeral_public_key_arr[..].copy_from_slice(ephemeral_public_key);

        x25519_dalek::PublicKey::from(ephemeral_public_key_arr)
    };

    let our_secret = {
        // private key of the recipient.
        let private_key = &priv_key.secret[..];

        // create scalar and reverse to little endian
        let private_key_le = private_key.iter().rev().cloned().collect::<Vec<u8>>();
        let mut private_key_arr = [0u8; 32];
        private_key_arr[..].copy_from_slice(&private_key_le);
        x25519_dalek::StaticSecret::from(private_key_arr)
    };

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // Perform key derivation
    let z = kdf(
        priv_key.hash,
        shared_secret.as_bytes(),
        priv_key.alg_sym.key_size(),
        &param,
    )?;

    // Peform AES Key Unwrap
    let decrypted_key_padded = aes_kw::unwrap(&z, encrypted_session_key)?;

    // PKCS5 unpadding (PKCS5 is PKCS7 with a blocksize of 8)
    let decrypted_key = Pkcs7::unpad(&decrypted_key_padded)?;

    Ok(decrypted_key.to_vec())
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// https://tools.ietf.org/html/rfc6637#section-7
fn kdf(hash: HashAlgorithm, x: &[u8; 32], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = vec![0, 0, 0, 1];

    let values: Vec<&[u8]> = vec![&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}

/// ECDH encryption.
pub fn encrypt<R: CryptoRng + Rng>(
    rng: &mut R,
    curve: &ECCCurve,
    alg_sym: SymmetricKeyAlgorithm,
    hash: HashAlgorithm,
    fingerprint: &[u8],
    q: &[u8],
    plain: &[u8],
) -> Result<Vec<Vec<u8>>> {
    info!("ECDH encrypt");

    let param = build_ecdh_param(&curve.oid(), alg_sym, hash, fingerprint);

    ensure_eq!(q.len(), 33, "invalid public key");

    let their_public = {
        // public part of the ephemeral key (removes 0x40 prefix)
        let public_key = &q[1..];

        // create montgomery point
        let mut public_key_arr = [0u8; 32];
        public_key_arr[..].copy_from_slice(public_key);

        x25519_dalek::PublicKey::from(public_key_arr)
    };

    let our_secret = x25519_dalek::StaticSecret::new(rng);

    // derive shared secret
    let shared_secret = our_secret.diffie_hellman(&their_public);

    // Perform key derivation
    let z = kdf(hash, shared_secret.as_bytes(), alg_sym.key_size(), &param)?;

    // PKCS5 padding (PKCS5 is PKCS7 with a blocksize of 8)
    let len = plain.len();
    let mut plain_padded = plain.to_vec();
    plain_padded.resize(len + 8, 0);
    let plain_padded_ref = Pkcs7::pad(&mut plain_padded, len, 8)?;

    // Peform AES Key Wrap
    let encrypted_key = aes_kw::wrap(&z, plain_padded_ref)?;

    // Encode public point: prefix with 0x40
    let mut encoded_public = Vec::with_capacity(33);
    encoded_public.push(0x40);
    encoded_public.extend(x25519_dalek::PublicKey::from(&our_secret).as_bytes().iter());

    Ok(vec![encoded_public, encrypted_key])
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;

    use types::{PublicParams, SecretKeyRepr};

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::from_seed([0u8; 32]);

        let (pkey, skey) = generate_key(&mut rng);
        let mut fingerprint = vec![0u8; 20];
        rng.fill_bytes(&mut fingerprint);

        let plain = b"hello world";

        let mpis = match pkey {
            PublicParams::ECDH {
                ref curve,
                ref p,
                hash,
                alg_sym,
            } => encrypt(&mut rng, curve, alg_sym, hash, &fingerprint, p, &plain[..]).unwrap(),
            _ => panic!("invalid key generated"),
        };

        let decrypted = match skey.as_repr(&pkey).unwrap() {
            SecretKeyRepr::ECDH(ref skey) => decrypt(skey, &mpis, &fingerprint).unwrap(),
            _ => panic!("invalid key generated"),
        };

        assert_eq!(&plain[..], &decrypted[..]);
    }
}
