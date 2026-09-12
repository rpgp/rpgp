use pgp::{
    composed::{
        Deserializable, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{SecretSubkey, Signature, SignatureConfig, Subpacket, SubpacketData, SubpacketLength},
    ser::Serialize,
    types::{CompressionAlgorithm, KeyVersion, Password},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[test]
/// Create a TSK with a deeply nested embedded subpacket structure,
/// check that parsing doesn't panic
///
/// NOTE: parsing runs into a stack overflow at depth ~5000 for this test case,
/// without a guard against nested embedded subpackets
fn roundtrip_nested_embedded() {
    for depth in [2, 10, 100] {
        // run key generation with larger stack
        let signed_key = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024) // 256 MB
            .spawn(move || make_deep(depth))
            .unwrap()
            .join()
            .unwrap();

        // serialize with larger stack
        let binary = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024) // 256 MB
            .spawn(move || signed_key.to_bytes().expect("failed to serialize key"))
            .unwrap()
            .join()
            .unwrap();

        // Check that parsing rejects nesting
        SignedSecretKey::from_bytes(&*binary).expect_err("reject nested embedded signatures");
    }
}

fn make_deep(count: usize) -> SignedSecretKey {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let key_params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V6)
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(false)
        .feature_seipd_v2(true)
        .preferred_aead_algorithms(vec![(SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb)].into())
        .preferred_symmetric_algorithms(vec![SymmetricKeyAlgorithm::AES256].into())
        .preferred_hash_algorithms(vec![HashAlgorithm::Sha512].into())
        .preferred_compression_algorithms(vec![CompressionAlgorithm::Uncompressed].into())
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V6)
                .key_type(KeyType::Ed25519)
                .can_sign(true)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let mut signed_key = key_params
        .generate(&mut rng)
        .expect("failed to generate secret key");

    // ---

    let sig = &signed_key.secret_subkeys[0].signatures[0];

    let mut outer_config = sig.config().unwrap().clone();

    let emb = sig.embedded_signature().unwrap().clone();
    let emb_config = emb.config().unwrap().clone();

    // make a variant of the embedded signature that contains "count" levels of inner embedded signatures.
    // those are syntactically alright, but semantically nonsensical, and also not cryptographically valid.
    let emb_recursed = recursive_embedded(&emb_config, &signed_key.secret_subkeys[0].key, count);

    // make a valid back-signature out of this
    let emb_recursed_config = emb_recursed.config().unwrap().clone();

    // a cryptographically valid embedded signature (only its inner embedded subpackets are weird)
    let deep_embedded = emb_recursed_config
        .sign_primary_key_binding(
            &signed_key.secret_subkeys[0].key,
            &signed_key.secret_subkeys[0].key.public_key(),
            &Password::empty(),
            &signed_key.primary_key.public_key(),
        )
        .unwrap();

    // replace the embedded signature in the outer signature config of the subkey
    outer_config.hashed_subpackets.iter_mut().for_each(|sp| {
        if let SubpacketData::EmbeddedSignature(e) = &mut sp.data {
            **e = deep_embedded.clone()
        }

        sp.len = match sp.data.write_len() + 1 {
            i if i <= 191 => SubpacketLength::One(i as u8),
            i if i <= 16319 => SubpacketLength::Two(i as u16),
            i => SubpacketLength::Five(i as u32),
        };
    });

    let outer = outer_config
        .sign_subkey_binding(
            &signed_key.primary_key,
            &signed_key.primary_key.public_key(),
            &Password::empty(),
            &signed_key.secret_subkeys[0].key.public_key(),
        )
        .unwrap();

    signed_key.secret_subkeys[0].signatures[0] = outer;

    // ---

    signed_key
}

// make a recursive series of inner signatures
fn recursive_embedded(emb: &SignatureConfig, signer: &SecretSubkey, count: usize) -> Signature {
    let mut sig = emb
        .clone()
        .sign_primary_key_binding(signer, signer.public_key(), &Password::empty(), signer)
        .unwrap();

    for _ in 1..count {
        let mut config = emb.clone();

        config.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(sig.clone()))).unwrap(),
        );

        // syntactically ok, semantically nonsense
        sig = config
            .sign_primary_key_binding(signer, signer.public_key(), &Password::empty(), signer)
            .unwrap();
    }

    sig
}
