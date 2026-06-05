#![no_main]

use std::sync::OnceLock;

#[cfg(feature = "fuzzer_seed1")]
use libfuzzer_sys::fuzz_mutator;
use libfuzzer_sys::fuzz_target;
#[cfg(feature = "fuzzer_seed1")]
use pgp::composed::MessageBuilder;
#[cfg(feature = "fuzzer_seed1")]
use pgp::composed::SignedPublicKey;
#[cfg(feature = "fuzzer_seed1")]
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::{
    composed::{Deserializable, Edata, Message, SignedSecretKey},
    packet::{ProtectedDataConfig, SymEncryptedProtectedDataConfig},
    types::Password,
};
#[cfg(feature = "fuzzer_seed1")]
use rand_chacha::rand_core::SeedableRng;
#[cfg(feature = "fuzzer_seed1")]
use rand_chacha::ChaCha8Rng;

static KEY: OnceLock<SignedSecretKey> = OnceLock::new();

#[cfg(feature = "fuzzer_seed1")]
fuzz_mutator!(
    |data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
        mutate_message_synthesize_seipdv1(data, size, max_size, _seed)
    }
);

#[cfg(feature = "fuzzer_seed1")]
/// This implementation mis-uses the mutator format to repeatedly generate
/// and mutate variations of a correctly encrypted message
/// Note that this completely ignores the original data input, and as such
/// is only meant to be used occasionally with this fuzzer harness, and not
/// as the main or only fuzzer configuration
pub fn mutate_message_synthesize_seipdv1(
    data: &mut [u8],
    _size: usize,
    max_size: usize,
    seed: u32,
) -> usize {
    // reserve as much space as allowed
    let mut buffer = vec![0; max_size];

    // Ensure deterministic behavior via small PRNG based on fuzzer-controlled seed parameter
    let mut prng = ChaCha8Rng::seed_from_u64(seed.into());

    // dummy message
    let msg = b"Secret message";

    // fixed public key
    let public_key = SignedPublicKey::from(KEY.get().unwrap().clone());

    // Load the OpenPGP public key that we'll encrypt to
    let encryption_subkey = &public_key.public_subkeys[0];

    // Initialize encryption of `msg`, configure that the output will be a "SEIPDv1" encryption
    // container.
    let mut builder = MessageBuilder::from_bytes("", msg.to_vec())
        .seipd_v1(&mut prng, SymmetricKeyAlgorithm::AES256);

    // Add `encryption_subkey` as one recipient of the encrypted message
    builder
        .encrypt_to_key(&mut prng, &encryption_subkey)
        .unwrap();

    // Perform the actual encryption of the payload and put together the resulting encrypted message
    let encrypted_message_data = builder.to_vec(&mut prng).unwrap();
    let encrypted_message_data_length = encrypted_message_data.len();

    // check if we have enough room to fit our valid message
    if encrypted_message_data_length <= max_size {
        // copy valid encoded message into buffer
        buffer[..encrypted_message_data_length]
            .copy_from_slice(&encrypted_message_data[..encrypted_message_data_length]);

        // let the fuzzer manipulate the encoded message data, including growing it
        let mutated_data_size =
            libfuzzer_sys::fuzzer_mutate(&mut buffer, encrypted_message_data_length, max_size);

        // copy mutated result into output
        data[..mutated_data_size].copy_from_slice(&buffer[..mutated_data_size]);

        // tell the fuzzer engine how many bytes of data are relevant
        return mutated_data_size;
    }
    // simple fallback, return no data
    // alternatively, we could do some of the normal computation steps and return a subset of data
    0
}

// build message and try decryption with a known-good private key
fuzz_target!(
        init: {
            // special init function, to be run only once

            // file content of test key included here to avoid I/O operations
            // This key is compatible with SEIPDv1 requirements
            let key_input = include_str!(
                "../../tests/draft-bre-openpgp-samples-00/bob.sec.asc"
            );

            let (decrypt_key, _headers) = SignedSecretKey::from_string(key_input).unwrap();
            let _ = KEY.set(decrypt_key);
    },
    |data: &[u8]| {
    let message_res = Message::from_bytes(data);

    match message_res {
        // not interested further
        Err(_) => return,
        // perform checks
        Ok(message) => {

            // At the moment, this harness focuses on SEIPDv1 and aborts early on other messages
            // The intention is to partially guide the fuzzer towards the relevant functionality
            let Message::Encrypted { ref edata, .. } = &message else {
                return;
            };
            let Edata::SymEncryptedProtectedData { reader } = &edata else {
                return;
            };
            if reader.config() != &ProtectedDataConfig::Seipd(SymEncryptedProtectedDataConfig::V1) {
                return;
            }

            // attempt decryption
            let decryption_res = message.decrypt(&Password::empty(), KEY.get().unwrap());

            match decryption_res {
                // the fuzzer is not clever enough to encrypt anything to the public key
                // through the default mutatation mechanisms, but our custom mutator
                // can generate valid messages
                Ok(mut decryption) => {
                    #[cfg(feature = "fuzzer_verbose1")]
                    println!("fuzzer: successful decryption: {:?}", decryption);

                    let _ = decryption.literal_data_header();
                    let _ = decryption.packet_header();

                    // If this decrypted message is compressed, decompress it
                    if decryption.is_compressed() {
                        let _decompressed = decryption.decompress();
                    } else {
                        let _ = decryption.as_data_vec();
                    }
                },
                // not interesting
                Err(_err) => {
                    #[cfg(feature = "fuzzer_verbose1")]
                    println!("fuzzer: err - {}", _err);
                }
            }
        }
    }
});
