//! A SEIPD packet whose partial-length chain ends without a final fixed-length
//! part must yield an error when the message is read, never a panic.
//!
//! From <https://github.com/rpgp/rpgp/security/advisories/GHSA-cr9q-g3mm-67hg>

use pgp::{
    composed::{
        DecryptionOptions, Message, MessageBuilder, PlainSessionKey, RawSessionKey, TheRing,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        sym::SymmetricKeyAlgorithm,
    },
    types::Seipdv1ReadMode,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Body of the single SEIPD packet the builder emits (no ESK packets).
fn seipd_body(msg: &[u8]) -> &[u8] {
    match msg[1] {
        192..=223 => &msg[3..],
        255 => &msg[6..],
        _ => &msg[2..],
    }
}

/// Re-frame as power-of-two partial parts with no terminating fixed-length part.
fn unterminated(body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | 18];
    let mut rest = body;
    for k in (0..31).rev() {
        if rest.len() >= 1 << k {
            out.push(0xe0 | k as u8);
            out.extend_from_slice(&rest[..1 << k]);
            rest = &rest[1 << k..];
        }
    }
    out
}

fn read_all(bytes: &[u8], sk: PlainSessionKey) -> std::io::Result<Vec<u8>> {
    let msg = Message::from_bytes(bytes).expect("parse");
    let ring = TheRing {
        session_keys: vec![sk],
        decrypt_options: DecryptionOptions::new().set_seipdv1_read_mode(Seipdv1ReadMode::Streaming),
        ..Default::default()
    };
    match msg.decrypt_the_ring(ring, true) {
        Ok((mut m, _)) => m.as_data_vec(),
        Err(e) => Err(std::io::Error::other(e)),
    }
}

#[test]
fn seipd_v2_unterminated_partial_is_error() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let raw: RawSessionKey = vec![7u8; 16].into();
    // plaintext sized so the literal packet is exactly one 8 KiB chunk
    let body = (8000..8300)
        .find_map(|n| {
            let mut b = MessageBuilder::from_bytes("", vec![b'A'; n]).seipd_v2(
                &mut rng,
                SymmetricKeyAlgorithm::AES128,
                AeadAlgorithm::Ocb,
                ChunkSize::C8KiB,
            );
            b.set_session_key(raw.clone()).unwrap();
            let v = b.to_vec(&mut rng).unwrap();
            let body = seipd_body(&v).to_vec();
            (body.len() == 36 + 8192 + 16 + 16).then_some(body)
        })
        .unwrap();
    let mut padded = body;
    padded.extend(vec![0u8; 8300]);
    let res = read_all(&unterminated(&padded), PlainSessionKey::V6 { key: raw });
    assert!(res.is_err());
}

#[test]
fn seipd_v1_streaming_unterminated_partial_is_error() {
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let raw: RawSessionKey = vec![7u8; 16].into();
    // plaintext sized so literal + MDC is exactly 8192 bytes
    let body = (8000..8300)
        .find_map(|n| {
            let mut b = MessageBuilder::from_bytes("", vec![b'A'; n])
                .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
            b.set_session_key(raw.clone()).unwrap();
            let v = b.to_vec(&mut rng).unwrap();
            let body = seipd_body(&v).to_vec();
            (body.len() == 1 + 18 + 8192).then_some(body)
        })
        .unwrap();
    let sk = PlainSessionKey::V3_4 {
        sym_alg: SymmetricKeyAlgorithm::AES128,
        key: raw,
    };
    assert!(read_all(&unterminated(&body), sk).is_err());
}
