//! Tests for skipping public subkeys that fail to parse.
//!
//! A transferable public key that contains a public subkey packet rPGP can't parse should stay
//! usable for its other keys. The subkey is skipped, together with its signatures.

use std::io::Read;

use pgp::{
    armor,
    composed::{
        Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
        SubkeyParamsBuilder,
    },
    errors::Error,
    packet::{Packet, PacketParser},
    ser::Serialize,
    types::{KeyDetails, KeyVersion, PublicParams, Tag},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const ECDH: u8 = 18;
const ECDSA: u8 = 19;
const EDDSA_LEGACY: u8 = 22;

/// OID 1.3.6.1.4.1.37210.99, a curve that rPGP doesn't know (as in the "Mock PQ subkey" tests
/// of the OpenPGP interoperability test suite)
const UNKNOWN_CURVE: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x5a, 0x63];

/// Key material that isn't an MPI
const OPAQUE: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

/// The same bytes, as an MPI
const MPI: &[u8] = &[0x00, 0x20, 0xde, 0xad, 0xbe, 0xef];

/// ECDH KDF parameters: SHA256, AES128
const KDF: &[u8] = &[0x03, 0x01, 0x08, 0x07];

/// A v4 key packet body for an EC algorithm on `UNKNOWN_CURVE`, followed by `material`
fn ec_key_body(alg: u8, material: &[u8]) -> Vec<u8> {
    let mut body = vec![4, 0x5e, 0x0b, 0xe1, 0x00, alg, UNKNOWN_CURVE.len() as u8];
    body.extend_from_slice(UNKNOWN_CURVE);
    body.extend_from_slice(material);
    body
}

/// A packet with an OpenPGP format header
fn packet(tag: Tag, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 192);
    let mut p = vec![0xc0 | u8::from(tag), body.len() as u8];
    p.extend_from_slice(body);
    p
}

/// A public subkey packet that fails to parse
fn bad_subkey(alg: u8) -> Vec<u8> {
    packet(Tag::PublicSubkey, &ec_key_body(alg, OPAQUE))
}

/// A v4 key with two signing subkeys, split into its (serialized) packets
fn key_packets() -> (SignedSecretKey, Vec<Vec<u8>>) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let subkey = || {
        SubkeyParamsBuilder::default()
            .version(KeyVersion::V4)
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .build()
            .unwrap()
    };

    let key = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V4)
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .primary_user_id("Alice <alice@example.org>".into())
        .subkey(subkey())
        .subkey(subkey())
        .build()
        .unwrap()
        .generate(&mut rng)
        .unwrap();

    let public = SignedPublicKey::from(key.clone()).to_bytes().unwrap();
    (key, split(&public))
}

/// Split serialized packets (serializing a `Packet` includes its header)
fn split(bytes: &[u8]) -> Vec<Vec<u8>> {
    PacketParser::new(bytes)
        .map(|p| p.unwrap().to_bytes().unwrap())
        .collect()
}

/// The packets of `key_packets()`: primary, user id, its binding, then each subkey with one
/// binding signature
struct Parts {
    head: Vec<u8>,
    sub1: Vec<u8>,
    sub2: Vec<u8>,
}

fn parts() -> (SignedSecretKey, Parts) {
    let (key, p) = key_packets();
    assert_eq!(p.len(), 7, "primary, user id, sig, 2 x (subkey, sig)");
    let parts = Parts {
        head: p[..3].concat(),
        sub1: p[3..5].concat(),
        sub2: p[5..7].concat(),
    };
    (key, parts)
}

/// A binding signature to put after a bad subkey (any signature will do: if it was wrongly
/// attached to a neighboring subkey, that subkey would gain a signature)
fn some_sig(parts: &Parts) -> Vec<u8> {
    split(&parts.sub1)[1].clone()
}

#[test]
fn skip_bad_subkey_for_each_algorithm() {
    let (_, parts) = parts();

    for alg in [ECDSA, EDDSA_LEGACY, ECDH] {
        let input = [
            parts.head.clone(),
            parts.sub1.clone(),
            bad_subkey(alg),
            some_sig(&parts),
        ]
        .concat();

        let key = SignedPublicKey::from_bytes(&*input).expect("parse");
        assert_eq!(key.public_subkeys.len(), 1, "alg {alg}");
        key.verify_bindings().expect("bindings");

        // Serializing drops the skipped subkey and its signature, nothing else.
        assert_eq!(
            key.to_bytes().unwrap(),
            [parts.head.clone(), parts.sub1.clone()].concat()
        );
    }
}

#[test]
fn keep_unknown_curve_subkey_with_mpi() {
    // An unknown curve alone is fine: if the key material is an MPI, the subkey is kept as
    // unsupported. Only subkeys that fail to parse are skipped.
    let (_, parts) = parts();

    for (alg, material) in [
        (ECDSA, MPI.to_vec()),
        (EDDSA_LEGACY, MPI.to_vec()),
        (ECDH, [MPI, KDF].concat()),
    ] {
        let input = [
            parts.head.clone(),
            packet(Tag::PublicSubkey, &ec_key_body(alg, &material)),
            some_sig(&parts),
        ]
        .concat();

        let key = SignedPublicKey::from_bytes(&*input).expect("parse");
        assert_eq!(key.public_subkeys.len(), 1, "alg {alg}");
        assert!(matches!(
            key.public_subkeys[0].key.public_params(),
            PublicParams::ECDSA(_) | PublicParams::EdDSALegacy(_) | PublicParams::ECDH(_)
        ));
        assert_eq!(key.to_bytes().unwrap(), input);
    }
}

#[test]
fn skip_bad_subkey_between_good_ones() {
    let (_, parts) = parts();

    let input = [
        parts.head.clone(),
        parts.sub1.clone(),
        bad_subkey(ECDSA),
        some_sig(&parts),
        some_sig(&parts),
        parts.sub2.clone(),
    ]
    .concat();

    let key = SignedPublicKey::from_bytes(&*input).expect("parse");

    let expected = SignedPublicKey::from_bytes(
        &*[parts.head.clone(), parts.sub1.clone(), parts.sub2.clone()].concat(),
    )
    .unwrap();

    // Each good subkey has exactly its own binding signature: the skipped subkey's
    // signatures were not attached to the first one.
    assert_eq!(key, expected);
    assert_eq!(key.public_subkeys[0].signatures.len(), 1);
    assert_eq!(key.public_subkeys[1].signatures.len(), 1);
    key.verify_bindings().expect("bindings");
}

#[test]
fn skip_consecutive_and_trailing_bad_subkeys() {
    let (_, parts) = parts();

    let cases = [
        // two bad subkeys in a row, between good ones
        vec![
            parts.sub1.clone(),
            bad_subkey(ECDSA),
            some_sig(&parts),
            bad_subkey(ECDH),
            some_sig(&parts),
            parts.sub2.clone(),
        ],
        // bad subkeys without signatures
        vec![
            bad_subkey(ECDSA),
            bad_subkey(EDDSA_LEGACY),
            parts.sub1.clone(),
            parts.sub2.clone(),
        ],
        // a bad subkey as the last packet
        vec![parts.sub1.clone(), parts.sub2.clone(), bad_subkey(ECDH)],
    ];

    for (i, subkeys) in cases.into_iter().enumerate() {
        let input = [vec![parts.head.clone()], subkeys].concat().concat();
        let key = SignedPublicKey::from_bytes(&*input).expect("parse");
        assert_eq!(key.public_subkeys.len(), 2, "case {i}");
        key.verify_bindings().expect("bindings");
    }
}

#[test]
fn only_bad_subkeys() {
    let (_, parts) = parts();

    let input = [parts.head.clone(), bad_subkey(ECDSA), some_sig(&parts)].concat();
    let key = SignedPublicKey::from_bytes(&*input).expect("parse");
    assert!(key.public_subkeys.is_empty());
    key.verify_bindings().expect("bindings");
}

#[test]
fn keyring_continues_after_bad_subkey() {
    let (key1, parts) = parts();

    let input = [
        parts.head.clone(),
        bad_subkey(ECDSA),
        some_sig(&parts),
        parts.head.clone(),
        parts.sub1.clone(),
    ]
    .concat();

    let keys: Vec<_> = SignedPublicKey::from_bytes_many(&*input)
        .unwrap()
        .collect::<Result<_, _>>()
        .expect("parse");

    assert_eq!(keys.len(), 2);
    assert!(keys[0].public_subkeys.is_empty());
    assert_eq!(keys[1].public_subkeys.len(), 1);
    assert_eq!(keys[1].fingerprint(), key1.fingerprint());
}

#[test]
fn bad_primary_key_is_rejected() {
    let (_, parts) = parts();
    let rest = split(&parts.head)[1..].concat();

    let input = [packet(Tag::PublicKey, &ec_key_body(ECDSA, OPAQUE)), rest].concat();
    SignedPublicKey::from_bytes(&*input).expect_err("bad primary key");
}

#[test]
fn bad_secret_subkey_is_rejected() {
    // Skipping secret subkeys could silently lose secret key material, so they stay strict.
    let (key, _) = parts();
    let tsk = key.to_bytes().unwrap();

    // The public part fails to parse, followed by "unencrypted" (S2K usage 0) secret data.
    let body = [
        ec_key_body(ECDSA, OPAQUE),
        vec![0x00, 0x00, 0x08, 0x01, 0x00, 0x01],
    ]
    .concat();
    let input = [tsk.clone(), packet(Tag::SecretSubkey, &body)].concat();

    SignedSecretKey::from_bytes(&*tsk).expect("valid key");
    SignedSecretKey::from_bytes(&*input).expect_err("bad secret subkey");
}

#[test]
fn bad_public_subkey_in_secret_key_is_skipped() {
    let (key, _) = parts();
    let tsk = key.to_bytes().unwrap();

    let input = [tsk.clone(), bad_subkey(ECDSA)].concat();

    let parsed = SignedSecretKey::from_bytes(&*input).expect("parse");
    assert_eq!(parsed.to_bytes().unwrap(), tsk);
}

#[test]
fn v3_key_with_bad_subkey_is_rejected() {
    // v3 keys can't have subkeys, whether they parse or not
    let mut armored = Vec::new();
    std::fs::File::open("./tests/pgp6/expiring.pgp")
        .unwrap()
        .read_to_end(&mut armored)
        .unwrap();
    let mut v3 = Vec::new();
    armor::Dearmor::new(&*armored).read_to_end(&mut v3).unwrap();

    let key = SignedPublicKey::from_bytes(&*v3).expect("valid v3 key");
    assert_eq!(key.primary_key.version(), KeyVersion::V3);

    let input = [v3, bad_subkey(ECDSA)].concat();
    SignedPublicKey::from_bytes(&*input).expect_err("v3 key with subkey");
}

#[test]
fn error_marks_only_public_subkeys() {
    // The packet parser reports a public subkey that fails to parse as `InvalidPublicSubkey`,
    // inside the same `InvalidPacketContent` as before.
    let marked = |tag| {
        let p = packet(tag, &ec_key_body(ECDSA, OPAQUE));
        let res: Vec<Result<Packet, Error>> = PacketParser::new(&*p).collect();
        assert_eq!(res.len(), 1);
        match &res[0] {
            Err(Error::InvalidPacketContent { source }) => {
                matches!(**source, Error::InvalidPublicSubkey { .. })
            }
            other => panic!("unexpected result for {tag:?}: {other:?}"),
        }
    };

    assert!(marked(Tag::PublicSubkey));
    assert!(!marked(Tag::PublicKey));

    // A point that is not on the curve is an `EllipticCurve` error, which is not marked: those
    // packets are already dropped earlier, by the existing handling of "soft" errors.
    let p = p256_off_curve_subkey();
    let res: Vec<Result<Packet, Error>> = PacketParser::new(&*p).collect();
    assert!(matches!(
        &res[..],
        [Err(Error::InvalidPacketContent { source })] if matches!(**source, Error::EllipticCurve { .. })
    ));
}

/// A P-256 public subkey packet whose point is not on the curve
fn p256_off_curve_subkey() -> Vec<u8> {
    const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    // MPI (515 bits) of an uncompressed point 0x04 || x || y, with x = y = 1
    let mut point = vec![0x02, 0x03, 0x04];
    point.extend([0u8; 31]);
    point.push(1);
    point.extend([0u8; 31]);
    point.push(1);

    let body = [
        vec![4, 0x5e, 0x0b, 0xe1, 0x00, ECDSA, P256.len() as u8],
        P256.to_vec(),
        point,
    ]
    .concat();
    packet(Tag::PublicSubkey, &body)
}

#[test]
fn off_curve_subkey_is_still_dropped() {
    // Not changed by skipping bad subkeys: this subkey is dropped as before, by the existing
    // handling of `EllipticCurve` errors (its signatures are not dropped along with it).
    let (_, parts) = parts();

    let input = [
        parts.head.clone(),
        parts.sub1.clone(),
        p256_off_curve_subkey(),
        some_sig(&parts),
        parts.sub2.clone(),
    ]
    .concat();

    let key = SignedPublicKey::from_bytes(&*input).expect("parse");
    let expected = SignedPublicKey::from_bytes(
        &*[parts.head.clone(), parts.sub1.clone(), parts.sub2.clone()].concat(),
    )
    .unwrap();

    let fingerprints = |k: &SignedPublicKey| {
        k.public_subkeys
            .iter()
            .map(|s| s.key.fingerprint())
            .collect::<Vec<_>>()
    };
    assert_eq!(fingerprints(&key), fingerprints(&expected));
    key.verify_bindings().expect("bindings");
}

#[test]
fn bad_signature_after_bad_subkey_rejects_key() {
    // Only subkey packets are skipped. A signature packet that fails to parse still rejects the
    // whole key, also right after a skipped subkey. So the good subkey after it is not lost
    // silently: the key fails to parse, as it does for a bad signature after a good subkey.
    let (_, parts) = parts();

    // v4 signature with an empty hashed subpacket
    let bad_sig = packet(
        Tag::Signature,
        &[4, 0x18, 1, 8, 0, 2, 0, 2, 0, 0, 0xab, 0xcd, 0x00, 0x08, 1],
    );

    let input = [
        parts.head.clone(),
        bad_subkey(ECDSA),
        bad_sig.clone(),
        parts.sub1.clone(),
    ]
    .concat();
    SignedPublicKey::from_bytes(&*input).expect_err("bad signature");

    let input = [
        parts.head.clone(),
        parts.sub1.clone(),
        bad_sig,
        parts.sub2.clone(),
    ]
    .concat();
    SignedPublicKey::from_bytes(&*input).expect_err("bad signature");
}
