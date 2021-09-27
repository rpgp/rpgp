use zeroize::Zeroize;

use crate::crypto::public_key::PublicKeyAlgorithm;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum ECCCurve {
    Curve25519,
    Ed25519,
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Secp256k1,
}

impl ECCCurve {
    /// Standard name
    pub fn name(&self) -> &str {
        match *self {
            ECCCurve::Curve25519 => "Curve25519",
            ECCCurve::Ed25519 => "Ed25519",
            ECCCurve::P256 => "NIST P-256",
            ECCCurve::P384 => "NIST P-384",
            ECCCurve::P521 => "NIST P-521",
            ECCCurve::BrainpoolP256r1 => "brainpoolP256r1",
            ECCCurve::BrainpoolP384r1 => "brainpoolP384r1",
            ECCCurve::BrainpoolP512r1 => "brainpool5126r1",
            ECCCurve::Secp256k1 => "secp256k1",
        }
    }

    /// IETF formatted OID
    pub fn oid_str(&self) -> &str {
        match *self {
            ECCCurve::Curve25519 => "1.3.6.1.4.1.3029.1.5.1",
            ECCCurve::Ed25519 => "1.3.6.1.4.1.11591.15.1",
            ECCCurve::P256 => "1.2.840.10045.3.1.7",
            ECCCurve::P384 => "1.3.132.0.34",
            ECCCurve::P521 => "1.3.132.0.35",
            ECCCurve::BrainpoolP256r1 => "1.3.36.3.3.2.8.1.1.7",
            ECCCurve::BrainpoolP384r1 => "1.3.36.3.3.2.8.1.1.11",
            ECCCurve::BrainpoolP512r1 => "1.3.36.3.3.2.8.1.1.13",
            ECCCurve::Secp256k1 => "1.3.132.0.10",
        }
    }

    /// Nominal bit length of the curve
    pub fn nbits(&self) -> u16 {
        match *self {
            ECCCurve::Curve25519 => 255,
            ECCCurve::Ed25519 => 255,
            ECCCurve::P256 => 256,
            ECCCurve::P384 => 384,
            ECCCurve::P521 => 521,
            ECCCurve::BrainpoolP256r1 => 256,
            ECCCurve::BrainpoolP384r1 => 384,
            ECCCurve::BrainpoolP512r1 => 512,
            ECCCurve::Secp256k1 => 256,
        }
    }

    /// Alternative name of the curve
    pub fn alias(&self) -> Option<&str> {
        match *self {
            ECCCurve::Curve25519 => Some("cv25519"),
            ECCCurve::Ed25519 => Some("ed25519"),
            ECCCurve::P256 => Some("nistp256"),
            ECCCurve::P384 => Some("nistp384"),
            ECCCurve::P521 => Some("nistp521"),
            ECCCurve::BrainpoolP256r1 => None,
            ECCCurve::BrainpoolP384r1 => None,
            ECCCurve::BrainpoolP512r1 => None,
            ECCCurve::Secp256k1 => None,
        }
    }

    /// Required algo, or None for ECDSA/ECDH
    pub fn pubkey_algo(&self) -> Option<PublicKeyAlgorithm> {
        match *self {
            ECCCurve::Curve25519 => Some(PublicKeyAlgorithm::ECDH),
            ECCCurve::Ed25519 => Some(PublicKeyAlgorithm::EdDSA),
            ECCCurve::P256 => None,
            ECCCurve::P384 => None,
            ECCCurve::P521 => None,
            ECCCurve::BrainpoolP256r1 => None,
            ECCCurve::BrainpoolP384r1 => None,
            ECCCurve::BrainpoolP512r1 => None,
            ECCCurve::Secp256k1 => None,
        }
    }

    pub fn oid(&self) -> Vec<u8> {
        // the OID String is turned into bytes
        // with the first two numbers combined
        let mut id: Vec<u32> = self
            .oid_str()
            .split('.')
            // safe as we hard coded these
            .map(|v| v.parse::<u32>().expect("bad oid string"))
            .collect();

        // combine the first two
        let first = id.remove(0) * 40 + id.remove(0);
        id.insert(0, first);

        id.iter()
            .flat_map(|ident| asn1_der_object_id_val_enc(*ident))
            .collect()
    }
}
/// Get the right curve given an oid.
pub fn ecc_curve_from_oid(oid: &[u8]) -> Option<ECCCurve> {
    if ECCCurve::Curve25519.oid().as_slice() == oid {
        return Some(ECCCurve::Curve25519);
    }
    if ECCCurve::Ed25519.oid().as_slice() == oid {
        return Some(ECCCurve::Ed25519);
    }
    if ECCCurve::P256.oid().as_slice() == oid {
        return Some(ECCCurve::P256);
    }
    if ECCCurve::P384.oid().as_slice() == oid {
        return Some(ECCCurve::P384);
    }
    if ECCCurve::P521.oid().as_slice() == oid {
        return Some(ECCCurve::P521);
    }
    if ECCCurve::BrainpoolP256r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP256r1);
    }
    if ECCCurve::BrainpoolP384r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP384r1);
    }
    if ECCCurve::BrainpoolP512r1.oid().as_slice() == oid {
        return Some(ECCCurve::BrainpoolP512r1);
    }
    if ECCCurve::Secp256k1.oid().as_slice() == oid {
        return Some(ECCCurve::Secp256k1);
    }
    None
}

fn asn1_der_object_id_val_enc(val: u32) -> Vec<u8> {
    let mut val = val;
    let mut acc = vec![(val & 0x7f) as u8];
    val >>= 7;

    while val > 0 {
        acc.insert(0, (0x80 | (val & 0x7f)) as u8);
        val >>= 7;
    }

    acc
}

impl ToString for ECCCurve {
    fn to_string(&self) -> String {
        self.name().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecc_curve_to_oid() {
        assert_eq!(
            ECCCurve::P256.oid(),
            vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        );
        assert_eq!(ECCCurve::P384.oid(), vec![0x2B, 0x81, 0x04, 0x00, 0x22]);
    }

    #[test]
    fn test_ecc_curve_from_oid() {
        let one = vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        assert_eq!(ecc_curve_from_oid(one.as_slice()).unwrap(), ECCCurve::P256);

        assert_eq!(ecc_curve_from_oid(vec![1, 2, 3].as_slice()), None);
    }

    #[test]
    fn test_asn1_der_object_id_val_enc() {
        assert_eq!(asn1_der_object_id_val_enc(840), vec![0x86, 0x48]);
        assert_eq!(asn1_der_object_id_val_enc(113_549), vec![0x86, 0xf7, 0x0d]);
    }
}
