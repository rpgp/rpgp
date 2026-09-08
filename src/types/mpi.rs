use std::io::{self, BufRead};

use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use crypto_bigint::{NonZero, Odd};
use rsa::BoxedUint;

use crate::{
    errors::{InvalidInputSnafu, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

/// Number of bits we accept when reading or writing MPIs.
/// The value is the same as gnupgs.
const MAX_EXTERN_MPI_BITS: u16 = 16384;

/// Represents an owned MPI value.
/// The inner value is ready to be serialized, without the need to strip leading zeros.
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-multiprecision-integers>
#[derive(Default, Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Mpi(#[debug("{}", hex::encode(_0))] Bytes);

impl Mpi {
    /// Wraps the given bytes as an MPI, must be normalized before
    /// Avoid if possible.
    ///
    /// Only used internally to handle reversed Curve 25519 "Mpis".
    pub(crate) fn from_raw(bytes: Bytes) -> Self {
        Mpi(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parses the given reader as an MPI.
    ///
    /// The buffer is expected to be length-prefixed.
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let len_bits = i.read_be_u16()?;

        if len_bits > MAX_EXTERN_MPI_BITS {
            return Err(InvalidInputSnafu.build());
        }

        let len_bytes = (len_bits + 7) >> 3;

        let mut n = i.take_bytes(usize::from(len_bytes))?.freeze();
        let n_stripped = match leading_zeros_offset(&n) {
            Some(offset) => {
                n.advance(offset);
                n
            }
            None => Bytes::new(),
        };

        Ok(Mpi(n_stripped))
    }

    /// Represent the data in `raw` as an Mpi.
    /// Note that `raw` is not expected to be length-prefixed!
    ///
    /// Strips leading zeros.
    pub fn from_slice(raw: &[u8]) -> Self {
        Self(strip_leading_zeros(raw).to_vec().into())
    }
}

/// Returns the bit length of a given slice.
#[inline]
fn bit_size(val: &[u8]) -> usize {
    if val.is_empty() {
        0
    } else {
        (val.len() * 8) - val[0].leading_zeros() as usize
    }
}

#[inline]
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    match leading_zeros_offset(bytes) {
        Some(offset) => &bytes[offset..],
        None => &[],
    }
}

#[inline]
fn leading_zeros_offset(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|b| b != &0)
}

impl AsRef<[u8]> for Mpi {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Serialize for Mpi {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
        let bytes = &self.0;
        let size = bit_size(bytes);
        w.write_u16::<BigEndian>(size as u16)?;
        w.write_all(bytes)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        2 + self.0.len()
    }
}

impl From<BoxedUint> for Mpi {
    fn from(other: BoxedUint) -> Self {
        Self::from(&other)
    }
}

impl From<&BoxedUint> for Mpi {
    fn from(other: &BoxedUint) -> Self {
        // TODO(baloo): are Mpi used for private keys?
        //              This is only meant to be used for public keys
        Mpi(other.to_be_bytes_trimmed_vartime().into())
    }
}

impl From<NonZero<BoxedUint>> for Mpi {
    fn from(other: NonZero<BoxedUint>) -> Self {
        Self::from(other.get())
    }
}

impl From<&NonZero<BoxedUint>> for Mpi {
    fn from(other: &NonZero<BoxedUint>) -> Self {
        Self::from(other.as_ref())
    }
}

impl From<Odd<BoxedUint>> for Mpi {
    fn from(other: Odd<BoxedUint>) -> Self {
        Mpi(other.to_be_bytes().into())
    }
}

impl From<&Odd<BoxedUint>> for Mpi {
    fn from(other: &Odd<BoxedUint>) -> Self {
        Mpi(other.to_be_bytes().into())
    }
}

impl From<&Mpi> for BoxedUint {
    fn from(other: &Mpi) -> Self {
        let bytes = other.as_ref();
        BoxedUint::from_be_slice(
            bytes,
            (bytes.len() * 8)
                .try_into()
                .expect("invariant violated, MPI should only be MAX_EXTERN_MPI_BITS long"),
        )
        .expect("invariant violated, MPI should only be MAX_EXTERN_MPI_BITS long")
    }
}

impl From<Mpi> for BoxedUint {
    fn from(other: Mpi) -> Self {
        Self::from(&other)
    }
}

impl TryFrom<&Mpi> for NonZero<BoxedUint> {
    type Error = signature::Error;

    fn try_from(other: &Mpi) -> Result<Self, Self::Error> {
        Self::new(BoxedUint::from(other))
            .into_option()
            .ok_or(signature::Error::new())
    }
}

impl TryFrom<Mpi> for NonZero<BoxedUint> {
    type Error = signature::Error;

    fn try_from(other: Mpi) -> Result<Self, Self::Error> {
        Self::try_from(&other)
    }
}

impl TryFrom<&Mpi> for Odd<BoxedUint> {
    type Error = signature::Error;

    fn try_from(other: &Mpi) -> Result<Self, Self::Error> {
        Self::new(BoxedUint::from(other))
            .into_option()
            .ok_or(signature::Error::new())
    }
}

impl TryFrom<Mpi> for Odd<BoxedUint> {
    type Error = signature::Error;

    fn try_from(other: Mpi) -> Result<Self, Self::Error> {
        Self::try_from(&other)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    impl Arbitrary for Mpi {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            proptest::collection::vec(0u8..255, 1..500)
                .prop_map(|v| Mpi::from_slice(&v))
                .boxed()
        }
    }

    #[test]
    fn test_mpi() {
        // Decode the number `511` (`0x1FF` in hex).
        assert_eq!(
            Mpi::try_from_reader(&mut &[0x00, 0x09, 0x01, 0xFF][..]).unwrap(),
            Mpi::from_slice(&[0x01, 0xFF][..])
        );

        // Decode the number `2^255 + 7`.
        assert_eq!(
            Mpi::try_from_reader(
                &mut &[
                    0x01, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07
                ][..]
            )
            .unwrap(),
            Mpi::from_slice(
                &[
                    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0x07
                ][..]
            )
        );
    }

    #[test]
    fn test_bignum_mpi() {
        let fixtures = [
            ("b4a71b058ac8aa1ddc453ab2663331c38f7645542815ac189a9af56d0e07a615469d3e08849650e03026d49259423cf00d089931cd700fd3a6e940bf83c81406e142a4b0a86f00738c7e1a9ff1b709f6bccc6cf900d0113a8e62e53d63be0a05105755b9efc6a4098c362c73fb422d40187d8e2382e88624d72caffceb13cec8fa0079c7d17883a46a1336471ab5be8cbb555c5d330d7fadb43318fa73b584edac312fa3302886bb5d04a05da3be2676c1fb94b3cf5c19d598659c3a7728ebab95f71721b662ac46aa9910726fe576d438f789c5ce2448f54546f254da814bcae1c35ee44b171e870ffa6403167a10e68573bdf155549274b431ff8e2418b627", "0800b4a71b058ac8aa1ddc453ab2663331c38f7645542815ac189a9af56d0e07a615469d3e08849650e03026d49259423cf00d089931cd700fd3a6e940bf83c81406e142a4b0a86f00738c7e1a9ff1b709f6bccc6cf900d0113a8e62e53d63be0a05105755b9efc6a4098c362c73fb422d40187d8e2382e88624d72caffceb13cec8fa0079c7d17883a46a1336471ab5be8cbb555c5d330d7fadb43318fa73b584edac312fa3302886bb5d04a05da3be2676c1fb94b3cf5c19d598659c3a7728ebab95f71721b662ac46aa9910726fe576d438f789c5ce2448f54546f254da814bcae1c35ee44b171e870ffa6403167a10e68573bdf155549274b431ff8e2418b627"),
            ("00e57192fa7bd6abd7d01331f0411eebff4651290af1329369cc3bb3b8ccbd7ba6e352400c3f64f637967e24524921ee04f1e0a79168781f0bec9029e34c8a1fb1c328a4b8d74c31429616a6ff4707bb56b71ab66643243087c8ff0d0c4883b3473c56deece9a83dbd06eef09fac3558003ae45f8898b8a9490aa79672eebdd7d985d051d62698f2da7eee33ba740e30fc5a93c3f16ca1490dfd62b84ba016c9da7c087a28a4e97d8af79c6b638bc22f20a8b5953bb83caa3dddaaf1d0dc15a3f7ed47870174af74e5308b856138771a10019fe4374389eb89d2280776e33fa2dd3526cec35cd86a9cf6c94253fe00c4b8a87a36451745116456833bb1a237", "07f0e57192fa7bd6abd7d01331f0411eebff4651290af1329369cc3bb3b8ccbd7ba6e352400c3f64f637967e24524921ee04f1e0a79168781f0bec9029e34c8a1fb1c328a4b8d74c31429616a6ff4707bb56b71ab66643243087c8ff0d0c4883b3473c56deece9a83dbd06eef09fac3558003ae45f8898b8a9490aa79672eebdd7d985d051d62698f2da7eee33ba740e30fc5a93c3f16ca1490dfd62b84ba016c9da7c087a28a4e97d8af79c6b638bc22f20a8b5953bb83caa3dddaaf1d0dc15a3f7ed47870174af74e5308b856138771a10019fe4374389eb89d2280776e33fa2dd3526cec35cd86a9cf6c94253fe00c4b8a87a36451745116456833bb1a237"),
        ];

        for (i, (raw, encoded)) in fixtures.iter().enumerate() {
            println!("fixture {i}");
            let n = hex::decode(raw).unwrap();

            let n_big = BoxedUint::from_be_slice(&n, (n.len() * 8).try_into().unwrap()).unwrap();
            let n_mpi: Mpi = n_big.clone().into();
            let mut n_encoded = Vec::new();
            n_mpi.to_writer(&mut n_encoded).unwrap();

            assert_eq!(&n_encoded, &hex::decode(encoded).unwrap());

            let n_big2 = Mpi::try_from_reader(&mut &n_encoded[..]).unwrap();
            assert_eq!(n_big, BoxedUint::from(n_big2));
        }
    }

    #[test]
    fn test_strip_leading_zeros_with_all_zeros() {
        let buf = [0u8, 0u8, 0u8];
        let stripped: &[u8] = strip_leading_zeros(&buf[..]);
        assert!(stripped.is_empty());
    }

    proptest! {
        #[test]
        fn mpi_bytes_wite_le(m: Mpi) {
            let mut buf = Vec::new();
            m.to_writer(&mut buf)?;

            prop_assert_eq!(m.write_len(), buf.len());
        }

        #[test]
        fn mpi_bytes_roundtrip(m: Mpi) {
            let mut buf = Vec::new();
            m.to_writer(&mut buf)?;

            let m_back = Mpi::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(m, m_back);
        }
    }
}
