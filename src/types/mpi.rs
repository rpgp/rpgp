use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use nom::number::streaming::be_u16;
use nom::{Err, InputIter, InputTake};
use num_bigint::BigUint;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{self, Error, IResult};
use crate::ser::Serialize;
use crate::util::{bit_size, strip_leading_zeros, strip_leading_zeros_vec};

/// Number of bits we accept when reading or writing MPIs.
/// The value is the same as gnupgs.
const MAX_EXTERN_MPI_BITS: u32 = 16384;

/// Parse Multi Precision Integers
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-multiprecision-integers>
///
/// # Examples
///
/// ```rust
/// use pgp::types::mpi;
/// use pgp::types::MpiRef;
///
/// // Decode the number `1`.
/// assert_eq!(
///     mpi(&[0x00, 0x01, 0x01][..]).unwrap(),
///     (&b""[..], MpiRef::from_slice(&[1][..]))
/// );
/// ```
pub fn mpi(input: &[u8]) -> IResult<&[u8], MpiRef<'_>> {
    let (number, len) = be_u16(input)?;

    let bits = u32::from(len);
    let len_actual = (bits + 7) >> 3;

    if len_actual > MAX_EXTERN_MPI_BITS {
        Err(Err::Error(Error::InvalidInput))
    } else {
        // same as take!
        let cnt = len_actual as usize;
        match number.slice_index(cnt) {
            Err(needed) => Err(nom::Err::Incomplete(needed)),
            Ok(index) => {
                let (rest, n) = number.take_split(index);
                let n_stripped: MpiRef<'_> = MpiRef::from_slice(strip_leading_zeros(n));

                Ok((rest, n_stripped))
            }
        }
    }
}

/// Represents an owned MPI value.
/// The inner value is ready to be serialized, without the need to strip leading zeros.
#[derive(Default, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, derive_more::Debug)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct Mpi(
    #[debug("{}", hex::encode(_0))]
    #[cfg_attr(
        test,
        proptest(strategy = "mpi_gen()", filter = "|mpi| !mpi.is_empty()")
    )]
    Vec<u8>,
);

#[cfg(test)]
proptest::prop_compose! {
    fn mpi_gen()(mut v in proptest::collection::vec(0u8..255, 1..500)) -> Vec<u8> {
        strip_leading_zeros_vec(&mut v);
        v
    }
}

/// Represents a borrowed MPI value.
/// The inner value is ready to be serialized, without the need to strip leading zeros.
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct MpiRef<'a>(#[debug("{}", hex::encode(_0))] &'a [u8]);

impl AsRef<[u8]> for Mpi {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Mpi {
    pub fn from_raw(mut v: Vec<u8>) -> Self {
        strip_leading_zeros_vec(&mut v);
        Mpi(v)
    }

    /// Strips leading zeros.
    pub fn from_slice(raw: &[u8]) -> Self {
        Mpi(strip_leading_zeros(raw).to_vec())
    }

    pub fn as_ref(&self) -> MpiRef<'_> {
        MpiRef(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for Mpi {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for MpiRef<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> MpiRef<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        MpiRef(strip_leading_zeros(slice))
    }

    pub fn to_owned(&self) -> Mpi {
        Mpi(self.0.to_owned())
    }

    pub fn parse(slice: &'a [u8]) -> IResult<&'a [u8], MpiRef<'a>> {
        mpi(slice)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }
}

impl Serialize for Mpi {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> errors::Result<()> {
        MpiRef(&self.0).to_writer(w)
    }
    fn write_len(&self) -> usize {
        MpiRef(&self.0).write_len()
    }
}

impl Serialize for MpiRef<'_> {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> errors::Result<()> {
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

impl From<BigUint> for Mpi {
    fn from(other: BigUint) -> Self {
        Mpi(other.to_bytes_be())
    }
}

impl From<Mpi> for BigUint {
    fn from(other: Mpi) -> Self {
        BigUint::from_bytes_be(other.as_bytes())
    }
}

impl<'a> From<&'a Mpi> for BigUint {
    fn from(other: &'a Mpi) -> Self {
        BigUint::from_bytes_be(other.as_bytes())
    }
}

impl<'a> From<MpiRef<'a>> for BigUint {
    fn from(other: MpiRef<'a>) -> Self {
        BigUint::from_bytes_be(other.as_bytes())
    }
}

impl<'a, 'b> From<&'b MpiRef<'a>> for BigUint {
    fn from(other: &'b MpiRef<'a>) -> Self {
        BigUint::from_bytes_be(other.as_bytes())
    }
}

impl<'a> From<&'a BigUint> for Mpi {
    fn from(other: &'a BigUint) -> Self {
        Mpi(other.to_bytes_be())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;

    #[test]
    fn test_mpi() {
        // Decode the number `511` (`0x1FF` in hex).
        assert_eq!(
            mpi(&[0x00, 0x09, 0x01, 0xFF][..]).unwrap(),
            (&b""[..], MpiRef::from_slice(&[0x01, 0xFF][..]))
        );

        // Decode the number `2^255 + 7`.
        assert_eq!(
            mpi(&[
                0x01, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x07
            ][..])
            .unwrap(),
            (
                &b""[..],
                MpiRef::from_slice(
                    &[
                        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0x07
                    ][..]
                )
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

            let n_big = BigUint::from_bytes_be(&n);
            let n_mpi: Mpi = n_big.clone().into();
            let mut n_encoded = Vec::new();
            n_mpi.to_writer(&mut n_encoded).unwrap();

            assert_eq!(&n_encoded, &hex::decode(encoded).unwrap());

            let (rest, n_big2) = mpi(&n_encoded).unwrap();
            assert_eq!(rest.len(), 0);
            assert_eq!(n_big, n_big2.into());
        }
    }

    proptest! {
        #[test]
        fn mpi_roundtrip(m: Mpi) {
            let mut buf = Vec::new();
            m.to_writer(&mut buf)?;

            let (i, m_back) = mpi(&buf)?;
            prop_assert!(i.is_empty());
            prop_assert_eq!(m.as_ref(), m_back);
        }
    }
}
