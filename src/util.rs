use std::convert::AsMut;
use std::io;
use std::ops::{Range, RangeFrom, RangeTo};

use byteorder::{BigEndian, WriteBytesExt};
use nom::types::{CompleteByteSlice, CompleteStr};
use nom::{
    self, be_u16, be_u32, be_u8, eol, is_alphanumeric, line_ending, Err, IResult, InputIter,
    InputLength, InputTake, Slice,
};
use num_bigint::BigUint;

use errors;

/// Number of bits we accept when reading or writing MPIs.
/// The value is the same as gnupgs.
const MAX_EXTERN_MPI_BITS: u32 = 16384;

#[inline]
pub fn u8_as_usize(a: u8) -> usize {
    a as usize
}

#[inline]
pub fn u16_as_usize(a: u16) -> usize {
    a as usize
}

#[inline]
pub fn u32_as_usize(a: u32) -> usize {
    a as usize
}

#[inline]
pub fn is_base64_token(c: u8) -> bool {
    is_alphanumeric(c) || c == b'/' || c == b'+' || c == b'=' || c == b'\n' || c == b'\r'
}

named!(pub prefixed<CompleteByteSlice, CompleteByteSlice>, do_parse!(
             many0!(line_ending)
    >> rest: take_while1!(is_base64_token)
    >> (rest)
));

/// Recognizes one or more body tokens
pub fn base64_token(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let input_length = input.input_len();
    if input_length == 0 {
        return Err(Err::Incomplete(nom::Needed::Unknown));
    }

    for (idx, item) in input.iter_indices() {
        if !is_base64_token(item) {
            if idx == 0 {
                return Err(Err::Error(error_position!(
                    input,
                    nom::ErrorKind::AlphaNumeric
                )));
            } else {
                return Ok((input.slice(idx..), input.slice(0..idx)));
            }
        }
    }
    Ok((input.slice(input_length..), input))
}

/// Parse Multi Precision Integers
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-3.2
///
/// # Examples
///
/// ```rust
/// use pgp::util::mpi;
///
/// // Decode the number `1`.
/// assert_eq!(
///     mpi(&[0x00, 0x01, 0x01][..]).unwrap(),
///     (&b""[..], &[1][..])
/// );
/// ```
///
///
pub fn mpi(input: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let (number, len) = be_u16(input)?;

    let bits = u32::from(len);
    let len_actual = ((bits + 7) >> 3) as u32;

    if len_actual > MAX_EXTERN_MPI_BITS {
        Err(Err::Error(error_position!(
            input,
            nom::ErrorKind::Custom(errors::MPI_TOO_LONG)
        )))
    } else {
        // same as take!
        let cnt = len_actual as usize;
        match number.slice_index(cnt) {
            None => nom::need_more(number, nom::Needed::Size(cnt)),
            Some(index) => {
                let (rest, n) = number.take_split(index);
                let n_stripped = strip_leading_zeros(n);

                Ok((rest, n_stripped))
            }
        }
    }
}

/// Parse an MPI and convert it to a [BigUint].
named!(pub mpi_big<BigUint>, map!(mpi, BigUint::from_bytes_be));

/// Convert a BigUint to an MPI for use in packets.
#[inline]
pub fn bignum_to_mpi(n: &BigUint) -> Vec<u8> {
    let mut buf = Vec::new();
    write_bignum_mpi(n, &mut buf).expect("writing to vec");

    buf
}

/// Returns the bit length of a given slice.
#[inline]
pub fn bit_size(val: &[u8]) -> usize {
    if val.is_empty() {
        0
    } else {
        (val.len() * 8) - val[0].leading_zeros() as usize
    }
}

/// Write a given [BigUint] to a given [io::Write] `writer`, according to the MPI defition.
pub fn write_bignum_mpi(n: &BigUint, w: &mut impl io::Write) -> errors::Result<()> {
    let size = n.bits();

    w.write_u16::<BigEndian>(size as u16)?;
    let bytes = n.to_bytes_be();

    // to stripping of leading zeroes, BigUint takes care of this for us

    w.write_all(&bytes)?;

    Ok(())
}

#[inline]
pub fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let offset = bytes.iter().position(|b| *b != 0).unwrap_or(0);
    &bytes[offset..]
}

/// Write a given byte slice, to the given [io::Write] `writer`, according to the MPI
/// definition.
/// If there are leading zeroes they are stripped.
pub fn write_mpi(bytes: &[u8], w: &mut impl io::Write) -> errors::Result<()> {
    let stripped_bytes = strip_leading_zeros(bytes);

    let size = bit_size(stripped_bytes);
    w.write_u16::<BigEndian>(size as u16)?;
    w.write_all(stripped_bytes)?;

    Ok(())
}

/// Convert a slice into an array.
pub fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

/// Parse a packet length.
#[rustfmt::skip]
named!(pub packet_length<usize>, do_parse!(
       olen: be_u8
    >>  len: switch!(value!(olen),
                     // One-Octet Lengths
                     0...191   => value!(olen as usize) |
                     // Two-Octet Lengths
                     192...254 => map!(be_u8, |a| {
                         ((olen as usize - 192) << 8) + 192 + a as usize
                     }) |
                     // Five-Octet Lengths
                     255       => map!(be_u32, u32_as_usize)
    )
    >> (len)
));

/// Write packet length, including the prefix.
pub fn write_packet_length(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 8384 {
        // nothing
    } else {
        writer.write_all(&[0xFF])?;
    }

    write_packet_len(len, writer)
}

/// Write the raw packet length.
pub fn write_packet_len(len: usize, writer: &mut impl io::Write) -> errors::Result<()> {
    if len < 192 {
        writer.write_all(&[len as u8])?;
    } else if len < 8384 {
        writer.write_all(&[(((len - 192) / 256) + 192) as u8, ((len - 192) % 256) as u8])?;
    } else {
        writer.write_u32::<BigEndian>(len as u32)?;
    }

    Ok(())
}

pub fn end_of_line(input: CompleteStr) -> IResult<CompleteStr, CompleteStr> {
    alt!(input, eof!() | eol)
}

/// Return the length of the remaining input.
// Adapted from https://github.com/Geal/nom/pull/684
#[inline]
pub fn rest_len<T>(input: T) -> IResult<T, usize>
where
    T: Slice<Range<usize>> + Slice<RangeFrom<usize>> + Slice<RangeTo<usize>>,
    T: InputLength,
{
    let len = input.input_len();
    Ok((input, len))
}

#[macro_export]
macro_rules! impl_try_from_into {
    ($enum_name:ident, $( $name:ident => $variant_type:ty ),*) => {
       $(
           impl $crate::try_from::TryFrom<$enum_name> for $variant_type {
               // TODO: Proper error
               type Err = $crate::errors::Error;

               fn try_from(other: $enum_name) -> ::std::result::Result<$variant_type, Self::Err> {
                   if let $enum_name::$name(value) = other {
                       Ok(value)
                   } else {
                      Err(format_err!("invalid packet type: {:?}", other))
                   }
               }
           }

           impl From<$variant_type> for $enum_name {
               fn from(other: $variant_type) -> $enum_name {
                   $enum_name::$name(other)
               }
           }
       )*
    }
}

pub fn write_string(val: &str) -> Vec<u8> {
    val.chars().map(|c| c as u8).collect()
}

pub fn read_string(raw: &[u8]) -> String {
    raw.iter().map(|c| *c as char).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpi() {
        // Decode the number `511` (`0x1FF` in hex).
        assert_eq!(
            mpi(&[0x00, 0x09, 0x01, 0xFF][..]).unwrap(),
            (&b""[..], &[0x01, 0xFF][..])
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
                &[
                    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0x07
                ][..]
            )
        );
    }

    #[test]
    fn test_read_string() {
        assert_eq!(read_string(b"hello"), "hello".to_string());
        assert_eq!(
            read_string(&[
                74, 252, 114, 103, 101, 110, 32, 77, 97, 114, 115, 99, 104, 97, 108, 108, 32, 60,
                106, 117, 101, 114, 103, 101, 110, 46, 109, 97, 114, 115, 99, 104, 97, 108, 108,
                64, 112, 114, 111, 109, 112, 116, 46, 100, 101, 62
            ]),
            "Jürgen Marschall <juergen.marschall@prompt.de>".to_string()
        );
    }

    #[test]
    fn test_write_string() {
        let vals = vec![
            vec![
                74, 252, 114, 103, 101, 110, 32, 77, 97, 114, 115, 99, 104, 97, 108, 108, 32, 60,
                106, 117, 101, 114, 103, 101, 110, 46, 109, 97, 114, 115, 99, 104, 97, 108, 108,
                64, 112, 114, 111, 109, 112, 116, 46, 100, 101, 62,
            ],
            hex::decode("4275527354664c6f3064203c73616d75656c2e726f7474406f72616e67652e66723e")
                .unwrap(),
        ];

        for val in &vals {
            assert_eq!(&write_string(&read_string(val)), val);
        }
    }

    #[test]
    fn test_write_packet_len() {
        let mut res = Vec::new();
        write_packet_len(1173, &mut res).unwrap();
        assert_eq!(hex::encode(res), "c3d5");
    }
    #[test]
    fn test_write_packet_length() {
        let mut res = Vec::new();
        write_packet_length(12870, &mut res).unwrap();
        assert_eq!(hex::encode(res), "ff00003246");
    }

    #[test]
    fn test_bignum_mpi() {
        let fixtures = vec![
            ("b4a71b058ac8aa1ddc453ab2663331c38f7645542815ac189a9af56d0e07a615469d3e08849650e03026d49259423cf00d089931cd700fd3a6e940bf83c81406e142a4b0a86f00738c7e1a9ff1b709f6bccc6cf900d0113a8e62e53d63be0a05105755b9efc6a4098c362c73fb422d40187d8e2382e88624d72caffceb13cec8fa0079c7d17883a46a1336471ab5be8cbb555c5d330d7fadb43318fa73b584edac312fa3302886bb5d04a05da3be2676c1fb94b3cf5c19d598659c3a7728ebab95f71721b662ac46aa9910726fe576d438f789c5ce2448f54546f254da814bcae1c35ee44b171e870ffa6403167a10e68573bdf155549274b431ff8e2418b627", "0800b4a71b058ac8aa1ddc453ab2663331c38f7645542815ac189a9af56d0e07a615469d3e08849650e03026d49259423cf00d089931cd700fd3a6e940bf83c81406e142a4b0a86f00738c7e1a9ff1b709f6bccc6cf900d0113a8e62e53d63be0a05105755b9efc6a4098c362c73fb422d40187d8e2382e88624d72caffceb13cec8fa0079c7d17883a46a1336471ab5be8cbb555c5d330d7fadb43318fa73b584edac312fa3302886bb5d04a05da3be2676c1fb94b3cf5c19d598659c3a7728ebab95f71721b662ac46aa9910726fe576d438f789c5ce2448f54546f254da814bcae1c35ee44b171e870ffa6403167a10e68573bdf155549274b431ff8e2418b627"),
            ("00e57192fa7bd6abd7d01331f0411eebff4651290af1329369cc3bb3b8ccbd7ba6e352400c3f64f637967e24524921ee04f1e0a79168781f0bec9029e34c8a1fb1c328a4b8d74c31429616a6ff4707bb56b71ab66643243087c8ff0d0c4883b3473c56deece9a83dbd06eef09fac3558003ae45f8898b8a9490aa79672eebdd7d985d051d62698f2da7eee33ba740e30fc5a93c3f16ca1490dfd62b84ba016c9da7c087a28a4e97d8af79c6b638bc22f20a8b5953bb83caa3dddaaf1d0dc15a3f7ed47870174af74e5308b856138771a10019fe4374389eb89d2280776e33fa2dd3526cec35cd86a9cf6c94253fe00c4b8a87a36451745116456833bb1a237", "07f0e57192fa7bd6abd7d01331f0411eebff4651290af1329369cc3bb3b8ccbd7ba6e352400c3f64f637967e24524921ee04f1e0a79168781f0bec9029e34c8a1fb1c328a4b8d74c31429616a6ff4707bb56b71ab66643243087c8ff0d0c4883b3473c56deece9a83dbd06eef09fac3558003ae45f8898b8a9490aa79672eebdd7d985d051d62698f2da7eee33ba740e30fc5a93c3f16ca1490dfd62b84ba016c9da7c087a28a4e97d8af79c6b638bc22f20a8b5953bb83caa3dddaaf1d0dc15a3f7ed47870174af74e5308b856138771a10019fe4374389eb89d2280776e33fa2dd3526cec35cd86a9cf6c94253fe00c4b8a87a36451745116456833bb1a237"),
        ];

        for (i, (raw, encoded)) in fixtures.iter().enumerate() {
            println!("fixture {}", i);
            let n = hex::decode(raw).unwrap();

            let n_big = BigUint::from_bytes_be(&n);
            let n_encoded = bignum_to_mpi(&n_big);
            let (rest, n_big2) = mpi_big(&n_encoded).unwrap();
            assert_eq!(rest.len(), 0);
            assert_eq!(n_big, n_big2);

            println!("{}", hex::encode(&n));
            let mut buf = Vec::new();
            write_mpi(&n, &mut buf).unwrap();
            let (rest, n_big3) = mpi_big(&buf).unwrap();

            assert_eq!(hex::encode(&buf), hex::encode(&n_encoded));
            assert_eq!(n_big, n_big3);
            assert_eq!(rest.len(), 0);

            let mut buf = Vec::new();
            write_bignum_mpi(&n_big, &mut buf).unwrap();

            assert_eq!(&buf, &n_encoded);
            assert_eq!(&buf, &hex::decode(encoded).unwrap());

            let (rest, n_big4) = mpi_big(&buf).unwrap();
            assert_eq!(rest.len(), 0);
            assert_eq!(n_big, n_big4);
        }
    }
}
