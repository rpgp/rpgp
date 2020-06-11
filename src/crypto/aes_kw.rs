use aes::{BlockCipher, NewBlockCipher};
use byteorder::{BigEndian, WriteBytesExt};
use generic_array::sequence::{Concat, Split};
use generic_array::typenum::U8;
use generic_array::GenericArray;

use crate::errors::Result;

lazy_static! {
    static ref IV: GenericArray<u8, U8> = arr![u8; 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
}

/// AES Key Wrap
/// As defined in RFC 3394.
pub fn wrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ensure_eq!(data.len() % 8, 0, "data must be a multiple of 64bit");

    let aes_size = key.len() * 8;
    match aes_size {
        128 => Ok(wrap_128(key, data)),
        192 => Ok(wrap_192(key, data)),
        256 => Ok(wrap_256(key, data)),
        _ => bail!("invalid aes key size: {}", aes_size),
    }
}

/// AES Key Unwrap
/// As defined in RFC 3394.
pub fn unwrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    ensure_eq!(data.len() % 8, 0, "data must be a multiple of 64bit");

    let aes_size = key.len() * 8;
    match aes_size {
        128 => unwrap_128(key, data),
        192 => unwrap_192(key, data),
        256 => unwrap_256(key, data),
        _ => bail!("invalid aes key size: {}", aes_size),
    }
}

macro_rules! impl_aes_kw {
    ($name_wrap:ident, $name_unwrap:ident, $size:expr, $hasher:ty) => {
        #[inline]
        fn $name_wrap(key: &[u8], data: &[u8]) -> Vec<u8> {
            // 0) Prepare inputs

            // number of 64 bit blocks in the input data
            let n = data.len() / 8;

            let p: Vec<_> = data.chunks(8).map(|chunk|{
                GenericArray::<u8, _>::clone_from_slice(chunk)
            }).collect();

            let key = GenericArray::from_slice(key);

            // 1) Initialize variables

            //   Set A to the IV
            let mut a = *IV;

            //   for i = 1 to n: R[i] = P[i]
            let mut r = p.clone();

            // 2) calculate intermediate values

            let mut t_arr = arr![u8; 0, 0, 0, 0, 0, 0, 0, 0];
            for j in 0..=5 {
                for i in 0..n {
                    let t = (n * j + (i + 1)) as u64;

                    let cipher = <$hasher as NewBlockCipher>::new(&key);
                    // Safe to unwrap, as we know the size of t_arr.
                    (&mut t_arr[..]).write_u64::<BigEndian>(t).unwrap();

                    // A | R[i]
                    let mut b = a.concat(r[i]);
                    // B = AES(K, ..)
                    cipher.encrypt_block(&mut b);

                    let (hi, lo) = b.split();

                    // A = MSB(64, B) ^ t
                    a = hi;
                    a.iter_mut().zip(t_arr.iter()).for_each(|(ai, ti)| *ai ^= ti);

                    // R[i] = LSB(64, B)
                    r[i] = lo;
                }
            }

            // 3) output the results
            r.iter().fold(a.to_vec(), |mut acc, v| {
                acc.extend(v);
                acc
            })
        }

        #[inline]
        fn $name_unwrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            // 0) Prepare inputs

            let n = (data.len() / 8) - 1;

            let c: Vec<_> = data.chunks(8).map(|chunk|{
                GenericArray::<u8, _>::clone_from_slice(chunk)
            }).collect();

            let key = GenericArray::from_slice(key);

            // 1) Initialize variables

            //   A = C[0]
            let mut a = c[0];

            //   for i = 1 to n: R[i] = C[i]
            let mut r = (&c[1..]).to_vec();

            // 2) calculate intermediate values

            let mut t_arr = arr![u8; 0, 0, 0, 0, 0, 0, 0, 0];

            for j in (0..=5).rev() {
                for i in (0..n).rev() {
                    let t = (n * j + (i + 1)) as u64;

                    let cipher = <$hasher as NewBlockCipher>::new(&key);
                    // Safe to unwrap, as we know the size of t_arr.
                    (&mut t_arr[..]).write_u64::<BigEndian>(t).unwrap();

                    // A ^ t
                    a.iter_mut().zip(t_arr.iter()).for_each(|(ai, ti)| *ai ^= ti);

                    // (A ^ t) | R[i]
                    let mut b = a.concat(r[i]);
                    // B = AES-1(K, ..)
                    cipher.decrypt_block(&mut b);

                    let (hi, lo) = b.split();

                    // A = MSB(64, B)
                    a = hi;

                    // R[i] = LSB(64, B)
                    r[i] = lo;
                }
            }

            // 3) output the results

            if a == *IV {
                Ok(r.iter().fold(Vec::with_capacity(r.len() * 8), |mut acc, v| {
                    acc.extend(v);
                    acc
                }))
            } else {
                bail!("failed integrity check");
            }
        }
    };
}

impl_aes_kw!(wrap_128, unwrap_128, 128, aes::Aes128);
impl_aes_kw!(wrap_192, unwrap_192, 192, aes::Aes192);
impl_aes_kw!(wrap_256, unwrap_256, 256, aes::Aes256);

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_aes_kw {
        ($name:ident, $kek:expr, $input:expr, $output:expr) => {
            #[test]
            fn $name() {
                let kek = hex::decode($kek).unwrap();
                let input_bin = hex::decode($input).unwrap();
                let output_bin = hex::decode($output).unwrap();

                assert_eq!(
                    hex::encode(wrap(&kek, &input_bin).unwrap()),
                    $output.to_lowercase(),
                    "failed wrap"
                );
                assert_eq!(
                    hex::encode(unwrap(&kek, &output_bin).unwrap()),
                    $input.to_lowercase(),
                    "failed unwrap"
                );
            }
        };
    }

    test_aes_kw!(
        wrap_unwrap_128_key_128_kek,
        "000102030405060708090A0B0C0D0E0F",
        "00112233445566778899AABBCCDDEEFF",
        "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
    );

    test_aes_kw!(
        wrap_unwrap_128_key_192_kek,
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF",
        "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
    );

    test_aes_kw!(
        wrap_unwrap_128_key_256_kek,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF",
        "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    );
    test_aes_kw!(
        wrap_unwrap_192_key_192_kek,
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
    );
    test_aes_kw!(
        wrap_unwrap_192_key_256_kek,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF0001020304050607",
        "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    );
    test_aes_kw!(
        wrap_unwrap_256_key_256_kek,
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    );
}
