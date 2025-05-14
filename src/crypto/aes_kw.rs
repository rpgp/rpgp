use cipher::{
    array::Array,
    typenum::{U16, U24, U32},
    KeyInit,
};
use snafu::{ResultExt, Snafu};
use zeroize::Zeroizing;

/// AES key wrap possible errors.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid key size: {}", size))]
    InvalidKeySize { size: usize },
    #[snafu(display("wrap failed"))]
    Wrap { source: aes_kw::Error },
    #[snafu(display("unwrap failed"))]
    Unwrap { source: aes_kw::Error },
}

/// AES Key Wrap
/// As defined in RFC 3394.
pub fn wrap(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let aes_size = key.len() * 8;
    let mut buf = vec![0u8; data.len() + aes_kw::IV_LEN];
    let res = match aes_size {
        128 => {
            let key = Array::<u8, U16>::from_slice(key);
            let kek = aes_kw::KwAes128::new(key);
            kek.wrap_key(data, &mut buf).map(|b| b.to_vec())
        }
        192 => {
            let key = Array::<u8, U24>::from_slice(key);
            let kek = aes_kw::KwAes192::new(key);
            kek.wrap_key(data, &mut buf).map(|b| b.to_vec())
        }
        256 => {
            let key = Array::<u8, U32>::from_slice(key);
            let kek = aes_kw::KwAes256::new(key);
            kek.wrap_key(data, &mut buf).map(|b| b.to_vec())
        }
        _ => {
            return Err(InvalidKeySizeSnafu { size: aes_size }.build());
        }
    };
    res.context(WrapSnafu)
}

/// AES Key Unwrap
/// As defined in RFC 3394.
pub fn unwrap(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let aes_size = key.len() * 8;
    let mut buf = Zeroizing::new(vec![0u8; data.len()]);
    let out = match aes_size {
        128 => {
            let key = Array::<u8, U16>::from_slice(key);
            let kek = aes_kw::KwAes128::new(key);
            kek.unwrap_key(data, &mut buf)
        }
        192 => {
            let key = Array::<u8, U24>::from_slice(key);
            let kek = aes_kw::KwAes192::new(key);
            kek.unwrap_key(data, &mut buf)
        }
        256 => {
            let key = Array::<u8, U32>::from_slice(key);
            let kek = aes_kw::KwAes256::new(key);
            kek.unwrap_key(data, &mut buf)
        }
        _ => {
            return Err(InvalidKeySizeSnafu { size: aes_size }.build());
        }
    }
    .map(|b| Zeroizing::new(b.to_vec()))
    .context(WrapSnafu)?;

    Ok(out)
}

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
