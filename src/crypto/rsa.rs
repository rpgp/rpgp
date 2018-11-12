use rsa::padding::PaddingScheme;
use rsa::RSAPrivateKey;

use errors::Result;

pub fn decrypt_rsa(
    priv_key: &RSAPrivateKey,
    mpis: &[Vec<u8>],
    _fingerprint: &[u8],
) -> Result<Vec<u8>> {
    // rsa consist of exactly one mpi
    let mpi = &mpis[0];
    info!("RSA m^e mod n: {}", hex::encode(mpi));
    let m = priv_key.decrypt(PaddingScheme::PKCS1v15, mpi)?;
    info!("m: {}", hex::encode(&m));

    Ok(m)
}
