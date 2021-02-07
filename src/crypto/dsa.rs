use num_bigint::{traits::ModInverse, BigUint};

use crate::errors::Result;
use crate::types::Mpi;

/// Verify a DSA signature.
pub fn verify(p: &Mpi, q: &Mpi, g: &Mpi, y: &Mpi, hashed: &[u8], sig: &[Mpi]) -> Result<()> {
    // Key
    let p: BigUint = p.into();
    let q: BigUint = q.into();
    let g: BigUint = g.into();
    let y: BigUint = y.into();

    // Signature
    ensure!(sig.len() == 2, "invalid signature");
    let r: BigUint = (&sig[0]).into();
    let s: BigUint = (&sig[1]).into();

    let one: BigUint = 1u32.into();
    ensure!(one < r && r < q && one < s && s < q, "invalid signature");

    // https://tools.ietf.org/html/rfc4880#section-5.2.2
    //     If the output size of the chosen hash is larger than the number of
    //     bits of q, the hash result is truncated to fit by taking the number
    //     of leftmost bits equal to the number of bits of q.  This (possibly
    //     truncated) hash function result is treated as a number and used
    //     directly in the DSA signature algorithm.
    let h = {
        let mut tmp: BigUint = BigUint::from_bytes_be(hashed);
        tmp >>= tmp.bits().saturating_sub(q.bits());
        tmp
    };

    let w = match s.mod_inverse(&q).and_then(|x| x.to_biguint()) {
        Some(w) => w,
        _ => bail!("invalid key"), // q isn't prime, please ask for a refund from the key generator
    };
    let u1 = (&h * &w) % &q;
    let u2 = (&r * &w) % &q;
    let v = ((g.modpow(&u1, &p) * y.modpow(&u2, &p)) % p) % q;

    ensure!(v == r, "invalid signature");

    Ok(())
}
