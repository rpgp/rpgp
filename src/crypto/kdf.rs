use crypto::hash::HashAlgorithm;
use crypto::sym::SymmetricKeyAlgorithm;
use errors::Result;
use packet::types::StringToKeyType;

/// String-To-Key methods are used to convert a given password string into a key.
/// Ref: https://tools.ietf.org/html/rfc4880#section-3.7
pub fn s2k<F>(
    password: F,
    sym_alg: SymmetricKeyAlgorithm,
    s2k: StringToKeyType,
    hash_alg: HashAlgorithm,
    salt: Option<&Vec<u8>>,
    count: Option<&usize>,
) -> Result<Vec<u8>>
where
    F: FnOnce() -> String,
{
    match s2k {
        StringToKeyType::Simple | StringToKeyType::Salted | StringToKeyType::IteratedAndSalted => {
            let key_size = sym_alg.key_size();
            let hash_size = hash_alg.digest_size();
            let num_contexts = (key_size + hash_size - 1) / hash_size;
            let pw = password();
            println!("{} {} {} {}", key_size, hash_size, num_contexts, pw);
            println!("{:?} {:?} {:?}", sym_alg, hash_alg, s2k);

            let mut zeros = Vec::with_capacity(num_contexts + 1);
            let mut ret = vec![0u8; key_size];

            for data in ret.chunks_mut(hash_size) {
                let mut hash = hash_alg.new()?;
                hash.update(&zeros[..]);

                match s2k {
                    StringToKeyType::Simple => {
                        hash.update(pw.as_bytes());
                    }
                    StringToKeyType::Salted => {
                        hash.update(salt.expect("missing salt for salted"));
                        hash.update(pw.as_bytes());
                    }
                    StringToKeyType::IteratedAndSalted => {
                        let salt = salt.expect("missing salt for iterated");
                        let count = count.expect("missing count for iterated");
                        let octs_per_iter = salt.len() + pw.as_bytes().len();
                        let mut data = vec![0u8; octs_per_iter];
                        let full = count / octs_per_iter;
                        let tail = count - (full * octs_per_iter);

                        data[0..salt.len()].clone_from_slice(salt);
                        data[salt.len()..].clone_from_slice(pw.as_bytes());

                        for _ in 0..full {
                            hash.update(&data);
                        }

                        if tail != 0 {
                            hash.update(&data[0..tail]);
                        }
                    }
                    _ => unreachable!(),
                }
                zeros.push(0);
                let l = data.len();
                data.clone_from_slice(&hash.finish()[0..l]);
            }

            Ok(ret)
        }
        _ => unsupported_err!("s2k: {:?}", s2k),
    }
}

/// Key Derivation Function for ECDH (as defined in RFC 6637).
/// https://tools.ietf.org/html/rfc6637#section-7
pub fn kdf(hash: HashAlgorithm, x: &[u8], length: usize, param: &[u8]) -> Result<Vec<u8>> {
    let prefix = vec![0, 0, 0, 1];

    let values: Vec<&[u8]> = vec![&prefix, x, param];
    let data = values.concat();

    let mut digest = hash.digest(&data)?;
    digest.truncate(length);

    Ok(digest)
}
