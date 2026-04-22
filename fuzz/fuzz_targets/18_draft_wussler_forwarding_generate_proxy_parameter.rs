#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::{
    composed::{Deserializable, SignedSecretKey},
    types::Password,
};

// The string-focused format is likely harder for the fuzzer to mutate efficiently,
// but easier to find existing input snippets for among existing rpgp test files
#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    key1: String,
    key2: String,
}

fuzz_target!(|data: Input| {
    let key1_res = SignedSecretKey::from_string(&data.key1);

    match key1_res {
        Err(_) => return,
        Ok((key1, _)) => {
            // ensure there is at least one subkey
            if key1.secret_subkeys.len() < 1 {
                return;
            }

            let key2_res = SignedSecretKey::from_string(&data.key2);
            match key2_res {
                Err(_) => return,
                Ok((key2, _)) => {
                    // ensure there is at least one subkey
                    if key2.secret_subkeys.len() < 1 {
                        return;
                    }

                    // existence of the subkeys was checked previously
                    let recipient_key = &key1.secret_subkeys[0].key;
                    let forwardee_key = &key2.secret_subkeys[0].key;

                    // call the target function
                    let k_res = recipient_key.generate_proxy_parameter(
                        forwardee_key,
                        &Password::empty(),
                        &Password::empty(),
                    );

                    match k_res {
                        Err(_) => {}
                        Ok(proxy_parameter) => {
                            #[cfg(feature = "fuzzer_verbose1")]
                            print!("fuzzer: success, {:?}\n", proxy_parameter.as_ref());
                        }
                    }
                }
            }
        }
    }
});
