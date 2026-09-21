//! Test parsing of composed keys

use std::path::Path;

use pgp::composed::{Deserializable, SignedPublicKey};

#[test]
#[ignore]
fn test_composed_sks_0000() {
    let p = Path::new("./tests/tests/sks-dump/0000.pgp");

    for (j, key) in SignedPublicKey::from_file_many(p).unwrap().enumerate() {
        // eprintln!("{j}");
        if key.is_err() {
            eprintln!("err: {:?}", key.err().unwrap());
        }
    }

    // sees 20992, with 25 of them errors
    // -> how many should it be?
    // -> can we avoid some or all of the errors?
}

// ftp_pgp_net_1997/strong.pgp: 2124 public key packets
#[test]
#[ignore]
fn test_strong_1997() {
    let p = Path::new("./tests/tests/ftp_pgp_net_1997/strong.pgp");

    for (j, key) in SignedPublicKey::from_file_many(p).unwrap().enumerate() {
        // eprintln!("{j}");
        if key.is_err() {
            eprintln!("err: {:?}", key.err().unwrap());
        }
    }

    // Sees 2123, with 9 of them errors
}
