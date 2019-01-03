use std::fs::{self, File};
use std::io::Cursor;
use std::io::Read;
use test::{black_box, Bencher};

#[cfg(feature = "profile")]
use gperftools::profiler::PROFILER;

use pgp::composed::{Deserializable, Message, SignedSecretKey};

#[cfg(feature = "profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.profile", stage))
        .unwrap();
}

#[cfg(not(feature = "profile"))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "profile")]
#[inline(always)]
fn stop_profile() {
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "profile"))]
#[inline(always)]
fn stop_profile() {}

#[bench]
fn bench_message_parse(b: &mut Bencher) {
    let mut message_file =
        File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001.asc").unwrap();
    let mut bytes = Vec::new();
    message_file.read_to_end(&mut bytes).unwrap();

    start_profile("message_parse");
    b.iter(|| {
        let c = Cursor::new(bytes.clone());
        black_box(Message::from_armor_single(c).unwrap())
    });
    b.bytes = bytes.len() as u64;
    stop_profile();
}

#[bench]
fn bench_message_decryption_rsa(b: &mut Bencher) {
    let mut decrypt_key_file =
        File::open("./tests/opengpg-interop/testcases/messages/gnupg-v1-001-decrypt.asc").unwrap();
    let decrypt_key = SignedSecretKey::from_armor_single(&mut decrypt_key_file).unwrap();
    let message_file_path = "./tests/opengpg-interop/testcases/messages/gnupg-v1-001.asc";
    let mut message_file = File::open(message_file_path).unwrap();
    let message = Message::from_armor_single(&mut message_file).unwrap();

    start_profile("message_decryption");
    b.bytes = fs::metadata(message_file_path).unwrap().len();
    b.iter(|| {
        black_box(
            message
                .decrypt(|| "".to_string(), || "test".to_string(), &decrypt_key)
                .unwrap(),
        )
    });
    stop_profile();
}
