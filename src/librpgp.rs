use std::io::Cursor;

use libc;

use composed::key::from_armor_many;

#[no_mangle]
pub unsafe extern "C" fn import_key(raw: *const u8, len: libc::size_t) -> u32 {
    let bytes = ::std::slice::from_raw_parts(raw, len);

    let keys = from_armor_many(Cursor::new(bytes)).expect("failed to parse");
    for key in keys {
        let key = key.expect("failed to parse key");
        println!("got key {:#?}", key);

        key.verify().expect("key failed to verify");
    }

    0
}
