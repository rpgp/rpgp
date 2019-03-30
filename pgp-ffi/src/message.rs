use std::ffi::{CStr, CString};
use std::io::Cursor;
use std::slice;

use libc::c_char;
use pgp::composed::{Deserializable, Message, SignedPublicKey, SignedSecretKey};
use pgp::types::{CompressionAlgorithm, KeyTrait, StringToKey};
use rand::thread_rng;

use crate::cvec::cvec;
use crate::{signed_public_key, signed_secret_key, update_last_error};

pub type message = Message;

/// Parse an armored message.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_from_armor(
    msg_ptr: *const u8,
    msg_len: libc::size_t,
) -> *mut message {
    assert!(!msg_ptr.is_null());
    assert!(msg_len > 0);

    let enc_msg = slice::from_raw_parts(msg_ptr, msg_len);

    let (msg, _headers) = try_ffi!(
        Message::from_armor_single(Cursor::new(enc_msg)),
        "invalid message"
    );

    Box::into_raw(Box::new(msg))
}

/// Parse a message in bytes format.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_from_bytes(
    msg_ptr: *const u8,
    msg_len: libc::size_t,
) -> *mut message {
    assert!(!msg_ptr.is_null());
    assert!(msg_len > 0);

    let enc_msg = slice::from_raw_parts(msg_ptr, msg_len);

    let msg = try_ffi!(Message::from_bytes(Cursor::new(enc_msg)), "invalid message");

    Box::into_raw(Box::new(msg))
}

/// Decrypt the passed in message, using a password.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_decrypt_with_password(
    msg_ptr: *const message,
    password_ptr: *const c_char,
) -> *mut message {
    assert!(!msg_ptr.is_null());
    assert!(!password_ptr.is_null());

    let msg = &*msg_ptr;
    let password = CStr::from_ptr(password_ptr);
    let password_str = try_ffi!(password.to_str(), "invalid password");
    let mut decryptor = try_ffi!(
        msg.decrypt_with_password(|| password_str.into()),
        "failed to decrypt message"
    );
    let decrypted_msg = try_ffi!(
        try_ffi!(
            decryptor.next().ok_or_else(|| format_err!("")),
            "no message found"
        ),
        "failed to decrypt message"
    );

    Box::into_raw(Box::new(decrypted_msg))
}

/// Decrypt the passed in message, without attempting to use a password.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_decrypt_no_pw(
    msg_ptr: *const message,
    skeys_ptr: *const *const signed_secret_key,
    skeys_len: libc::size_t,
    pkeys_ptr: *const *const signed_public_key,
    pkeys_len: libc::size_t,
) -> *mut message_decrypt_result {
    assert!(!msg_ptr.is_null());
    assert!(!skeys_ptr.is_null());
    assert!(skeys_len > 0);

    let msg = &*msg_ptr;
    let skeys_raw = slice::from_raw_parts(skeys_ptr, skeys_len);
    let skeys = skeys_raw
        .iter()
        .map(|k| {
            let v: &SignedSecretKey = &**k;
            v
        })
        .collect::<Vec<_>>();

    let pkeys = if pkeys_ptr.is_null() || pkeys_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(pkeys_ptr, pkeys_len))
    };

    let (mut decryptor, _) = try_ffi!(
        msg.decrypt(|| "".into(), || "".into(), &skeys[..]),
        "failed to decrypt message"
    );

    // TODO: how to handle the case when we detect multiple messages?
    let dec_msg = try_ffi!(
        try_ffi!(
            decryptor.next().ok_or_else(|| format_err!("no message")),
            "no message found"
        ),
        "failed to decrypt message"
    );

    let (valid_ids_ptr, valid_ids_len) = if let Some(pkeys) = pkeys {
        let mut valid_ids = pkeys
            .iter()
            .filter_map(|pkey| match dec_msg.verify(&(**pkey).primary_key) {
                Ok(_) => Some(
                    CString::new(hex::encode_upper(&(&**pkey).fingerprint()))
                        .expect("failed to allocate")
                        .into_raw(),
                ),
                Err(_) => None,
            })
            .collect::<Vec<_>>();

        valid_ids.shrink_to_fit();
        let res = (valid_ids.as_mut_ptr(), valid_ids.len());
        std::mem::forget(valid_ids);
        res
    } else {
        (std::ptr::null_mut(), 0)
    };

    Box::into_raw(Box::new(message_decrypt_result {
        message_ptr: Box::into_raw(Box::new(dec_msg)),
        valid_ids_ptr,
        valid_ids_len,
    }))
}

/// Message decryption result.
#[repr(C)]
pub struct message_decrypt_result {
    /// A pointer to the decrypted message.
    pub message_ptr: *mut message,
    /// Pointer to a list of fingerprints which verified the signature.
    pub valid_ids_ptr: *mut *mut c_char,
    pub valid_ids_len: libc::size_t,
}

/// Free a [message_decrypt_result].
#[no_mangle]
pub unsafe extern "C" fn rpgp_message_decrypt_result_drop(res_ptr: *mut message_decrypt_result) {
    assert!(!res_ptr.is_null());

    let res = &*res_ptr;
    let _msg = &*res.message_ptr;
    let _ids = Vec::from_raw_parts(res.valid_ids_ptr, res.valid_ids_len, res.valid_ids_len);
    // Drop
}

/// Returns the underlying data of the given message.
/// Fails when the message is encrypted. Decompresses compressed messages.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_to_bytes(msg_ptr: *const message) -> *mut cvec {
    assert!(!msg_ptr.is_null());

    let msg = &*msg_ptr;

    let result = try_ffi!(msg.get_content(), "failed to extract content");
    match result {
        Some(data) => Box::into_raw(Box::new(data.into())),
        None => {
            update_last_error(format_err!("called on encrypted message").into());
            std::ptr::null_mut()
        }
    }
}

/// Encodes the message into its ascii armored representation.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_to_armored(msg_ptr: *const message) -> *mut cvec {
    assert!(!msg_ptr.is_null());

    let msg = &*msg_ptr;

    let result = try_ffi!(
        msg.to_armored_bytes(None),
        "failed to encode message to ASCII Armor"
    );

    Box::into_raw(Box::new(result.into()))
}

/// Encodes the message into its ascii armored representation, returning a string.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_to_armored_str(msg_ptr: *const message) -> *mut c_char {
    assert!(!msg_ptr.is_null());

    let msg = &*msg_ptr;

    let result = try_ffi!(
        msg.to_armored_string(None),
        "failed to encode message to ASCII Armor"
    );

    CString::new(result).expect("allocation failed").into_raw()
}

/// Free a [message], that was created by rpgp.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_drop(msg_ptr: *mut message) {
    assert!(!msg_ptr.is_null());

    let _ = &*msg_ptr;
    // Drop
}

/// Get the number of fingerprints of a given encrypted message.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_recipients_len(msg_ptr: *mut message) -> u32 {
    assert!(!msg_ptr.is_null());

    let msg = &*msg_ptr;

    let list = msg.get_recipients();

    list.len() as u32
}

/// Get the fingerprint of a given encrypted message, by index, in hexformat.
#[no_mangle]
pub unsafe extern "C" fn rpgp_msg_recipients_get(msg_ptr: *mut message, i: u32) -> *mut c_char {
    assert!(!msg_ptr.is_null());

    let msg = &*msg_ptr;

    let list = msg.get_recipients();
    if (i as usize) < list.len() {
        CString::new(hex::encode(&list[i as usize]))
            .expect("allocation failure")
            .into_raw()
    } else {
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_encrypt_bytes_to_keys(
    bytes_ptr: *const u8,
    bytes_len: libc::size_t,
    pkeys_ptr: *const *const signed_public_key,
    pkeys_len: libc::size_t,
) -> *mut message {
    assert!(!bytes_ptr.is_null());
    assert!(bytes_len > 0);
    assert!(!pkeys_ptr.is_null());
    assert!(pkeys_len > 0);

    let pkeys_raw = slice::from_raw_parts(pkeys_ptr, pkeys_len);
    let pkeys = pkeys_raw
        .iter()
        .map(|k| {
            let v: &SignedPublicKey = &**k;
            v
        })
        .collect::<Vec<_>>();

    let bytes = slice::from_raw_parts(bytes_ptr, bytes_len);

    let mut rng = thread_rng();
    let lit_msg = Message::new_literal_bytes("", bytes);

    let msg = try_ffi!(
        lit_msg.encrypt_to_keys(&mut rng, Default::default(), &pkeys),
        "failed to encrypt"
    );

    Box::into_raw(Box::new(msg))
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_sign_encrypt_bytes_to_keys(
    bytes_ptr: *const u8,
    bytes_len: libc::size_t,
    pkeys_ptr: *const *const signed_public_key,
    pkeys_len: libc::size_t,
    skey_ptr: *const signed_secret_key,
) -> *mut message {
    assert!(!bytes_ptr.is_null());
    assert!(bytes_len > 0);
    assert!(!pkeys_ptr.is_null());
    assert!(pkeys_len > 0);
    assert!(!skey_ptr.is_null());

    let pkeys_raw = slice::from_raw_parts(pkeys_ptr, pkeys_len);
    let pkeys = pkeys_raw
        .iter()
        .map(|k| {
            let v: &SignedPublicKey = &**k;
            v
        })
        .collect::<Vec<_>>();

    let skey = &*skey_ptr;

    let bytes = slice::from_raw_parts(bytes_ptr, bytes_len);

    let mut rng = thread_rng();

    let lit_msg = Message::new_literal_bytes("", bytes);
    let signed_msg = try_ffi!(
        lit_msg.sign(&skey, || "".into(), Default::default()),
        "failed to sign"
    );

    let compressed_msg = try_ffi!(
        signed_msg.compress(CompressionAlgorithm::ZLIB),
        "failed to compress"
    );

    let encrypted_msg = try_ffi!(
        compressed_msg.encrypt_to_keys(&mut rng, Default::default(), &pkeys),
        "failed to encrypt"
    );

    Box::into_raw(Box::new(encrypted_msg))
}

#[no_mangle]
pub unsafe extern "C" fn rpgp_encrypt_bytes_with_password(
    bytes_ptr: *const u8,
    bytes_len: libc::size_t,
    password_ptr: *const c_char,
) -> *mut message {
    assert!(!bytes_ptr.is_null());
    assert!(!password_ptr.is_null());
    assert!(bytes_len > 0);

    let bytes = slice::from_raw_parts(bytes_ptr, bytes_len);

    let mut rng = thread_rng();
    let lit_msg = Message::new_literal_bytes("", bytes);

    let password = CStr::from_ptr(password_ptr);
    let password_str = try_ffi!(password.to_str(), "invalid password");

    let s2k = StringToKey::new_default(&mut rng);

    let msg = try_ffi!(
        lit_msg.encrypt_with_password(&mut rng, s2k, Default::default(), || {
            password_str.into()
        }),
        "failed to encrypt"
    );

    Box::into_raw(Box::new(msg))
}
