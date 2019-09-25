#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

#[macro_use]
extern crate pgp;

#[macro_use]
mod macros;

mod cvec;
mod errors;
mod hash;
mod key;
mod message;
mod public_key;
mod secret_key;

pub use cvec::*;
pub use errors::*;
pub use hash::*;
pub use key::*;
pub use message::*;
pub use public_key::*;
pub use secret_key::*;

/// Free string, that was created by rpgp.
#[no_mangle]
pub unsafe extern "C" fn rpgp_string_drop(p: *mut libc::c_char) {
    let _ = std::ffi::CString::from_raw(p);
    // Drop
}
