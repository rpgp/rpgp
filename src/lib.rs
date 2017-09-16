#[macro_use]
extern crate nom;
// extern crate openssl;
extern crate crc24;
extern crate base64;
extern crate byteorder;
#[macro_use]
extern crate enum_primitive;

pub mod pgp;

mod types;
mod header;
mod email;
mod packet;
mod util;
