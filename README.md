# rPGP

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/pgp">
    <img src="https://img.shields.io/crates/v/pgp.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/pgp">
    <img src="https://img.shields.io/crates/d/pgp.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- docs.rs docs -->
  <a href="https://docs.rs/pgp">
    <img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square"
      alt="docs.rs docs" />
  </a>
  <!-- msrv -->
  <a href="https://img.shields.io/badge/rustc-1.85+-blue.svg?style=flat-square">
    <img src="https://img.shields.io/badge/rustc-1.85+-blue.svg?style=flat-square"
      alt="MSRV 1.85" />
  </a>
</div>

<div align="center">
  <h3>
    <a href="https://docs.rs/pgp">
      Rust Docs
    </a>
    <span> | </span>
    <a href="https://github.com/rpgp/rpgp/releases">
      Releases
    </a>
  </h3>
</div>
<br/>

> OpenPGP implemented in pure Rust, permissively licensed

rPGP is a pure Rust implementation of OpenPGP.

rPGP implements OpenPGP as specified in [RFC9580], including the commonly used v4 formats, as well as the latest v6 key formats and AEAD encryption mechanisms.
All formats specified in the historical RFCs [RFC4880] and [RFC6637], such as v3 keys and signatures, are supported as well.


See [`IMPL_STATUS.md`](docs/IMPL_STATUS.md) for more details on the implemented PGP features.

rPGP offers a flexible low-level API and gives users the ability to build higher level PGP tooling in the most compatible way possible.
Additionally, it fully supports all functionality required by the [Autocrypt 1.1 e-mail encryption specification].

## Usage

```sh
> cargo add pgp
```

### Load a public key and verify an inline-signed message

```rust no_run
use std::fs;

use pgp::composed::{Deserializable, Message, SignedPublicKey};

fn main() {
   let pub_key_file = "key.asc";
   let msg_file = "msg.asc";

   let key_string = fs::read_to_string(pub_key_file).unwrap();
   let (public_key, _headers_public) = SignedPublicKey::from_string(&key_string).unwrap();

   let msg_string = fs::read_to_string(msg_file).unwrap();
   let (mut msg, _headers_msg) = Message::from_string(&msg_string).unwrap();

   // Verify this message
   // NOTE: This assumes that the primary serves as the signing key, which is not always the case!
   msg.verify(&public_key).unwrap();

   let msg_string = msg.as_data_string().unwrap(); // actual message content
   println!("Signed message: {msg_string:?}");
}
```

### Generate and verify a detached signature with an OpenPGP keypair

```rust no_run
use std::time::SystemTime;

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{KeyDetails, Password};

fn main() -> pgp::errors::Result<()> {
   let priv_key_file = "key.sec.asc";

   let data = b"Hello world!";

   // -- Create a new signature using the private key --
   let signed_secret_key = SignedSecretKey::from_armor_file(priv_key_file)?.0;

   // Set up a signature configuration to create a binary data signature
   let mut config = SignatureConfig::from_key(
      &mut rand::rng(),
      &signed_secret_key.primary_key,
      SignatureType::Binary,
   )?;
   config.hashed_subpackets = vec![
      Subpacket::regular(SubpacketData::IssuerFingerprint(
         signed_secret_key.fingerprint(),
      ))?,
      Subpacket::critical(SubpacketData::SignatureCreationTime(
         SystemTime::now().into(),
      ))?,
   ];
   config.unhashed_subpackets =
           vec![Subpacket::regular(SubpacketData::Issuer(signed_secret_key.key_id()))?];

   // Generate an OpenPGP signature packet (which is used as a "detached signature", in this context)
   let signature = config
           .sign(
              &signed_secret_key.primary_key,
              &Password::empty(),
              &data[..],
           )?;

   // -- Verify the signature using the public key --
   let pub_key_file = "key.asc";
   let public_key = SignedPublicKey::from_armor_file(pub_key_file)?.0;

   signature.verify(&public_key, &data[..])?;

   Ok(())
}
```

## Current Status

> Last updated *September 2024*

- Implementation Status: [IMPL_STATUS.md](docs/IMPL_STATUS.md)
- Security Status: [STATUS_SECURITY.md](docs/SECURITY_STATUS.md)
- Supported Platforms: [PLATFORMS.md](docs/PLATFORMS.md)

## rPGP for application developers

rPGP aims to make it easy for application developers to incorporate OpenPGP functionality into their projects.

However, the OpenPGP format and its semantics are relatively complex, and there has historically not been a reader-friendly introduction to the domain.

The text ["OpenPGP for application developers"](https://openpgp.dev/) offers an introduction to OpenPGP, aimed mainly at application developers. We recommend it for initial orientation.

Independently, we welcome questions in the rPGP issue tracker.

## Users & Libraries built using rPGP

- [Delta Chat]: Cross-platform messaging app that works over e-mail
- [`rpm`]: A pure rust library for parsing and creating RPM files
- [`rpgpie`]: An experimental high level OpenPGP API
- [`rsop`]: A SOP CLI tool based on rPGP and rpgpie
- [`debian-packaging`]: a library crate for dealing with Debian packages

Don't see your project here? Please send a PR :)

### FAQs

Checkout [FAQ.md](docs/FAQ.md).


## Minimum Supported Rust Version (MSRV)

All crates in this repository support Rust 1.85 or higher. In future minimally supported
version of Rust can be changed, but it will be done with a minor version bump.

## Funding

[RFC 9580 support for rPGP](https://nlnet.nl/project/rPGP-cryptorefresh/)
has been funded in part through [NGI0 Core](https://nlnet.nl/core/),
a fund established by [NLnet](https://nlnet.nl)
with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) programme.

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   <http://www.apache.org/licenses/LICENSE-2.0>)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[RFC2440]: https://tools.ietf.org/html/rfc2440
[RFC4880]: https://tools.ietf.org/html/rfc4880.html
[RFC6637]: https://www.rfc-editor.org/rfc/rfc6637
[RFC9580]: https://www.rfc-editor.org/rfc/rfc9580.html
[Autocrypt 1.1 e-mail encryption specification]: https://autocrypt.org/level1.html
[the `pgp` Crate]: https://crates.io/crates/pgp/
[Delta Chat]: https://delta.chat
[`rsop`]: https://crates.io/crates/rsop/
[`rpgpie`]: https://crates.io/crates/rpgpie
[`rpm`]: https://crates.io/crates/rpm
[`debian-packaging`]: https://crates.io/crates/debian-packaging
