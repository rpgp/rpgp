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
  <a href="https://img.shields.io/badge/rustc-1.70+-blue.svg?style=flat-square">
    <img src="https://img.shields.io/badge/rustc-1.70+-blue.svg?style=flat-square"
      alt="MSRV 1.70" />
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

rPGP is the only pure Rust implementation of OpenPGP, following the main RFCs

- [RFC4880]
- [RFC2440],
- [RFC6637] and
- [draft-ietf-openpgp-crypto-refresh]

See [`IMPL_STATUS.md`](docs/IMPL_STATUS.md) for more details on the implemented PGP features.

It offers a flexible low-level API and gives users the ability to build higher level PGP tooling in the most compatible way possible.
Additionally it fully supports all functionality required by the [Autocrypt 1.1 e-mail encryption specification].

## Usage

```sh
> cargo add pgp
```

### Load a key and verify a message

```rust
use std::fs;
use pgp::{SignedSecretKey, Message, Deserializable};

let key_file = "key.sec.asc";
let msg_file = "msg.asc";

let key_string = fs::read_to_string("key.sec.asc").unwrap(),
let (secret_key, _headers) = SignedSecretKey::from_string(&key_string).unwrap();
let public_key = skey.public_key();

let msg_string = fs::read_to_string("msg.asc").unwrap();
let (msg, _headres) = Message::from_string(msg_string).unwrap();

// Verify this message
msg.verify(&pkey).unwrap();

let msg_content = msg.get_content().unwrap(); // actual message content
```

## Current Status

> Last updated *April 2024*

- Implementation Status: [IMPL_STATUS.md](docs/IMPL_STATUS.md)
- Security Staus: [STATUS_SECURITY.md](docs/SECURITY_STATUS.md)
- Supported Platforms: [PLATFORMS.md](docs/PLATFORMS.md)


## Users & Libraries built using rPGP

- [Delta Chat]: Messaging app that works over e-mail
- [`rpgpie`]: An experimental high level OpenPGP API
- [`rsop`]: A SOP CLI tool based on rPGP and rpgpie

Don't see your project here? Please send a PR :)

### FAQs

Checkout [FAQ.md](docs/FAQ.md).


## Minimum Supported Rust Version (MSRV)

All crates in this repository support Rust 1.70 or higher. In future minimally supported
version of Rust can be changed, but it will be done with a minor version bump.

## License

Copyright 2024 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[RFC2440]: https://tools.ietf.org/html/rfc2440
[RFC4880]: https://tools.ietf.org/html/rfc4880.html
[Autocrypt 1.1 e-mail encryption specification]: https://autocrypt.org/level1.html
[the `pgp` Crate]: https://crates.io/crates/pgp/
[Delta Chat]: https://delta.chat
[`rsop`]: https://crates.io/crates/rsop/
[`rpgpie`]: https://crates.io/crates/rpgpie
[RFC6637]: https://www.rfc-editor.org/rfc/rfc6637
[draft-ietf-openpgp-crypto-refresh]: https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/13/
