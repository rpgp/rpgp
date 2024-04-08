# rPGP

[![crates.io][crate-image]][crate-link]
[![Documentation][doc-image]][doc-link]
[![Build Status][build-image]][build-link]
![minimum rustc 1.70][msrv-image]
[![dependency status][deps-image]][deps-link]
[![License][license-image]][license-link]

> OpenPGP implemented in pure Rust, permissively licensed

rPGP is the only pure Rust implementation of OpenPGP, following the main RFCs

- [RFC4880]
- [RFC2440],
- [RFC6637] and
- [draft-ietf-openpgp-crypto-refresh]

See [`STATUS.md`](STATUS.md) for more details on the implemented PGP features.

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

- Implementation Status: [STATUS.md](STATUS.md)
- Security Staus: [SECURITY.md](SECURITY.md)
- Supported Platforms: [PLATFORMS.md](PLATFORMS.md)


## Users & Libraries built using rPGP

- [Delta Chat]: Messaging app that works over e-mail
- [`rpgpie`]: An experimental high level OpenPGP
- [`rsop`]: A SOP CLI tool based on rPGP and rpgpie.

Don't see your project here? Please send a PR :)

### FAQs

Checkout [FAQ.md](FAQ.md).


## Minimum Supported Rust Version (MSRV)

All crates in this repository support Rust 1.70 or higher. In future minimally supported
version of Rust can be changed, but it will be done with a minor version bump.

## LICENSE

MIT or Apache 2.0

## Contribution

Unless you explicitly state otherwise, any contribution submitted
for inclusion in rPGP by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[crate-image]: https://img.shields.io/crates/v/pgp.svg?style=flat-square
[crate-link]: https://crates.io/crates/pgp
[doc-image]: https://img.shields.io/badge/docs-online-blue.svg?style=flat-square
[doc-link]: https://docs.rs/crate/pgp/
[license-image]: https://img.shields.io/badge/License-MIT%2FApache2.0-green.svg?style=flat-square
[license-link]: https://github.com/rpgp/rpgp/blob/master/LICENSE.md
[build-image]: https://github.com/rpgp/rpgp/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/rpgp/rpgp/actions?query=workflow%3ACI+branch%3Amaster
[msrv-image]: https://img.shields.io/badge/rustc-1.70+-blue.svg
[deps-image]: https://deps.rs/repo/github/rpgp/rpgp/status.svg
[deps-link]: https://deps.rs/repo/github/rpgp/rpgp
[RFC2440]: https://tools.ietf.org/html/rfc2440
[RFC4880]: https://tools.ietf.org/html/rfc4880.html
[Autocrypt 1.1 e-mail encryption specification]: https://autocrypt.org/level1.html
[the `pgp` Crate]: https://crates.io/crates/pgp/
[Delta Chat]: https://delta.chat
[`rsop`]: https://crates.io/crates/rsop/
[`rpgpie`]: https://crates.io/crates/rpgpie
[RFC6637]: https://www.rfc-editor.org/rfc/rfc6637
[draft-ietf-openpgp-crypto-refresh]: https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/13/
