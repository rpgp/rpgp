# rPGP

*OpenPGP implemented in pure Rust, permissively licensed*

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
  <a href="https://img.shields.io/badge/rustc-1.88+-blue.svg?style=flat-square">
    <img src="https://img.shields.io/badge/rustc-1.88+-blue.svg?style=flat-square"
      alt="MSRV 1.88" />
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

rPGP is a pure Rust implementation of OpenPGP as specified in [RFC9580].
It supports the commonly used v4 formats, as well as the latest v6 key formats and AEAD encryption mechanisms.
(All formats specified in the historical RFCs [RFC4880] and [RFC6637], including v3 keys and signatures, are supported as well.)

See [`IMPL_STATUS`](docs/IMPL_STATUS.md) for more details on the implemented PGP features and ["Overview of OpenPGP formats and mechanisms"](docs/openpgp.md) for context about them.

rPGP offers a flexible low-level API. It gives users the ability to build higher level PGP tooling in the most compatible way possible.
Additionally, it fully supports all functionality required by the [Autocrypt 1.1 e-mail encryption specification].

## Notable Users & Libraries built using rPGP

- [Delta Chat]: Cross-platform messaging app that works over e-mail
- [`debian-packaging`]: A library crate for dealing with Debian packages
- [`himalaya`]: CLI to manage emails (includes [`pgp-lib`] component)
- [`oct-git`]: Git signing and verification backend (with a focus on OpenPGP cards)
- [`prs-lib`]: A CLI password manager inspired by pass (with optional rPGP backend, including OpenPGP card support)
- [`rpgpie`]: An experimental OpenPGP semantics library
- [`rpm`]: A pure rust library for parsing and creating RPM files
- [`rsop`]: A [SOP] CLI tool based on rPGP and rpgpie
- [`rsop-oct`]: A [SOP] CLI tool for OpenPGP card devices (also based on rPGP and rpgpie)
- [`signstar`]: A signing enclave framework for HSM backends
- [`voa-openpgp`]: OpenPGP implementation for [VOA]

Don't see your project here? Please send a PR :)

## Usage

```sh
> cargo add pgp
```

### Load a public key and verify an inline-signed message

```rust no_run
use pgp::composed::{Deserializable, Message, SignedPublicKey};

fn main() -> pgp::errors::Result<()> {
    let (public_key, _headers_public) = SignedPublicKey:: from_armor_file("key.asc")?;
   
    let (mut msg, _headers_msg) = Message::from_armor_file("msg.asc")?;
    if msg.verify(&public_key).is_ok() { // Verify using the primary (NOTE: This is not always the right key!)
        // Signature is correct, print message payload
        println!("Signed message: {:?}", msg.as_data_string()?);
    }
   
    Ok(())
}
```

### Generate and verify a detached signature with an OpenPGP keypair

```rust no_run
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;

fn main() -> pgp::errors::Result<()> {
   const DATA: &[u8] = b"Hello world!";

   // Create a signature over DATA with the private key
   let (private_key, _headers) = SignedSecretKey::from_armor_file("key.sec.asc")?;
   let sig = DetachedSignature::sign_binary_data(
      &mut rand::rng(),
      &private_key.primary_key, // Sign with the primary (NOTE: This is not always the right key!)
      &Password::empty(),
      HashAlgorithm::Sha256,
      DATA,
   )?;

   // Verify signature with the public key
   let (public_key, _headers) = SignedPublicKey::from_armor_file("key.asc")?;
   sig.verify(&public_key, DATA)?; // Verify with primary key (NOTE: This is not always the right key!)

   Ok(())
}
```

### Cargo features

- `bzip2`: Enables bzip2 support
- `asm`: Enables assembly based optimizations
- `wasm`: Allows building for wasm
- `malformed-artifact-compat`: Be lenient towards some types of malformed artifacts (erroneously formed ECDH PKESK; invalidly short first partial body segments), and allow use of very large RSA keys (>8192 bit). Most users will NOT need this feature, should be disabled by default!
- `draft-pqc`: Enables implementation of draft-ietf-openpgp-pqc-12 (This is unstable and can have breaking changes in patch releases. DO NOT USE IN PRODUCTION!)
- `draft-wussler-openpgp-forwarding`: Enables support for the formats from [draft-wussler-openpgp-forwarding](https://datatracker.ietf.org/doc/draft-wussler-openpgp-forwarding/), and decryption of forwarded ECDH Curve25519 OpenPGP messages

## Current Status

> Last updated *September 2025*

- Implementation Status: [`IMPL_STATUS.md`](docs/IMPL_STATUS.md)
- Security Status: [`SECURITY_STATUS.md`](docs/SECURITY_STATUS.md)
- Supported Platforms: [`PLATFORMS.md`](docs/PLATFORMS.md)

## FAQs

See [`FAQ.md`](docs/FAQ.md).

## rPGP is a library for application developers

rPGP aims to make it easy for application developers to incorporate OpenPGP functionality into their projects.

Note that the OpenPGP format and its semantics are relatively complex.
We recommend the text ["OpenPGP for application developers"](https://openpgp.dev/) for initial orientation.

Independently, we welcome questions in the rPGP issue tracker.

## rPGP is a low-level OpenPGP library

rPGP offers abstractions for handling the formats and mechanisms specified in RFC 9580.
However, it offers them as relatively low-level building blocks, and doesn't attempt to ensure that users can not apply them unsafely.

> rPGP allows following almost all parts of the OpenPGP specification, but the APIs are low level building blocks and do not claim that using them is (a) secure or (b) following the OpenPGP specification

Using the building blocks in rPGP correctly and safely requires a solid understanding of OpenPGP and at least a basic understanding of cryptography.

### OpenPGP is a layered technology

For context, OpenPGP can be thought of as a multi-layered technology, roughly like this:

1. Wire format: [Packet framing](https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-syntax), [Packet content](https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-types), [ASCII armor](https://www.rfc-editor.org/rfc/rfc9580.html#name-forming-ascii-armor), ...
2. Composite objects (e.g. Certificates, Messages) constructed according to [grammars](https://www.rfc-editor.org/rfc/rfc9580.html#name-packet-sequence-composition)
3. Functionality to process data, such as calculation and validation of OpenPGP signatures and encryption and decryption of messages.
4. OpenPGP semantics (e.g.: *Expiration* and *Revocation* of Certificates and their components, *Key Flags* that define which semantical operations a given component key may be used for, signaling of algorithm preferences, ...)

Of these layers, the OpenPGP RFC specifies 1-3, while 4 is not specified in detail.

Some work on formalizing OpenPGP semantics can be found in
[draft-gallagher-openpgp-signatures](https://datatracker.ietf.org/doc/draft-gallagher-openpgp-signatures/) and
[draft-dkg-openpgp-revocation](https://datatracker.ietf.org/doc/draft-dkg-openpgp-revocation/).

Analogous to the RFC, rPGP handles layers 1-3, but explicitly does not deal with 4.
Applications that need OpenPGP semantics must implement them manually, or rely on additional libraries to deal with that layer.

NOTE: The [`rpgpie`] library implements some of these high level OpenPGP semantics.
It may be useful either to incorporate in rPGP projects, or to study for reference.

### Mechanisms in OpenPGP evolve over time

rPGP can handle a wide range of OpenPGP artifacts.
It offers support for almost all mechanisms in OpenPGP, both modern and those now considered legacy.

This explicitly includes artifacts that use historical algorithms, which are considered insecure given today's understanding.

rPGP doesn't ensure that application developers use appropriate cryptographic building blocks for their purposes
(even though it generally produces appropriately modern artifacts, by default).

See ["Overview of OpenPGP formats and mechanisms"](docs/openpgp.md) for more details on the evolution of OpenPGP over time.

## Minimum Supported Rust Version (MSRV)

All crates in this repository support Rust 1.88 or higher. In future minimally supported
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
[SOP]: https://dkg.gitlab.io/openpgp-stateless-cli/
[VOA]: https://uapi-group.org/specifications/specs/file_hierarchy_for_the_verification_of_os_artifacts/
[Autocrypt 1.1 e-mail encryption specification]: https://autocrypt.org/level1.html
[Delta Chat]: https://delta.chat
[`rsop`]: https://crates.io/crates/rsop/
[`rsop-oct`]: https://crates.io/crates/rsop-oct/
[`rpgpie`]: https://crates.io/crates/rpgpie
[`rpm`]: https://crates.io/crates/rpm
[`signstar`]: https://gitlab.archlinux.org/archlinux/signstar/
[`debian-packaging`]: https://crates.io/crates/debian-packaging
[`himalaya`]: https://crates.io/crates/himalaya
[`oct-git`]: https://crates.io/crates/openpgp-card-tool-git
[`pgp-lib`]: https://crates.io/crates/pgp-lib
[`prs-lib`]: https://crates.io/crates/prs-lib
[`voa-openpgp`]: https://crates.io/crates/voa-openpgp
