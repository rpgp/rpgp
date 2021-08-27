# rPGP

> OpenPGP implemented in pure Rust, permissively licensed

[![crates.io version][crate-shield]][crate] [![CircleCI build status][circle-shield]][circle] [![Appveyor build status][appveyor-shield]][appveyor] [![Docs][docs-shield]][docs] [![License][license-shield]][license]

rPGP is the only full Rust implementation of OpenPGP, following [RFC4880](https://tools.ietf.org/html/rfc4880.html) and [RFC2440](https://tools.ietf.org/html/rfc2440). It offers a minimal low-level API and does not prescribe trust schemes or key management policies. It fully supports all functionality required by the [Autocrypt 1.1 e-mail encryption specification](https://autocrypt.org/level1.html).

rPGP is regularly published as [the `pgp` Crate](https://crates.io/crates/pgp/) and its [RSA](https://crates.io/crates/rsa) implementation
lives under the collective [RustCrypto umbrella](https://github.com/RustCrypto/RSA).
For ECC crypto support we are using [Curve25519-dalek](https://crates.io/crates/curve25519-dalek).

> Please note that the API is not well documented yet. You may check out
> the tests which exercise the API. Please open issues here if if you are
> attempting to use rPGP and need help.

## Status (Last updated: October 2019)

rPGP and its RSA dependency got a first independent security review mid 2019.
No critical flaws were found. We have fixed and are fixing some high, medium and
low risk ones. We will soon publish the full review report.
Further independent security reviews are upcoming.

rPGP is used in production by [Delta Chat, the e-mail based messenger app suite](https://delta.chat), successfully running on Windows, Linux, macOS, Android and iOS in 32bit (only Windows and Android) and 64 bit builds (for the other platforms).

More details on platform and OpenPGP implementation status: 

- [OpenPGP Status document](STATUS.md) which describes what of OpenPGP is supported
- [Platform status document](PLATFORMS.md) which describes current platform support.

### Experimental WASM Support

When enabeling the `wasm` feature, rpgp can be compiled to run using WASM in Node.js and the supported Browsers. Experimental bindings for this can be found in [rpgp/rpgp-js](https://github.com/rpgp/rpgp-js).

## Developement

To run the stress tests,

```sh
> git submodule update --init --recursive
> cargo test --release -- --ignored
```

To enable debugging, add

```rust
use pretty_env_logger;
let _ = pretty_env_logger::try_init();
```

And then run tests with `RUST_LOG=pgp=info`.

## How is rPGP different from Sequoia?

Some key differences:

- rPGP has a more libre license than Sequoia that allows a broader usage

- rPGP is a library with a well-defined, relatively small feature-set
  where Sequoia also tries to be a replacement for the GPG command line tool

- All crypto used in rPGP is implemented in pure Rust,
  whereas sequoia uses Nettle, which is implemented in C.


## Minimum Supported Rust Version (MSRV)

All crates in this repository support Rust 1.51 or higher. In future minimally supported version of Rust can be changed, but it will be done with a minor version bump.

## LICENSE

MIT or Apache 2.0

## Contribution

Unless you explicitly state otherwise, any contribution submitted
for inclusion in rPGP by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[circle-shield]: https://img.shields.io/circleci/project/github/rpgp/rpgp/master.svg?style=flat-square
[circle]: https://circleci.com/gh/rpgp/rpgp/
[appveyor-shield]: https://ci.appveyor.com/api/projects/status/99y4f73itv7yvt93/branch/master?style=flat-square
[appveyor]: https://ci.appveyor.com/project/dignifiedquire/pgp/branch/master
[docs-shield]: https://img.shields.io/badge/docs-online-blue.svg?style=flat-square
[docs]: https://docs.rs/crate/pgp/
[license-shield]: https://img.shields.io/badge/License-MIT%2FApache2.0-green.svg?style=flat-square
[license]: https://github.com/rpgp/rpgp/blob/master/LICENSE.md
[crate-shield]: https://img.shields.io/crates/v/pgp.svg?style=flat-square
[crate]: https://crates.io/crates/pgp
