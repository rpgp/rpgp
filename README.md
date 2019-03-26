# rPGP

[![crates.io version][crate-shield]][crate] [![CircleCI build status][circle-shield]][circle] [![Appveyor build status][appveyor-shield]][appveyor] [![Docs][docs-shield]][docs] [![License][license-shield]][license]

> Pure rust implementation of OpenPGP. Following [RFC4880](https://tools.ietf.org/html/rfc4880.html) and [RFC2440](https://tools.ietf.org/html/rfc2440).

> ⚠️ **WARNING:** This library has **not** been audited, so be careful.

## Status

You can find the details of the currently supported features in [this status document](STATUS.md)

## Platform Support

Windows, Linux, MacOS and every other unix-like OS is supported (although maybe
untested). For details see [this platform document](PLATFORMS.md).

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

## LICENSE

MIT or Apache 2.0

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in pgp by you, as defined in the Apache-2.0 license, shall be
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
