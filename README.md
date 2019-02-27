# rPGP

[![crates.io version][crate-shield]][crate] [![CircleCI build status][circle-shield]][circle] [![Appveyor build status][appveyor-shield]][appveyor] [![Docs][docs-shield]][docs] [![License][license-shield]][license]

> Pure rust implementation of OpenPGP. Following [RFC4880](https://tools.ietf.org/html/rfc4880.html) and [RFC2440](https://tools.ietf.org/html/rfc2440).



> ⚠️ **WARNING:** This library has **not** been audited, so be careful.



## Status

You can find the details of the currently supported features in [this status document](STATUS.md)




## Platform Support

Windows, Linux, MacOS and every other unix-like OS is supported (although maybe
untested). The following targets are known to work and pass all tests:

### Linux

* x86_64-unknown-linux-gnu

> Note: currently not tested on CI, but likely working.

* aarch64-unknown-linux-gnu
* arm-unknown-linux-gnueabi
* armv7-unknown-linux-gnueabihf
* i586-unknown-linux-gnu
* i686-unknown-linux-gnu
* mips-unknown-linux-gnu
* mips64-unknown-linux-gnuabi64
* mips64el-unknown-linux-gnuabi64
* mipsel-unknown-linux-gnu
* powerpc-unknown-linux-gnu
* powerpc64-unknown-linux-gnu
* powerpc64le-unknown-linux-gnu
* x86_64-unknown-linux-musl

### Android

> Note: currently not test on CI, but likely working.

* aarch64-linux-android
* arm-linux-androideabi
* armv7-linux-androideabi
* x86_64-linux-android

### iOS

> Note: currently not tested on CI, but likely working.

* i386-apple-ios
* x86_64-apple-ios
* armv7-apple-ios
* armv7s-apple-ios

### MacOS X

* x86_64-apple-darwin

> Note: currently not tested on CI, but likely working.

* i686-apple-darwin


### Windows

* i686-pc-windows-gnu
* x86_64-pc-windows-gnu
* i686-pc-windows-msvc
* x86_64-pc-windows-msvc

## Developement

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

[circle-shield]: https://img.shields.io/circleci/project/github/dignifiedquire/rpgp/master.svg?style=flat-square
[circle]: https://circleci.com/gh/dignifiedquire/rpgp/
[appveyor-shield]: https://ci.appveyor.com/api/projects/status/99y4f73itv7yvt93/branch/master?style=flat-square
[appveyor]: https://ci.appveyor.com/project/dignifiedquire/pgp/branch/master
[docs-shield]: https://img.shields.io/badge/docs-online-blue.svg?style=flat-square
[docs]: https://docs.rs/crate/pgp/
[license-shield]: https://img.shields.io/badge/License-MIT%2FApache2.0-green.svg?style=flat-square
[license]: https://github.com/dignifiedquire/rpgp/blob/master/LICENSE.md
[crate-shield]: https://img.shields.io/crates/v/pgp.svg?style=flat-square
[crate]: https://crates.io/crates/pgp
