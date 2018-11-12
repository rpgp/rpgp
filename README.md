# PGP in Rust

[![Build Status](https://travis-ci.org/dignifiedquire/pgp.svg?branch=master)](https://travis-ci.org/dignifiedquire/pgp) [![Build status](https://ci.appveyor.com/api/projects/status/d1knobws948pyynk/branch/master?svg=true)](https://ci.appveyor.com/project/dignifiedquire/pgp/branch/master)

> Rust implementation of PGP. Following [RFC4880](https://tools.ietf.org/html/rfc4880.html) and [RFC2440](https://tools.ietf.org/html/rfc2440).

[Documentation](https://docs.rs/pgp)

## Warning

**Work in progress:** Not usable yet, but hopefully soon

## Developement

To enable debugging, add

```rust
use pretty_env_logger;
let _ = pretty_env_logger::try_init();
```

And then run tests with `RUST_LOG=pgp=info`.

## LICENSE

MIT or Apache 2.0
