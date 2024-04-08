# Contributing

## Development

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
