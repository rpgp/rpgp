# Changelog

All notable changes to pgp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

# [Unreleased]

## Changed

- Made members of `OnePassSignature` public [#234](https://github.com/rpgp/rpgp/pull/234)
- Update to newly published `rsa@0.9.0` [#240](https://github.com/rpgp/rpgp/pull/240)


# [v0.10.1]

## Breaking

- Ensures that signature validation is more strict, by ensuring that issuers match the key id. This is now stricter than in `0.9`.

# [v0.10.0] - YANKED

## Breaking

- Update MSRV to 1.65

## Added

- ECDSA support for P256 and P384 [#204](https://github.com/rpgp/rpgp/pull/204) and [#215](https://github.com/rpgp/rpgp/pull/215).
- Expand cipher support to include Camellia and Idea [#198](https://github.com/rpgp/rpgp/pull/198).
- Improved support for unicode and UTF8 [#221](https://github.com/rpgp/rpgp/pull/198).

## Removed

## Changed

- Update dependencies [#218](https://github.com/rpgp/rpgp/pull/218), [#214](https://github.com/rpgp/rpgp/pull/214), [#219](https://github.com/rpgp/rpgp/pull/219), [#229](https://github.com/rpgp/rpgp/pull/229).


[Unreleased]: https://github.com/rpgp/rpgp/compare/v0.10.0...HEAD
[v0.10.1]: https://github.com/rpgp/rpgp/compare/v0.10.0...v0.10.1
[v0.10.0]: https://github.com/rpgp/rpgp/compare/v0.9.0...v0.10.0
