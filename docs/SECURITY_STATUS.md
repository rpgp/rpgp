# Security Status

## Known Issues

The used [`rsa`](https://crates.io/crates/rsa) crate is vulnerable to the Marvin attack and potentitally other side channel attacks. This is being tracked and worked on actively:

- https://github.com/RustCrypto/RSA/issues/19
- https://github.com/RustCrypto/RSA/pull/394

## Security Audits

rPGP and its RSA dependency received an independent security audit and a security analysis.

### 2024

[Hardening Guaranteed End-to-End encryption based on a security analysis from ETH researchers](https://delta.chat/en/2024-03-25-crypto-analysis-securejoin)

All discovered issues have been fixed.

### 2019

[Security Assessment of DeltaChat's RPGP and
RustCrypto RSA Libraries for the Open Tech
Fund](https://delta.chat/assets/blog/2019-first-security-review.pdf).

No critical flaws were found and we have fixed most high, medium and low risk ones.
