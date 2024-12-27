# Security Status

## Known Issues

The used [`rsa`](https://crates.io/crates/rsa) crate is vulnerable to the Marvin attack and potentitally other side channel attacks. This is being tracked and worked on actively:

- https://github.com/RustCrypto/RSA/issues/19
- https://github.com/RustCrypto/RSA/pull/394

## Security Audits

rPGP and its RSA dependency received two independent security audits and a security analysis.

### 2024-12

Audit ["Nlnet Security Evaluation rPGP"](https://github.com/rpgp/docs/blob/main/audits/NGI%20Core%20rPGP%20penetration%20test%20report%202024%201.0.pdf) by [Radically Open Security](https://www.radicallyopensecurity.com/).

Two advisories were released about the findings of this audit:

- ["Panics on Malformed Untrusted Input"](https://github.com/rpgp/rpgp/security/advisories/GHSA-9rmp-2568-59rv) CVE-2024-53856
- ["Potential Resource Exhaustion when handling Untrusted Messages"](https://github.com/rpgp/rpgp/security/advisories/GHSA-4grw-m28r-q285) CVE-2024-53857

The issues outlined in these advisories have been fixed.

### 2024-03

[Hardening Guaranteed End-to-End encryption based on a security analysis from ETH researchers](https://delta.chat/en/2024-03-25-crypto-analysis-securejoin)

All discovered issues have been fixed.

### 2019

[Security Assessment of DeltaChat's RPGP and
RustCrypto RSA Libraries for the Open Tech
Fund](https://delta.chat/assets/blog/2019-first-security-review.pdf).

No critical flaws were found and we have fixed most high, medium and low risk ones.
