# Security Status

## Known Issues

The used [`rsa`](https://crates.io/crates/rsa) crate is vulnerable to the Marvin attack and potentially other side channel attacks. This is being tracked and worked on actively:

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

## Occurrence of weak algorithms in rPGP

### SHA-1

SHA-1 is not considered cryptographically secure, practical attacks exist.

However, OpenPGP can use the SHA-1 hash algorithm in a number of different contexts:

1. Fingerprints for v4 keys
2. As a hash algorithm in signatures
3. In SEIPDv1 encrypted messages for modification detection

These mechanisms all have modern replacements in RFC 9580.

Specifically, 2. (using SHA-1 in signatures) has been deprecated in OpenPGP for a long time, SHA-2 has already been
specified in RFC 4880, in the year 2007. Applications that use rPGP should consider using policies that don't accept
signatures that hinge on SHA-1 hashes, as appropriate.

rPGP uses [sha1-checked](https://crates.io/crates/sha1-checked) for 1. and 2. since version 0.13.0
(see https://github.com/rpgp/rpgp/pull/353).

This mitigates the currently known practical attacks, but is of course only a stopgap measure.

For case 3., collisions are not a concern, so rPGP uses the cheaper unchecked basic sha1 implementation.
(Still, RFC 9580 specifies SEIPDv2, which uses a modern AEAD construction, and aims to eventually replace SEIPDv1.)

### MD5

Analogous to SHA-1, in historical OpenPGP artifacts, MD5 hashes can occur. Specifically:

- Fingerprints for v3/v2 keys
- As hash algorithm in signatures

rPGP supports interacting with such artifacts, but they should be considered cryptographically insecure by
applications.
