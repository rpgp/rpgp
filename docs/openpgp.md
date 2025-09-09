# Overview of OpenPGP formats and mechanisms 

[RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) specifies most OpenPGP formats and mechanisms.
Some of them have also been specified in earlier OpenPGP RFCs.

This document provides a rough overview of formats and mechanisms and their origin, and outlines implementation support.

## Currently widespread (mostly from RFC 4880)

The following set of formats and mechanisms is widely supported.
It interoperates with all implementations of OpenPGP of the last many years.

Formats:

- Version 4 Keys
- Version 4 Signatures
- SEIPDv1 encryption

Algorithms:

- Asymmetric cryptography:
  - EdDSA/ECDH over Curve 25519
  - RSA
- Symmetric encryption: AES (128, 192 and 256)
- Hash algorithms: SHA-2 (SHA-256, SHA-384, SHA-512, SHA-224)

### Also current and standardized, but less widespread

The following set of cryptographic algorithms is also long-established.
However, these algorithms are less universally supported.
They should probably only be produced if a specific need indicates their use.

Algorithms:

- Asymmetric cryptography:
  - ECDSA/ECDH over NIST P 256, 384, 521 curves (originally from [RFC 6337](https://www.rfc-editor.org/rfc/rfc6637))
  - ECDSA/ECDH over brainpool P256r1, P384r1, P512r1 curves (not currently available in rPGP)
- Symmetric encryption: Twofish, Camellia 128, 192 and 256 ([RFC 5581](https://www.rfc-editor.org/rfc/rfc5581))

## Modern and/or upcoming

### From RFC 9580

The following set of formats and mechanisms is widely supported in most modern implementations of OpenPGP.
Notably, however, GnuPG does not yet implement support for the new formats in RFC 9580.
So interoperability of these formats and mechanisms is limited to the (large and growing) set of other implementations.

Formats:

- Version 6 Keys
- Version 6 Signatures
- SEIPDv2 encryption

Algorithms:

- EdDSA/ECDH with Curve 448
- AEAD encryption (in modes OCB, EAX and GCM)
- Hash algorithms: SHA-3 (SHA3-256, SHA3-512)

Note that RFC 9580 defines new algorithm ids and names for use of Curve 25519 with EdDSA and ECDH (the new algorithms are named "Ed25519" and "X25519" in RFC 9580).
These new formats exist in parallel to the commonly used Curve 25519 formats, but with a much simpler wire format.
The old variants are named "EdDSALegacy with Ed25519Legacy" and "ECDH with Curve25519Legacy" in RFC 9580.

While these newly specified OpenPGP algorithms don't use different cryptographic mechanisms, they are not interchangeable with the pre-existing ones.

### From draft-ietf-openpgp-pqc

The draft document [draft-ietf-openpgp-pqc](https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-pqc) defines post-quantum algorithm extensions for OpenPGP.

This draft is not finalized, but it is in a late stage of development.
Finalization as an RFC is pending, and anticipated in the coming months.

- Asymmetric cryptography:
  - ML-DSA-65+Ed25519, ML-DSA-87+Ed448 (hybrid signatures)
  - SLH-DSA-SHAKE 128s, 128f, 256s (hash-based signature scheme)
  - ML-KEM-768+X25519, ML-KEM-1024+X448 (hybrid encryption)

Of these, ML-KEM-768+X25519 keys may be used as encryption subkeys of v4 keys.
All other of the PQC algorithms may only be used in v6 OpenPGP keys.

rPGP implements support for the latest version of this draft ("draft-ietf-openpgp-pqc-12"), feature-gated as `draft-pqc`.

Note that, as the standard is not finalized, applications should *not emit these formats in production* use yet!
That said, rPGP's implementation enables experimentation with PQC today (and it has been shown to interoperate with other implementations).

## Legacy

These formats and algorithms should not be produced anymore.
However, under some circumstances it may be useful and appropriate to read existing artifacts, and interact with them.
Note that in some cases interacting with legacy artifacts may require additional caution!

Formats:

- Version 2/3 Keys
- Version 2/3 Signatures
- SED encryption format
 
Algorithms:

- Asymmetric cryptography:
  - DSA (especially with small key sizes)
  - RSA with small key sizes
  - Elgamal encryption (not supported by rPGP)
- Symmetric encryption: IDEA, DES, CAST5, Blowfish
- Hash algorithms: MD5, SHA-1 and RIPEMD-160

## Not standardized as part of OpenPGP

- ECDSA/ECDH over Secp256k1
- GnuPG's "OCB" encryption (rPGP has read-only support for this format)

## Shared/baseline infrastructure

- ASCII armoring
- Cleartext signature framework
