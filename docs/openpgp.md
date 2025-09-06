# Overview of OpenPGP formats and mechanisms 

## Currently widespread (mostly from RFC 4880)

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

Algorithms:

- Asymmetric cryptography:
  - ECDSA/ECDH over NIST P 256, 384, 521 curves (originally from RFC 6337)
  - ECDSA/ECDH over brainpool P256r1, P384r1, P512r1 curves (not currently available in rPGP)
- Symmetric encryption: Twofish, Camellia 128, 192 and 256 (RFC 5581)

## Modern and/or upcoming

### From RFC 9580

Version 6 Keys and Signatures, SEIPDv2 encryption

Algorithms:

- EdDSA/ECDH over Curve 448
- Hash algorithms: SHA-3 (SHA3-256, SHA3-512)

Note that RFC 9580 defines new algorithm ids and names for use of Curve 25519 with EdDSA and ECDH.
These new formats exist in parallel to the commonly used Curve 25519 formats, but with a much simpler wire format.
While these newly specified OpenPGP algorithms don't use different cryptographic mechanisms, they are not interchangeable with the pre-existing ones.

### From draft-ietf-openpgp-pqc

...

## Legacy

These formats and algorithms should not be produced anymore, however, under some circumstances it may be useful and appropriate to read existing artifacts, and interact with them. Note that in some cases interacting with legacy artifacts may require additional caution.

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
- Hash algorithms: MD-5, SHA-1 and RIPEMD-160

## Not standardized as part of OpenPGP

- ECDSA/ECDH over Secp256k1
- GnuPG's "OCB" encryption (rPGP has read-only support for this format)

## Shared/baseline infrastructure

- ASCII armoring
- Cleartext signature framework
