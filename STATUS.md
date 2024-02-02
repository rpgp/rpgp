# Status

Symbols:

- 🚧 Work in Progress
- 🚫 Not planned
- ❓ Maybe implement

## Low Level API

- [x] Packet Parser
  - [x] Old Format ("v3")
  - [x] New Format (RFC 2440, 4880) ("v4")
  - [ ] draft-koch-librepgp Format ("v5")
  - [ ] draft-ietf-openpgp-crypto-refresh Format ("v6")
- [x] Packet Generation
- [x] ASCII Armor
  - [x] Reading
  - [x] Writing
- [ ] Cleartext Signature Framework
- [x] Signatures (v4)
  - [x] Validation
  - [x] Generation
- [ ] Signatures (v6)
  - [ ] Validation
  - [ ] Generation
- [ ] Encryption
  - [x] PKESK v3, SKESK v4, SEIPD v1
  - [ ] PKESK v6, SKESK v6, SEIPD v2
- [ ] Decryption
  - [x] PKESK v3, SKESK v4, SEIPD v1
  - [ ] PKESK v6, SKESK v6, SEIPD v2
- [x] Keys (v4)
  - [x] Generation
  - [x] Export
  - [x] Import
- [ ] Keys (v6)
  - [ ] Generation
  - [ ] Export
  - [ ] Import
- [x] Public-Key Algorithms
  - [x] RSA
  - [ ] 🚫 Elgamal (Encrypt only)
  - [x] DSA
  - [x] ECDH
  - [x] ECDSA
  - [x] EdDSA
- [ ] Supported Elliptic Curves
  - [X] NIST P256
  - [X] NIST P384
  - [ ] NIST P521
  - [ ] brainpoolP256r1
  - [ ] brainpoolP384r1
  - [ ] brainpoolP512r1
  - [x] Curve 25519
  - [ ] Curve 448
  - [x] Secp256k1
- [x] Symmetric Algorithms
  - [x] Plaintext
  - [x] IDEA
  - [x] DES
  - [x] CAST5
  - [x] Blowfish
  - [x] AES 128
  - [x] AES 192
  - [x] AES 256
  - [x] Twofish
  - [x] Camellia 128
  - [x] Camellia 192
  - [x] Camellia 256
- [x] Hash Algorithms
  - [x] MD5
  - [x] SHA-1
  - [x] RIPE-MD/160
  - [x] SHA2 256
  - [x] SHA2 384
  - [x] SHA2 512
  - [x] SHA2 224
  - [x] SHA3 256
  - [x] SHA3 512
- [ ] Compression Algorithms
  - [x] ZIP
  - [x] ZLIB
  - [ ] 🚫 BZip2
- [ ] AEAD Algorithms
  - [ ] OCB
  - [ ] EAX
  - [ ] GCM
- S2K
  - [x] Iterated and Salted
  - [ ] Argon2

## High Level API

Not yet started
