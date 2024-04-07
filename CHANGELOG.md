# Changelog

All notable changes to rpgp will be documented in this file.

## [0.12.0-alpha.2](https://github.com/rpgp/rpgp/compare/v0.12.0-alpha.1..0.12.0-alpha.2) - 2024-04-07

### ⛰️  Features

- Basic support for AEAD ([#316](https://github.com/rpgp/rpgp/issues/316)) - ([93ca7d8](https://github.com/rpgp/rpgp/commit/93ca7d8f5d002677c51be0438564522e636b014d))
- Avoid Seek  - ([fa82b12](https://github.com/rpgp/rpgp/commit/fa82b12fcd69ea7dbfba83914a972c0cabbe1b5f))
- Cleartext framework support  - ([66b005c](https://github.com/rpgp/rpgp/commit/66b005c11467068bac9599c27c9d90bc405095d6))

### 🐛 Bug Fixes

- *(packet-parser)* Increase buffer size for unknown size - ([1013c13](https://github.com/rpgp/rpgp/commit/1013c134c90b7e38c02de9d74fc61780e06bfa05))

### 🚜 Refactor

- Improve internal crypto abstractions to allow for more flexibility - ([a3dd485](https://github.com/rpgp/rpgp/commit/a3dd485f9be48024b7756358e0e6d13d54101790))
- Break out ecdh unwrap - ([bde459c](https://github.com/rpgp/rpgp/commit/bde459ccb759903e63e90f201a1526353a33c6d5))
- Move benches to criterion and expand benchmarks - ([8e87774](https://github.com/rpgp/rpgp/commit/8e87774cc08b9549e5a374d75b41b585768c053d))

### 🧪 Testing

- Approximate decryption and signing operations with an OpenPGP card - ([42cfa11](https://github.com/rpgp/rpgp/commit/42cfa11b5c3661166f561b613439d0ac6d40a9b8))

### ⚙️ Miscellaneous Tasks

- Fix feature = "cargo-clippy" deprecation - ([a75db54](https://github.com/rpgp/rpgp/commit/a75db5470ea75f5c392f0b5688da76762a42ca0b))
- Set debug in Cargo.toml to the normalized value - ([29adca7](https://github.com/rpgp/rpgp/commit/29adca744539955ccc16895afb8e7f8504936aa3))

### Bench

- Add benchmarks for s2k ([#325](https://github.com/rpgp/rpgp/issues/325)) - ([ff2a3fc](https://github.com/rpgp/rpgp/commit/ff2a3fcd26ce951a6f45e90fbb87d42e8d13fab7))

## [0.12.0-alpha.1](https://github.com/rpgp/rpgp/compare/v0.11.0..v0.12.0-alpha.1) - 2024-03-17

### ⛰️  Features

- Export a crate VERSION string - ([1808c99](https://github.com/rpgp/rpgp/commit/1808c994746b3e54d76ed16d5512dee2ff031ba1))
- Obfuscate symmetric key length with ecdh padding - ([2fc374a](https://github.com/rpgp/rpgp/commit/2fc374aeb4eccee16238109159e62e8e58187b7b))
- Implement hash_alg() and public_params() for SecretKeyTrait - ([bb7782d](https://github.com/rpgp/rpgp/commit/bb7782dbcbf839ddefb05664c574ecc2ed653ba0))
- Implement support for ECDSA over NIST P-521 - ([14d0f6a](https://github.com/rpgp/rpgp/commit/14d0f6a185a597a317a39437397a0a929b0a600d))
- Eadd reader functions that autodetect armored vs. binary - ([efd27c0](https://github.com/rpgp/rpgp/commit/efd27c0bf0d22499f9739c46f9539859fde26874))

### 🐛 Bug Fixes

- *(ecdsa)* Never pad ecdsa secret MPIs - ([87cb242](https://github.com/rpgp/rpgp/commit/87cb2421fc2cc9d604ca74c691f0878e3fc3436d))
- *(parser)* There should be no edata except after ESKs - ([cadccd5](https://github.com/rpgp/rpgp/commit/cadccd5c66c46a2b86cb7ae39e34ef4da45dcc4f))
- *(test)* Adjust to changed message decryption interface - ([e57c49a](https://github.com/rpgp/rpgp/commit/e57c49af90a2657887dce980d69a48971865f808))
- Avoid stack overflow when verifying recursively compressed message - ([bfa34bb](https://github.com/rpgp/rpgp/commit/bfa34bbe3ced26b28c411ebbdd4e9a96800949d9))
- Configure hash_alg based on signing key type - ([6cda288](https://github.com/rpgp/rpgp/commit/6cda28834af077889fbfd60adfaab5feafbaf1d3))

### 🧪 Testing

- Increase key_gen_ecdsa_p256 rounds - ([f7fd18d](https://github.com/rpgp/rpgp/commit/f7fd18d2986f00e7536881bab1416ababdeda8bf))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.12.0-alpha.1 - ([2d255ed](https://github.com/rpgp/rpgp/commit/2d255ed462374e19ac6c8a9b60a274cd0b794c9c))
- Adjust to chrono deprecations - ([d0bf0fd](https://github.com/rpgp/rpgp/commit/d0bf0fdb6e61dfeb8a7c4adabc10696d522465b1))

### S2k

- Restructure, implement argon2 - ([6298c15](https://github.com/rpgp/rpgp/commit/6298c1580b7e631f5bdec1a96f56ba6e9cf85217))

## [0.11.0](https://github.com/rpgp/rpgp/compare/v0.10.2..v0.11.0) - 2024-02-21

### ⛰️  Features

- Add Signature::verify_key_binding_primary_back_sig  - ([2764b39](https://github.com/rpgp/rpgp/commit/2764b39f065c69ee7276af872ec1e529753f68f9))
- Implement support for Secp256k1 ([#275](https://github.com/rpgp/rpgp/issues/275)) - ([0d8e580](https://github.com/rpgp/rpgp/commit/0d8e58096cdc7770460942c653815463a925f954))
- Add dsa support - ([4ed459b](https://github.com/rpgp/rpgp/commit/4ed459be58d09d9949894a8fffe30e75bc1a8b7d))
- Generalize packet parsing to accept more unknown values; packet parser error type distinguishes "hard and soft" errors. - ([48af40c](https://github.com/rpgp/rpgp/commit/48af40c9afa787fd8815d8da038c2425ceee4477))
- Handle distinction between hard and soft packet parsing errors - ([6752d83](https://github.com/rpgp/rpgp/commit/6752d835384068bf710d87550550e49a1e384f1a))
- Implement From<SignedSecretKey> for SignedPublicKey and From<SignedSecretSubKey> for SignedPublicSubKey - ([43370c5](https://github.com/rpgp/rpgp/commit/43370c5a97d431d97f11aad8761877bd8dd0840d))

### 🐛 Bug Fixes

- *(terminology)* Use "certification" where we mean signatures that confirm identities - ([44bccd3](https://github.com/rpgp/rpgp/commit/44bccd3a026b6eda7099065f80e972ef88863f8a))
- Handle other RevocationCode values - ([6167e99](https://github.com/rpgp/rpgp/commit/6167e99473220d5e3c1bee3ce60fa62216a0247c))
- Return an error in Message::verify if we don't know what to verify - ([e29d089](https://github.com/rpgp/rpgp/commit/e29d089ec96b985c5263b7637713d0a9ecad60fa))
- Handle expiration times as Duration - ([1cb17a1](https://github.com/rpgp/rpgp/commit/1cb17a122ede618d8bd1af01b7de9ab464475ee5))
- Check SHA-1 checksum before parsing  - ([fd36c23](https://github.com/rpgp/rpgp/commit/fd36c23d47a08e58a7d44b94e6915edf1edb3961))
- Normalize line endings when hashing data for a Text signature - ([65c9e46](https://github.com/rpgp/rpgp/commit/65c9e46975c62ede7ac3427dc458109a371041cb))
- Move line ending normalization from Message::verify to Signature::verify - ([20dd658](https://github.com/rpgp/rpgp/commit/20dd6584c8587ecaea3483ffb5356647f914b385))
- Debug output cleanup - ([4e7ba07](https://github.com/rpgp/rpgp/commit/4e7ba07f5c10239f7fe7961c906c6c4ebef9ddf7))
- Do not allow decryption with "Plaintext" algorithm - ([9201b7e](https://github.com/rpgp/rpgp/commit/9201b7e59d96e6873c284ab428fd038b778d7dfc))
- Enforce Partial Body Length "MUST" from RFC 4880 - ([d37a7b5](https://github.com/rpgp/rpgp/commit/d37a7b538852c208ebe2e7adcf82464b239bcd57))
- Clarify use of subpackets from hashed and unhashed areas - ([7f1ae5c](https://github.com/rpgp/rpgp/commit/7f1ae5c650dc1f2b735274c5ad9fae9214318fd7))
- [**breaking**] Generalize issuer subpacket checks - ([7c43d22](https://github.com/rpgp/rpgp/commit/7c43d2298fe37a4c1188e9110c00e622640ee1b3))
- Make ECDH unpadding more robust - ([bf7a3f3](https://github.com/rpgp/rpgp/commit/bf7a3f3dba0822611c34941d5d820061f803ea60))

### 🚜 Refactor

- Switch from num_derive to num_enum - ([8014e49](https://github.com/rpgp/rpgp/commit/8014e4959579dc4ccf2791fef601fbd48bdce3df))

### 📚 Documentation

- *(readme)* Fix CI status image and rust version badge - ([59c9d73](https://github.com/rpgp/rpgp/commit/59c9d732694c34694b99ea3c1c511afef0cd258c))
- Remove unnecessary backticks ([#252](https://github.com/rpgp/rpgp/issues/252)) - ([2b17b30](https://github.com/rpgp/rpgp/commit/2b17b30b8acb2eff0d330c60bb46080ce59e837b))
- Roughly reflect formats/mechanisms from draft-ietf-openpgp-crypto-refresh - ([97edf8f](https://github.com/rpgp/rpgp/commit/97edf8fd3073eac2f11cd717896db288c61f6589))
- Clarify parameters in verify_key_binding_internal - ([b82cd3f](https://github.com/rpgp/rpgp/commit/b82cd3f71d1c4ffacb27ea287d5041e8ec0f8959))
- Switch to git-cliff for changelog - ([39444e5](https://github.com/rpgp/rpgp/commit/39444e5a316168412eab0c59c072fc5feaf4b275))

### ⚡ Performance

- Avoid `concat` in sha1 checksum impl - ([f56529f](https://github.com/rpgp/rpgp/commit/f56529faf44e37984328286220aa266d4ec0d26a))

### 🧪 Testing

- Read signature with "other" revocation code - ([dd3742b](https://github.com/rpgp/rpgp/commit/dd3742b77a8e9c05276d0c51eb4ff937f391df5e))
- Add test for normalization of line endings with text-mode signatures - ([19c3d1d](https://github.com/rpgp/rpgp/commit/19c3d1dc6ed1d3db6a9aa22df4c2f22d87956d81))
- Test that verifying unsigned messages fails - ([5a1e8c7](https://github.com/rpgp/rpgp/commit/5a1e8c784446e99295de310bd885c4078ed91374))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.11.0 - ([20335b3](https://github.com/rpgp/rpgp/commit/20335b387037bfedd1b3cdb4a48fb7466f721b56))
- Fix deprecation warning reported by clippy - ([a9a7a0b](https://github.com/rpgp/rpgp/commit/a9a7a0b02cab4a6892ae0158b23757f3ad41371e))
- Fix vec performance lint - ([7aa80c9](https://github.com/rpgp/rpgp/commit/7aa80c9dd94b5fda0d2d9c9f9798e9379a5ea6d0))
- Use 1.72 stabley toolchain instead of stable for mips - ([334c0b8](https://github.com/rpgp/rpgp/commit/334c0b83e6339c774b6ed05e7ff9d8b0aed54894))
- Set Rust version to 1.67 - ([0e673a2](https://github.com/rpgp/rpgp/commit/0e673a2f88aea89e33d6e921dfd51ac6a0dc7ee9))
- Fix clippy lint - ([8c4c27f](https://github.com/rpgp/rpgp/commit/8c4c27f8c078411a9d4df43d236fdef0f0af56d0))
- Fix clippy lints in tests - ([30b15e7](https://github.com/rpgp/rpgp/commit/30b15e71897ed16782992a08e1beb15381125e66))
- Update dalek deps and fix nightly on CI - ([414250a](https://github.com/rpgp/rpgp/commit/414250ad85f924ced11c45f3d44ed99089890278))
- Bump to Rust 1.70 - ([1dd37d2](https://github.com/rpgp/rpgp/commit/1dd37d2d9d106d3a1a4dbce99f734cd4fbed897b))

### Cleanup

- Rename Indeterminated to Indeterminate - ([5357815](https://github.com/rpgp/rpgp/commit/535781523618d99d90107deadb9927087dd516f3))

## [0.10.2](https://github.com/rpgp/rpgp/compare/v0.10.1..v0.10.2) - 2023-07-24

### ⛰️  Features

- Implement `LowerHex` and `UpperHex` for `KeyId` ([#244](https://github.com/rpgp/rpgp/issues/244)) - ([9bb9d97](https://github.com/rpgp/rpgp/commit/9bb9d97c91cbc5c9ed4b5aec1a9becf02f950681))
- Update dalek crypto deps ([#247](https://github.com/rpgp/rpgp/issues/247)) - ([93866d2](https://github.com/rpgp/rpgp/commit/93866d24673e4407f3c83873f83bf917c20feaba))

### 🐛 Bug Fixes

- Update to released rsa@0.9.0 - ([9226269](https://github.com/rpgp/rpgp/commit/922626913d495458eeff8a3255d6935b981e6d0a))

### 🚜 Refactor

- *(packet)* Make members of OnePassSignature public - ([6036902](https://github.com/rpgp/rpgp/commit/60369027980552a765d6f4fcf0f1776ea91c0c86))
- Fix warnings - ([1e300ac](https://github.com/rpgp/rpgp/commit/1e300acefc6b14641869cb2a8be77fd0f2e1d19c))

### 📚 Documentation

- *(readme)* Update a couple of minor points in README - ([caf57aa](https://github.com/rpgp/rpgp/commit/caf57aa75dbe20b73f051daa6d3bdf5d989de20b))
- Update changelog - ([659989b](https://github.com/rpgp/rpgp/commit/659989b94c626edf1f1d5b819f9d6c96370a750d))
- Changelog for 0.10.2 - ([8e762fa](https://github.com/rpgp/rpgp/commit/8e762fa0b230c6ab5413fed6abcf102dcfb245e8))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.10.2 - ([6a3430c](https://github.com/rpgp/rpgp/commit/6a3430c500b77b5b3285912b174a8177789a1a48))
- Fix clippy - ([e557ec7](https://github.com/rpgp/rpgp/commit/e557ec7aafa09476981f240c68d35e5a9d295b8e))

## [0.10.1](https://github.com/rpgp/rpgp/compare/v0.10.0..v0.10.1) - 2023-03-30

### 🐛 Bug Fixes

- *(ecdsa)* Store original MPI to preserve padding - ([848af8f](https://github.com/rpgp/rpgp/commit/848af8f9a6772c187e7f184cd75488b78d13f9eb))
- *(signature)* Return error on KeyId missmatch - ([02bef50](https://github.com/rpgp/rpgp/commit/02bef50de14f2e4300a9e709de87e4838c28a019))

### 📚 Documentation

- *(changelog)* Prepare v0.10.1 - ([fe3c69f](https://github.com/rpgp/rpgp/commit/fe3c69fbb083f3b0572c020debc2c2a0f9e2b1b9))

### 🧪 Testing

- Check critical bit encoding roundtrips - ([cc78011](https://github.com/rpgp/rpgp/commit/cc780117d7d6dd64c999acfb80ba4cefa55f356c))
- Skip non validating keys again - ([a0556f5](https://github.com/rpgp/rpgp/commit/a0556f53602a091c66a84fb7d6a91ae3b7ad4471))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.10.1 - ([951b8f9](https://github.com/rpgp/rpgp/commit/951b8f9d9b2818fdce964581a08f0e636fd3ecf1))

## [0.10.0](https://github.com/rpgp/rpgp/compare/v0.9.0..v0.10.0) - 2023-03-27

### ⛰️  Features

- *(crypto)* Add missing symmetric cipher support  - ([1648fbb](https://github.com/rpgp/rpgp/commit/1648fbb341987612e84590a3321db34469252a9a))
- *(deps)* Update base64 and derive_builder - ([59dcda7](https://github.com/rpgp/rpgp/commit/59dcda7761f027707b4f295c231b961f74b4e3e7))
- Implement support for ECDSA keys - ([65e2f86](https://github.com/rpgp/rpgp/commit/65e2f86a3e45867f95414bbd57061309f2ff0b26))
- Update nom to v7 - ([be4eaaa](https://github.com/rpgp/rpgp/commit/be4eaaaade6d57c3c2a9eebba0ce0b1ab0065823))
- Update to latest dependencies ([#218](https://github.com/rpgp/rpgp/issues/218)) - ([013923b](https://github.com/rpgp/rpgp/commit/013923b62af995fc1a26e9c918d1dbe8b1299c5d))
- Move from String to BString - ([b388e4e](https://github.com/rpgp/rpgp/commit/b388e4e1f17d22492b81c66483e3255d76b7235a))

### 🐛 Bug Fixes

- Update to new chrono apis - ([8651965](https://github.com/rpgp/rpgp/commit/8651965a689fd35bbd5f53cb64eb40eb348312be))
- Resolve merge issue - ([ed98330](https://github.com/rpgp/rpgp/commit/ed983308bb4f75800214962f86f52500e999473a))
- Edcsa support - ([a463cca](https://github.com/rpgp/rpgp/commit/a463cca1cb2bbefe4bb3148babee3685a06a14a6))
- Fixup doc comments - ([f55c7a5](https://github.com/rpgp/rpgp/commit/f55c7a56a987e5c92fb740029ff112b0a410564f))
- Nightly warnings - ([0917b01](https://github.com/rpgp/rpgp/commit/0917b015b1e82f0fcc87be94d83556b1b0eadfe8))

### 🚜 Refactor

- Remove unused param from `decrypt` - ([810379f](https://github.com/rpgp/rpgp/commit/810379f781f66c51cde309f46741232d4fbdca15))
- Followup to #214 - ([3730457](https://github.com/rpgp/rpgp/commit/3730457315bd6da72defe358ff86259a32d6843e))
- Switch from buf_redux to buffer-redux - ([8e42501](https://github.com/rpgp/rpgp/commit/8e42501119cea413ec52b3df0383dd4454e5a271))

### 📚 Documentation

- Create changelog  - ([3f72a28](https://github.com/rpgp/rpgp/commit/3f72a28dca657cf5e1af502703d01ecb69d18f2a))
- Changelog for v0.10.0 - ([d5ea053](https://github.com/rpgp/rpgp/commit/d5ea0537153788474013a3a533e2ad0a866fd763))

### ⚙️ Miscellaneous Tasks

- *(crypto/sym)* Drop unused block size arguments - ([5beeb40](https://github.com/rpgp/rpgp/commit/5beeb40cef9bf4ced1db33485a11efe30115fe58))
- *(pgp)* Release 0.10.0 - ([69db862](https://github.com/rpgp/rpgp/commit/69db862cca24ced16810f123890a07b8b69609bc))
- Happy clippy - ([30d83a8](https://github.com/rpgp/rpgp/commit/30d83a81fd8d41074908199c081bd0459211bc9d))
- Remove old release config - ([a8ced15](https://github.com/rpgp/rpgp/commit/a8ced157095dee9478a3511e9a660f6cf01f577b))

## [0.9.0](https://github.com/rpgp/rpgp/compare/v0.8.0..v0.9.0) - 2022-11-07

### ⛰️  Features

- Remove unused clear_on_drop dependency  - ([446c91b](https://github.com/rpgp/rpgp/commit/446c91bec7c2e022180f94764d9d5c9034260493))
- Allow subkeys to be created with the authentication flag enabled - ([e37e921](https://github.com/rpgp/rpgp/commit/e37e921cdfb724931bfcf52aaf2d321a2cf55372))
- Update to RSA 0.7.0 interfaces - ([c57232e](https://github.com/rpgp/rpgp/commit/c57232ea73ef35e3a5d3ffa08d880c2dd37cbd8c))
- Edition 2021 and update crypto deps  - ([a0a71cc](https://github.com/rpgp/rpgp/commit/a0a71cc3f836cea69e721877baf2f9895657f85d))

### 🚜 Refactor

- Replace find_map with a find  - ([721b287](https://github.com/rpgp/rpgp/commit/721b287983702316cdbf23cad0f416ab69c5e42a))
- Remove unused circular dependency and also rewrite IV handling to not require lazy_static - ([30aea2e](https://github.com/rpgp/rpgp/commit/30aea2eca4f45accf28867c294c9fe8a6b619172))

### 📚 Documentation

- *(readme)* Update msrv - ([ac20fa0](https://github.com/rpgp/rpgp/commit/ac20fa03fcaa07897c698160e219f6b1a4111279))
- Add comma in `README` for clearer message ([#185](https://github.com/rpgp/rpgp/issues/185)) - ([28c80c8](https://github.com/rpgp/rpgp/commit/28c80c85d1b3694e3f2622e9a9ee22e5c1d82702))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.9.0 - ([e07f443](https://github.com/rpgp/rpgp/commit/e07f443d2d3464e2d3b07ad9564a582ef59681d5))
- Upgrade pretty_assertions to 1 - ([0277001](https://github.com/rpgp/rpgp/commit/027700108a6b5f4c4dbd8a493c39f9dffed3e6d3))

## [0.8.0](https://github.com/rpgp/rpgp/compare/v0.7.2..v0.8.0) - 2022-07-01

### ⛰️  Features

- Update deps & introduce MSRV  - ([5d86ab3](https://github.com/rpgp/rpgp/commit/5d86ab33242fb5489b17017a742259a8c781b4cd))
- Add a method to construct a PublicKey from parameters - ([f0d3fa8](https://github.com/rpgp/rpgp/commit/f0d3fa859c72d82245c511b446ce10da92a8449b))
- Derive Clone on hasher types  - ([d878faa](https://github.com/rpgp/rpgp/commit/d878faac629ef0ebd30746e70092bf158afcdbc4))
- Apply clippy and update some deps  - ([66c4f76](https://github.com/rpgp/rpgp/commit/66c4f76ee7420c51d4f04e1f44400d4ec2d34ffb))

### 🐛 Bug Fixes

- *(deps)* Fix zeroize version - ([e8ca41c](https://github.com/rpgp/rpgp/commit/e8ca41c6a1ea79f22ac2f57bc1d3a6d1f0254ac6))
- Disable `oldtime` feature of `chrono` - ([9d24203](https://github.com/rpgp/rpgp/commit/9d2420396eed95c43d16c925c9883518898e99e8))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.8.0 - ([b3671d5](https://github.com/rpgp/rpgp/commit/b3671d572a9e2b161f80932324895f98faef0bc4))
- Switch to github actions - ([202e7c1](https://github.com/rpgp/rpgp/commit/202e7c1059393ae6540d3376348924e12e8c8c17))
- Update release.toml - ([fd6e45d](https://github.com/rpgp/rpgp/commit/fd6e45d5b1006ee7d6464010f2a0da5ac7d674d7))

## [0.7.2](https://github.com/rpgp/rpgp/compare/v0.7.1..v0.7.2) - 2021-08-27

### 🐛 Bug Fixes

- Do not panic on IDEA cipher - ([1b7e2d5](https://github.com/rpgp/rpgp/commit/1b7e2d53732ff3e2a5f339599464639c68fc6593))
- Update & freeze deps to ensure build ([#135](https://github.com/rpgp/rpgp/issues/135)) - ([054e00b](https://github.com/rpgp/rpgp/commit/054e00b081caa828335e52d39eb39b89a7eea2eb))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.7.2 - ([f0dd2d8](https://github.com/rpgp/rpgp/commit/f0dd2d8ff5d0da988530309edf81151b683110e3))
- Update dependencies - ([90c9e6e](https://github.com/rpgp/rpgp/commit/90c9e6e50ad9e342ad9f8756ae9de4859097cc14))

## [0.7.1](https://github.com/rpgp/rpgp/compare/v0.7.0..v0.7.1) - 2020-09-17

### ⛰️  Features

- Update crypto deps - ([cacb24d](https://github.com/rpgp/rpgp/commit/cacb24d926d671b3d5ab523ddfd949f8a2b213ab))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.7.1 - ([eb4c151](https://github.com/rpgp/rpgp/commit/eb4c151979cceee503bd6c79d16ec4c558693199))

## [0.7.0](https://github.com/rpgp/rpgp/compare/v0.6.1..v0.7.0) - 2020-08-24

### ⛰️  Features

- Make sign/verify utilize trait std::io::Read - ([b77e20e](https://github.com/rpgp/rpgp/commit/b77e20e706719c1a85fb9ba1246b9813550a3da7))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.7.0 - ([94af2bc](https://github.com/rpgp/rpgp/commit/94af2bc21408f55e13be1e45168342c25a85a2c3))
- Fmt + clippy - ([ca81f7b](https://github.com/rpgp/rpgp/commit/ca81f7b65e5ad7a421aaa4bd9a78dbb41a346acf))

## [0.6.1](https://github.com/rpgp/rpgp/compare/v0.6.0..v0.6.1) - 2020-07-20

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.6.1 - ([5c5b2d0](https://github.com/rpgp/rpgp/commit/5c5b2d04dd5a803f762462feb04128f18e752cdc))
- Update some dependencies - ([cbb8b14](https://github.com/rpgp/rpgp/commit/cbb8b1405d171f44b60cf2800786bce0c46ed9b4))

## [0.6.0](https://github.com/rpgp/rpgp/compare/v0.5.2..v0.6.0) - 2020-06-11

### ⛰️  Features

- Update to the latest rustrcrypto deps - ([218ddbd](https://github.com/rpgp/rpgp/commit/218ddbdb831b39f396a9cc9ad2f7ed52c22a42b4))

### 🚜 Refactor

- Happy clippy - ([709132b](https://github.com/rpgp/rpgp/commit/709132b972f329f1b7ba553a49f6be23b81bead5))

### 📚 Documentation

- Add a few doctests to showcase API usage  - ([c7b7442](https://github.com/rpgp/rpgp/commit/c7b7442c82e1ad315482f2082a5dcff169a0b3e4))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.6.0 - ([931f4a1](https://github.com/rpgp/rpgp/commit/931f4a14dd2476ec567636742c47646d6fec8f06))
- Update rust-toolchain - ([2370f72](https://github.com/rpgp/rpgp/commit/2370f729f5cabfc2f87c278028742a0b24c4bcf9))

## [0.5.2](https://github.com/rpgp/rpgp/compare/v0.5.1..v0.5.2) - 2020-04-02

### 🐛 Bug Fixes

- Handle short x25519 keys properly - ([c07ecab](https://github.com/rpgp/rpgp/commit/c07ecabfd058e79d1cb6aa841fc9488f466c550a))

### 🧪 Testing

- Introduce failing test for ecdh keygen - ([b7d5ee4](https://github.com/rpgp/rpgp/commit/b7d5ee4bb44f3dfa0dccc6f0712e7d7ad49bde11))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.5.2 - ([ff0b43c](https://github.com/rpgp/rpgp/commit/ff0b43cf6820fd952d93f304d72e18bd92f3965b))

## [0.5.1](https://github.com/rpgp/rpgp/compare/v0.5.0..v0.5.1) - 2020-03-04

### 🐛 Bug Fixes

- Undo regression in base64_decoder - ([e23fa4e](https://github.com/rpgp/rpgp/commit/e23fa4ef0ff3e4fb6e415764cb0c4adeae435a91))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.5.1 - ([921a370](https://github.com/rpgp/rpgp/commit/921a3701f10cf042feaf1732702786c3edb0d03e))

## [0.5.0](https://github.com/rpgp/rpgp/compare/v0.4.1..v0.5.0) - 2020-03-04

### 🐛 Bug Fixes

- Remove usage of slice_dequeu - ([d176e2e](https://github.com/rpgp/rpgp/commit/d176e2ea168d16696e3cf6ef2ab2d5fa9ed1f5b2))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.5.0 - ([ef4a1ca](https://github.com/rpgp/rpgp/commit/ef4a1cae8545264ad72ccd7c8bdf64747516c429))

## [0.4.1](https://github.com/rpgp/rpgp/compare/0.4.0..v0.4.1) - 2020-03-01

### 🐛 Bug Fixes

- Encode leading zeros in ECDH session key - ([c53ade9](https://github.com/rpgp/rpgp/commit/c53ade9dd789bb3395ddb0572f76b985e51900b9))
- Correct typo in feature name for ringbuf - ([52e2339](https://github.com/rpgp/rpgp/commit/52e233955a5f6490c57822899b6344498901c858))

### 🚜 Refactor

- Happy clippy - ([9ac9213](https://github.com/rpgp/rpgp/commit/9ac9213f54ad93c914711ae8d9329f9f533aadb3))

### 🧪 Testing

- Encrypt 1000 times in test_x25519_encryption - ([1cc0e22](https://github.com/rpgp/rpgp/commit/1cc0e223e6b4f4b63494e3828506bcaedf2b5b9b))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.4.1 - ([cfe081d](https://github.com/rpgp/rpgp/commit/cfe081d1cd08e74b32fca15a9886eb5d1c8df50c))
- Cargo fmt - ([d05f50b](https://github.com/rpgp/rpgp/commit/d05f50b7c1ec4efb0dcfa34b819fda1872e8e47d))
- Update rust-toolchain - ([cd59306](https://github.com/rpgp/rpgp/commit/cd59306f04a46fe87e0f95e23600f0df408f3cef))

## [0.4.0](https://github.com/rpgp/rpgp/compare/0.3.2..0.4.0) - 2019-12-11

### ⛰️  Features

- *(key)* Add Signed(Public|Secret)Key::expires_at() method - ([8928a24](https://github.com/rpgp/rpgp/commit/8928a249f848d46889f618fde914417f698ea76f))
- Update dependencies - ([bcbd6b6](https://github.com/rpgp/rpgp/commit/bcbd6b6682a1753619fc37b19c0762afc18614ab))
- Update dependencies ([#82](https://github.com/rpgp/rpgp/issues/82)) - ([4d8af17](https://github.com/rpgp/rpgp/commit/4d8af17841b3e09739aa48d35617169f13b3d534))

### 🐛 Bug Fixes

- Remove unused enum_primitive dependency - ([4cc60a1](https://github.com/rpgp/rpgp/commit/4cc60a1e45a781ea6e7f394ae2583844ac75d214))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.4.0 - ([a6cba1d](https://github.com/rpgp/rpgp/commit/a6cba1d2afcf3f387ecb9378ecb55c66aee2f702))

## [0.3.2](https://github.com/rpgp/rpgp/compare/0.3.1..0.3.2) - 2019-11-20

### ⛰️  Features

- *(ci)* Add cargo audit job - ([aca6121](https://github.com/rpgp/rpgp/commit/aca6121cb0b53a4a3f5c5f8f67c9f15a43265fb5))
- Return the same error from decrypt_protected on invalid MDC - ([83f7c03](https://github.com/rpgp/rpgp/commit/83f7c03283567fb8582d09a814e6b17cbe32a6c2))
- Add  is_encryption_key for KeyTrait - ([4a82994](https://github.com/rpgp/rpgp/commit/4a829941104596544fccb866bdd4617790db2d55))
- Turn info!() that are used for debugging/tracing into debug!() - ([5da47f4](https://github.com/rpgp/rpgp/commit/5da47f48e5a864c845d440ea1b06c068b8379ca8))

### 🐛 Bug Fixes

- *(line-reader)* Improve correctness of LineReader::seek - ([2a8e22a](https://github.com/rpgp/rpgp/commit/2a8e22a370f0a5deee9d0235080b756bd9dfe93c))
- Do not log sensitive information - ([b47b07f](https://github.com/rpgp/rpgp/commit/b47b07fc45838050fe0d63d48c7a18b1f2cc3103))
- Clarify error message for EdDSA encryption - ([347c804](https://github.com/rpgp/rpgp/commit/347c804ccea314fd6732c8c57ee6dffa47ea47e1))
- Return true from is_signing_key for ECDSA keys - ([6977b14](https://github.com/rpgp/rpgp/commit/6977b14479ffa079d5857861ca89e69e93c8bd55))

### 🚜 Refactor

- Remove email module - ([3dd50a7](https://github.com/rpgp/rpgp/commit/3dd50a7d68fa8f4efac7e117553104914938318a))

### 📚 Documentation

- Improve documentation and comments - ([610f23f](https://github.com/rpgp/rpgp/commit/610f23fcc3b8ffabe5459cf4e153fadceddbbd52))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.3.2 - ([33ff206](https://github.com/rpgp/rpgp/commit/33ff206379d826a922c9fad822f178a0987e657c))

## [0.3.1](https://github.com/rpgp/rpgp/compare/0.3.0..0.3.1) - 2019-10-22

### 🐛 Bug Fixes

- Improve feature handling  - ([6008e8c](https://github.com/rpgp/rpgp/commit/6008e8cf95e907bda0211a2cc00838b1e9df510c))

### 📚 Documentation

- *(readme)* Merge security review info into Status - ([ae230ea](https://github.com/rpgp/rpgp/commit/ae230eaa88bacbd56f50a8c723e53cef5e7ca4e5))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.3.1 - ([4b04dd0](https://github.com/rpgp/rpgp/commit/4b04dd06313f54de1634e08660f89c331e613ae8))

## [0.3.0](https://github.com/rpgp/rpgp/compare/0.2.5..0.3.0) - 2019-10-19

### ⛰️  Features

- Add nice api for standalone signatures - ([bb18f39](https://github.com/rpgp/rpgp/commit/bb18f39e5249e7555bf6525a15ba25e2318b152f))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.3.0 - ([fe1702f](https://github.com/rpgp/rpgp/commit/fe1702fdb2caafbdcf07dcd2a53f216215a1d940))

## [0.2.5](https://github.com/rpgp/rpgp/compare/0.2.4..0.2.5) - 2019-10-18

### ⛰️  Features

- Expose api to parse signatures easily - ([42ac01a](https://github.com/rpgp/rpgp/commit/42ac01a5c6fd121bb64cacdbed3de1ae96e11fed))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.2.5 - ([5bb4952](https://github.com/rpgp/rpgp/commit/5bb4952eaa01cac611fc4932b461f36fdef85d54))

## [0.2.4](https://github.com/rpgp/rpgp/compare/0.2.3..0.2.4) - 2019-10-13

### ⛰️  Features

- Add experimental wasm support - ([6e46489](https://github.com/rpgp/rpgp/commit/6e464896dba7b8a87c5aa1ec55c5591d612a4faa))
- Zero out memory for secret key structures - ([0837833](https://github.com/rpgp/rpgp/commit/0837833a6f35fdd8eebb4b5bc8e8483d52bf6f56))
- Zero out memory for secret key structures ([#57](https://github.com/rpgp/rpgp/issues/57)) - ([1b8b3a8](https://github.com/rpgp/rpgp/commit/1b8b3a837ad401c94f256cc383805d8953122e7a))

### 🐛 Bug Fixes

- *(crypto)* Do not panic on inputs being too short - ([5a01b79](https://github.com/rpgp/rpgp/commit/5a01b796c84860c1696f541c4de7f4529254c2af))
- Typ in debug impl for public params - ([86601ce](https://github.com/rpgp/rpgp/commit/86601ce470b825228eca80448ff1295bbf6b5bbe))

### 🚜 Refactor

- Improve some debug impls - ([2bc8e43](https://github.com/rpgp/rpgp/commit/2bc8e43ff39848c45e580aa9428adafc47e61503))

### 📚 Documentation

- *(readme)* Updates to reflect current status better - ([e633dda](https://github.com/rpgp/rpgp/commit/e633dda536c6caf2da38782dac8a9db846808550))
- *(readme)* Improve layout a bit - ([a073622](https://github.com/rpgp/rpgp/commit/a0736224c092d89d7b83c05b2b74c627dfda4227))
- *(readme)* Move wasm note - ([5a73721](https://github.com/rpgp/rpgp/commit/5a737214e2b68ce312be685aff9f234ce69acdde))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.2.4 - ([eec5aed](https://github.com/rpgp/rpgp/commit/eec5aed3e65616488586dfb3333216badab1987e))

## [0.2.3](https://github.com/rpgp/rpgp/compare/0.2.2..0.2.3) - 2019-10-09

### 🐛 Bug Fixes

- *(packet)* Correct string creation for LiteralData::to_string - ([dec514c](https://github.com/rpgp/rpgp/commit/dec514cd5f93c92609dd7e9e208ea01d24a6112a))
- *(packet)* Correct string creation for LiteralData::to_string ([#52](https://github.com/rpgp/rpgp/issues/52)) - ([4498a32](https://github.com/rpgp/rpgp/commit/4498a32dbb6de8bd742a61b739f84eeff566a653))
- Make armor parsing more resilient - ([425e76e](https://github.com/rpgp/rpgp/commit/425e76eb9b1ea361ef70676cf602dfc3995a1357))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.2.3 - ([004255c](https://github.com/rpgp/rpgp/commit/004255c6b3d1c6399431668d1e6d9eec324b2d22))

## [0.2.2](https://github.com/rpgp/rpgp/compare/0.2.1..0.2.2) - 2019-09-26

### 🐛 Bug Fixes

- *(ffi)* Ensure dpeendency is found again - ([15d274b](https://github.com/rpgp/rpgp/commit/15d274b6d1a89985d3f99cd9b8f59cb95924a1c8))
- Handle incomplete packets in a safer way  - ([f0a831a](https://github.com/rpgp/rpgp/commit/f0a831a640a10f9d2ac48636c3b6cd1a17707327))

### 🚜 Refactor

- Migrate to 2018 edition - ([27c7d4f](https://github.com/rpgp/rpgp/commit/27c7d4fb0846e9b4651f947d29e6578ecc61d064))

### ⚙️ Miscellaneous Tasks

- *(pgp)* Release 0.2.2 - ([b9b505e](https://github.com/rpgp/rpgp/commit/b9b505eba1bd60bfc3174474b7cdd3c0be7ebf31))
- Update toolchain - ([2f89841](https://github.com/rpgp/rpgp/commit/2f898418649a41c78322d5c79d9b06d09b56552f))
- Update clippy rules and rust-toolchain - ([b40641b](https://github.com/rpgp/rpgp/commit/b40641be665a4bdd189219468beec24bc4060ff1))
- Configure release - ([840582b](https://github.com/rpgp/rpgp/commit/840582bc7cf860ef7813831799fcb74c2b13af92))

## [0.2.1](https://github.com/rpgp/rpgp/compare/v0.2.0-alpha..0.2.1) - 2019-05-28

### 🐛 Bug Fixes

- *(armor)* Normalize line writing to ensure no empty new lines are written - ([0c17c48](https://github.com/rpgp/rpgp/commit/0c17c48336d00b2be95a8e404f1a437181c345be))
- *(ffi)* Compress messages by default - ([83c1e10](https://github.com/rpgp/rpgp/commit/83c1e101a32f48eba5abc4e343be90c58b30942f))
- *(packets)* Handle incomplete packets properly - ([b9ecee8](https://github.com/rpgp/rpgp/commit/b9ecee8aff4f835fc0ce50e2f3fd43e28cdefce9))
- *(signature)* Generate non nested one pass signature packets by default - ([44d6a44](https://github.com/rpgp/rpgp/commit/44d6a44a2b2ea4c69974604caa97345ef53448d7))

## [0.2.0-alpha](https://github.com/rpgp/rpgp/compare/0.2.0..v0.2.0-alpha) - 2019-03-26

### ⚙️ Miscellaneous Tasks

- *(cargo)* Fix ffi nesting - ([39cd03d](https://github.com/rpgp/rpgp/commit/39cd03d48d30c74d9c43da9f68e8bd9a1b8d80bd))

## [0.2.0](https://github.com/rpgp/rpgp/compare/v0.1.0..0.2.0) - 2019-03-26

### ⛰️  Features

- *(build)* Better feature selections - ([20ad4b8](https://github.com/rpgp/rpgp/commit/20ad4b830c6e52a3e3ab451d1e4386e65cccca36))
- *(crypto)* Bring back blowfish and twofish - ([eb18f39](https://github.com/rpgp/rpgp/commit/eb18f39759a620ac9041eb7be75608ca78c45b52))
- *(errors)* Implement From for nom::Err - ([b175ede](https://github.com/rpgp/rpgp/commit/b175ede83df2dc420f909d6ca6523f5d3f768aa2))
- *(ffi)* Add from_bytes and fingerprint methods - ([a1fd36d](https://github.com/rpgp/rpgp/commit/a1fd36df0ff13d1f9398b5237908716afc2d53fa))
- *(ffi)* Implement skey_from_bytes - ([460efdd](https://github.com/rpgp/rpgp/commit/460efdde1a9e2ec97394df0cef6244589357eb36))
- *(ffi)* Add error handling and is_public, is_secret - ([ea196bd](https://github.com/rpgp/rpgp/commit/ea196bd1bdadc4b36bb46d70f82fbb10dbc9243a))
- *(ffi)* Implement decryption - ([4a8d3a3](https://github.com/rpgp/rpgp/commit/4a8d3a377b64ac0fbddd9e8f492667058da8602d))
- *(ffi)* Add instructions to build for ios - ([3632230](https://github.com/rpgp/rpgp/commit/36322307f056e185b89addb8afa9ddd13d4a773f))
- *(ffi)* Enable some optimizations for building - ([81ae4ec](https://github.com/rpgp/rpgp/commit/81ae4ec0ddbc023f106d17a4d1654fe1b36529fb))
- *(ffi)* Better flags setting - ([370888f](https://github.com/rpgp/rpgp/commit/370888f93d0fad2fa7c4bba3e70a0e5c2719b4fc))
- *(hash)* Add support for SHA3 - ([1dfb7f7](https://github.com/rpgp/rpgp/commit/1dfb7f7298df0facb554cc4a731558307e859641))
- *(key)* Initial implementation of private key parsing - ([856b29f](https://github.com/rpgp/rpgp/commit/856b29f951eeeabb18d754c4f471f43a4ec8b562))
- *(key)* Setup infrastructure for decrypting private keys, decode rsa private keys - ([de45a64](https://github.com/rpgp/rpgp/commit/de45a643a6d3bf9646978ea1f310a4415d2a6a82))
- *(key)* Handle expiration and creation time - ([c314d09](https://github.com/rpgp/rpgp/commit/c314d09db404fb4623c76460aa7d1e150a3a3b3f))
- *(key)* Add fingerprint placeholder methods - ([62b4aef](https://github.com/rpgp/rpgp/commit/62b4aef4b268cafa9808c3010467b5dc7491fdb9))
- *(key)* Import private rsa keys into openssl - ([11ce8e4](https://github.com/rpgp/rpgp/commit/11ce8e434039acd655dc5bc5a94efcefeff42984))
- *(message)* Implement basic public key encryption - ([a2f6aeb](https://github.com/rpgp/rpgp/commit/a2f6aeb6ea35a22b8090ecf2acb657db8962ee91))
- *(message)* Implement password based encryption and decryption - ([a28167c](https://github.com/rpgp/rpgp/commit/a28167c4825198de30f68a6317e42c1e999a4096))
- *(message)* Implement signing - ([8c4f8f3](https://github.com/rpgp/rpgp/commit/8c4f8f3dea4e8d4323d461dcd6bb28a6b3a5ae38))
- *(messages)* Handle more test cases - ([e7bffdc](https://github.com/rpgp/rpgp/commit/e7bffdc82b0ed12c026d5fde80fbf8eabe0029f4))
- *(packet)* Add nids to ecccurve - ([23c89e3](https://github.com/rpgp/rpgp/commit/23c89e3e4fc02bb881f5d89920a05662e5b920e6))
- *(pgp-ffi)* Implement public key encryption & signing - ([7f89d3a](https://github.com/rpgp/rpgp/commit/7f89d3a119c38054afb18c17f4caebc887d9c1d1))
- *(pgp-ffi)* Add hashing and password en/decryption - ([6a667ed](https://github.com/rpgp/rpgp/commit/6a667ed49874c54f85a6050b520b70b2236baaab))
- *(sig)* Serialize all subpackets - ([85ec336](https://github.com/rpgp/rpgp/commit/85ec336ed3b144dee8f0c409d722652d1c495a0a))
- *(sym)* Add support for blowfish - ([2376d47](https://github.com/rpgp/rpgp/commit/2376d47db2bbf73a769771884c394a30c8ec35c6))
- *(util)* Add mpi_big - ([4a0ac3b](https://github.com/rpgp/rpgp/commit/4a0ac3b68933633d7e898bfbf7146802a4f3907c))
- Upgrade deps - ([a77d542](https://github.com/rpgp/rpgp/commit/a77d542debbb275fdb4b8189e2e010168f456b40))
- Add cast5 support - ([519974b](https://github.com/rpgp/rpgp/commit/519974b4b257e9119874f9ffa3c7664eba5fc937))
- Add zlib support - ([4c4abb9](https://github.com/rpgp/rpgp/commit/4c4abb9e320822cf2c736c1ee630b73d7b0a3c5c))
- Armor parsing is now fully streaming - ([a258ab7](https://github.com/rpgp/rpgp/commit/a258ab7fc0a91572758be2c2a2c0a62269f5800c))
- Less panics, no more unwraps, better error handling - ([f0bc505](https://github.com/rpgp/rpgp/commit/f0bc505a34581cb97b620d590c89d2807b7b918f))
- Packet parsing is now an iterator - ([9335fbe](https://github.com/rpgp/rpgp/commit/9335fbef7ba575cd73f271c6bea132e66fd6d16d))
- Print warning when skipping packets - ([c8d8680](https://github.com/rpgp/rpgp/commit/c8d86808690303bf748d3704280a8d5caef74d0d))
- Run tests and cross compile for more envs - ([ab9e87a](https://github.com/rpgp/rpgp/commit/ab9e87a10730c2b69d7a0ddd0fcffff4d61b9016))
- Signature parsing for v3 sigs - ([2c7795f](https://github.com/rpgp/rpgp/commit/2c7795f50c2eb1d036a45992d33a39a3628362ac))
- Start setting up infra structure for signature validation - ([2b03025](https://github.com/rpgp/rpgp/commit/2b03025bafad9bb50835dc40cdb290011536a7f0))
- Start implementation of packet serialization - ([91ebdf2](https://github.com/rpgp/rpgp/commit/91ebdf22028c76c4e3356d8e526e465e96c8a9e1))
- Validat subkey bindings - ([91a4235](https://github.com/rpgp/rpgp/commit/91a42359b73f0f8763281bd21e47fec759bbcc0c))
- Validate v2/v3 signatures - ([c3b0978](https://github.com/rpgp/rpgp/commit/c3b0978df9c3e27ee85ad1d316f544fc3195cd83))
- Signature verification - round 1 - ([d335fd5](https://github.com/rpgp/rpgp/commit/d335fd5180c2c5f88fdaaa8dba4fd6485e210096))
- Better serialization for signatures and key packets - ([f53e068](https://github.com/rpgp/rpgp/commit/f53e068128534f3eeb6d3e562daf38cfad625dae))
- Handle partial body lengths packets - ([605374f](https://github.com/rpgp/rpgp/commit/605374f9e008338c01beae689fdb06d9e99ba97f))
- Basic ascii armor message serialization - ([c2012b0](https://github.com/rpgp/rpgp/commit/c2012b0a3a4bb1fcd309de769da770e4b2150c6f))
- Handle more serialization cases - ([1fd92b0](https://github.com/rpgp/rpgp/commit/1fd92b0a46bb3c654baca9bb0aebb6995e9b7dbe))
- Much better key serialization - ([574ae42](https://github.com/rpgp/rpgp/commit/574ae42c702404847100ab6f3d4bdae3b27c4493))
- More custom debug impls - ([d8ed5a3](https://github.com/rpgp/rpgp/commit/d8ed5a3ede96862575b3c0ceade45230459382a6))
- Initial setup for key gen and signature generation - ([7e1ab66](https://github.com/rpgp/rpgp/commit/7e1ab6642095f880be68a8a394ada3e5a602bb4e))
- Implement secret key encryption - ([eedad02](https://github.com/rpgp/rpgp/commit/eedad029a73d04f30fb789911ac24520370e839e))
- Public key export - ([14b9615](https://github.com/rpgp/rpgp/commit/14b9615ee9f5776956db9c722ac6de99e2188e43))
- Basic C FFI - ([9710f20](https://github.com/rpgp/rpgp/commit/9710f20843a43b1078c4539cf29a52e59837968c))
- Upgrade rand and use thread_rng by default - ([833971f](https://github.com/rpgp/rpgp/commit/833971f90f5bffc6de37f9fd9ae296500a98d9a8))
- Improved decrypt and KeyId handling - ([0f0046d](https://github.com/rpgp/rpgp/commit/0f0046d8f88eac686b9498f2b820fdc3eb83957a))
- Expose armor headers - ([c3ee4b3](https://github.com/rpgp/rpgp/commit/c3ee4b3c09d992c5bd0e1dc1b33f2b24a24bebb1))
- Switch to upstream dependencies - ([9b8ee1a](https://github.com/rpgp/rpgp/commit/9b8ee1afcac6a8bce99cd2a940d5071f8f691f41))

### 🐛 Bug Fixes

- *(ci)* Correct testing for pgp-ffi - ([6674760](https://github.com/rpgp/rpgp/commit/6674760be061c7a96652a448cb764d95434322a7))
- *(ffi)* Improve Makefile voodoo - ([280372e](https://github.com/rpgp/rpgp/commit/280372ecda9d3ded609e7eb9d55d48b3556d70a0))
- *(ffi)* Do not depend on generated files, clean the stamp file - ([61c81c0](https://github.com/rpgp/rpgp/commit/61c81c064b825c5ce5c0a32af70eff0bed6d585c))
- *(ffi)* Msg_decrypt_no_pw: use fingerprints instead of ids - ([8d712fb](https://github.com/rpgp/rpgp/commit/8d712fb02ac6c75e5fffb2af6b0f601e9a47c311))
- *(ffi)* Update crate name in the makefile - ([3a5e12f](https://github.com/rpgp/rpgp/commit/3a5e12fe07c01f0636951f6ed1e1f0fd3ce5ed9b))
- *(ffi)* Typo in Makefile - ([005cde0](https://github.com/rpgp/rpgp/commit/005cde017c931480e55e9af7f565b928d55c1d18))
- *(sym)* Disable broken blowfish - ([b63fa44](https://github.com/rpgp/rpgp/commit/b63fa44e3015f3176904201c26e189ece7aaef35))
- Partial boy reading with partial content - ([1b5d770](https://github.com/rpgp/rpgp/commit/1b5d7705d1934d01a8b0f634a01ae43ab32d253c))
- Proper random prefix in symmetric encryption - ([eb1ea53](https://github.com/rpgp/rpgp/commit/eb1ea5334332b22e05ee7236f5dae35ce5e76221))
- Correct handling of indeterminated length packets - ([86e8b77](https://github.com/rpgp/rpgp/commit/86e8b7723f8c9acd65b45b76013621510c7be753))
- Update x25519 libs - ([cdf7bc8](https://github.com/rpgp/rpgp/commit/cdf7bc8bc1a2b3c7023671c6fea2940a8afeed60))
- Include secret subkeys when converting to a public key - ([7508827](https://github.com/rpgp/rpgp/commit/75088276ffec8a2d1dd9e5cf76788e85c5958ac6))
- Gperftools dep - ([df364c8](https://github.com/rpgp/rpgp/commit/df364c8c8db6aea565bbc64dea5f4c6551c83d0f))
- Split asm and nightly flags - ([fa5932e](https://github.com/rpgp/rpgp/commit/fa5932e8fa12e8457eecb6f17ccf451657453753))
- Strip leading zeros when creating signatures - ([60366fc](https://github.com/rpgp/rpgp/commit/60366fc37f330dac54f6da3656c8dca3efc252a5))
- Stray newline - ([758327c](https://github.com/rpgp/rpgp/commit/758327c75d8328ff7088c227e95e0ec6ab0443df))

### 🚜 Refactor

- *(composed)* Remove code duplication in keyid and fingerprint generation - ([ceaad5a](https://github.com/rpgp/rpgp/commit/ceaad5a2a6c0f2578c82eb6b765854c8c7480230))
- *(pgp-ffi)* Split into multiple files - ([de978e4](https://github.com/rpgp/rpgp/commit/de978e4b65591b5b9c670f0d17c6132e69425487))
- Cleanup packet module - ([01b0ac9](https://github.com/rpgp/rpgp/commit/01b0ac97a0cc3c52473635c63da9934c624a9c1a))
- Improve type structure for public/private keys - ([127018b](https://github.com/rpgp/rpgp/commit/127018bbc90f09d6e08a7c093301a99a5d29e94d))
- Use derive(FromPrimitive) - ([d84faa7](https://github.com/rpgp/rpgp/commit/d84faa7bfe1876c7e2c65ee2489237b870df8433))
- Message parser as an iterator - ([2d9fe6f](https://github.com/rpgp/rpgp/commit/2d9fe6ff71d6eaec60c55dfd2109aff4a1d9a38b))
- Key parser is now an iterator - ([41d4c46](https://github.com/rpgp/rpgp/commit/41d4c4661c4c84df6568d3720717702a790342c3))
- Message decryption as iterator - ([3b8abbd](https://github.com/rpgp/rpgp/commit/3b8abbdc96e7c6a9342841f4c2091014db76ea0e))
- Split up composed key into multiple files - ([b0f620d](https://github.com/rpgp/rpgp/commit/b0f620d5d940d9a9fec88d6d65f9f1aede3a9f4c))
- Move logic for secret params into its own place - ([d81c13a](https://github.com/rpgp/rpgp/commit/d81c13a73eee7b1d08cb47d2286be1e900118445))
- More cleanup - ([da49313](https://github.com/rpgp/rpgp/commit/da4931338f671f1d1d883b1e0e68ae87987c19b5))
- Cleanup message code - ([9dfb076](https://github.com/rpgp/rpgp/commit/9dfb076054abb41e9f264dcbcb462df38491a173))
- Pull params into their own module - ([5f69b2c](https://github.com/rpgp/rpgp/commit/5f69b2c6f550eeec06d1399d2b2c2d5a54f96bce))
- Cleanup crypto code - ([a75d381](https://github.com/rpgp/rpgp/commit/a75d381e8b5df94a3b1524d547a5e21fb422724e))
- Extract proper type for mpis - ([9378195](https://github.com/rpgp/rpgp/commit/9378195770094f954397664bf43305e577b47a32))
- Split sks-dump tests into their own git submodule - ([1b69d70](https://github.com/rpgp/rpgp/commit/1b69d7028a1ce231716b533168589c1120bf6468))

### 📚 Documentation

- *(cargo)* Add some more metadata - ([a7b27a8](https://github.com/rpgp/rpgp/commit/a7b27a862cbdc1ceae2f0f25cebda701f8685820))
- *(readme)* Update appveyor badge - ([cdd824d](https://github.com/rpgp/rpgp/commit/cdd824d59566ac09f8c47ac53b9a683bef5706c6))
- *(readme)* Update for current ci status - ([250bc57](https://github.com/rpgp/rpgp/commit/250bc57241821a73b1f9d6ade28d7d70eb0844c6))
- *(status)* Fix typo  - ([170a98c](https://github.com/rpgp/rpgp/commit/170a98ceb2e6fbc3d090fd2eb6f96e9f4124724b))
- *(status)* Update - ([7fba149](https://github.com/rpgp/rpgp/commit/7fba149aa4a8199096b294a2be9727f612a065e0))
- *(status)* Update - ([5dd57de](https://github.com/rpgp/rpgp/commit/5dd57de37cea535499342552aeeb5e66256932d5))
- *(status)* Update - ([1834c95](https://github.com/rpgp/rpgp/commit/1834c95f236c95977cebc70bd086b8f7f9eefea3))
- Fix typo - ([c01ebb0](https://github.com/rpgp/rpgp/commit/c01ebb0ae9f877077d65982d29fc2d21447698b4))
- Update references and clarify some things - ([50ce46d](https://github.com/rpgp/rpgp/commit/50ce46de909f0534caa89695cd23a3e2751f3c18))
- Document current status - ([c016c32](https://github.com/rpgp/rpgp/commit/c016c32776ec70991d335f336c0cc82583d01ec3))
- Move platform suppport to its own document - ([a5bbdb3](https://github.com/rpgp/rpgp/commit/a5bbdb32525c2aa0a23401e0574b8d4e30aace0d))

### ⚡ Performance

- Reduce allocations in key handling and armor writing - ([1c10de5](https://github.com/rpgp/rpgp/commit/1c10de5db9b65b08b0db020597b33f72903de77e))
- Use smallvec for signature subpackets - ([61069c6](https://github.com/rpgp/rpgp/commit/61069c6c0f52639ffa0194b6d0d01e18498bfb41))
- Use more efficient ringbuffer when available - ([ddbac31](https://github.com/rpgp/rpgp/commit/ddbac31e8357cefada71d4da7c038db0ae823929))

### 🧪 Testing

- Import openpgp test suite - ([20c1429](https://github.com/rpgp/rpgp/commit/20c1429131722c8972a1ff9b8866715e886b09c4))
- Update key dump test numbers - ([2bb794a](https://github.com/rpgp/rpgp/commit/2bb794aa729228edf1c01df2f2c716e3ccd7b1c0))

### ⚙️ Miscellaneous Tasks

- *(cargo)* Exclude submodule from publishing - ([6d98faf](https://github.com/rpgp/rpgp/commit/6d98fafe6ba6e8366449c0a7128da8b814ae0348))
- *(cargo)* Fix keywords - ([a37e24f](https://github.com/rpgp/rpgp/commit/a37e24fce77ce9b7a057f41b9d3a380d6224ca9e))
- *(ci)* Try and fix appveyor - ([1370640](https://github.com/rpgp/rpgp/commit/13706409904de045ffa828b27c1a7bef4c4a358e))
- *(ci)* Appveyor fixes - ([69e2e48](https://github.com/rpgp/rpgp/commit/69e2e48eb4e98c7b99242a0d58b875fcb739439b))
- *(ci)* Stop installing openssl - ([080f518](https://github.com/rpgp/rpgp/commit/080f5189121a37cbf8ebd1581eef26f669296aab))
- *(ci)* Switch to circle ci  - ([dfbaab5](https://github.com/rpgp/rpgp/commit/dfbaab5a97833db3d47513369b6eda0c14a2e1ad))
- Cleanup unused test files - ([7f65c54](https://github.com/rpgp/rpgp/commit/7f65c542a528529555d835ff6a84a5262eafae9b))
- Drop gitmodules - ([694cfd7](https://github.com/rpgp/rpgp/commit/694cfd748ca2431642659406a7f8e396ee8b1e94))
- Include testcases manually - ([0096947](https://github.com/rpgp/rpgp/commit/0096947fbc893d8cf92e92e8144b6778418df717))
- Remove test file - ([1a6f9ad](https://github.com/rpgp/rpgp/commit/1a6f9ad71f3f12c99bb1ca46d14d5b6ac6eceefc))
- Remove profile files - ([affd2e4](https://github.com/rpgp/rpgp/commit/affd2e42a0b9a5400a193a94eec8b23773ed74dd))
- Update dependencies - ([0d76a71](https://github.com/rpgp/rpgp/commit/0d76a71f3ce5f46d44f709fd838783f3d965fec4))
- Move to org - ([5426d46](https://github.com/rpgp/rpgp/commit/5426d4670e5a8c5ba77ebc7318eebe8f203ad7e8))
- Update to latest nightly - ([c09c47f](https://github.com/rpgp/rpgp/commit/c09c47f22b4c5a1f057c8f4e10003573b1e09bd0))

### Bench

- *(key)* Add key gen benchmarks - ([4f325cd](https://github.com/rpgp/rpgp/commit/4f325cdd89d13ef6940e023c7cca269e8eacc4bf))
- *(message)* Fix compile errors - ([86525a1](https://github.com/rpgp/rpgp/commit/86525a1ae7149f806c79b7167e0bf2280e9090a9))

### Crypto

- Impl aes - ([bfdef22](https://github.com/rpgp/rpgp/commit/bfdef225e1bbf24cb3667e7a33ba3859acd139be))

### Key

- Add revocation key option - ([cd75dca](https://github.com/rpgp/rpgp/commit/cd75dcabbb2fcffe414f9c095efbd2b38bc08e89))
- Add issuer fingerprint subpacket - ([944e6b6](https://github.com/rpgp/rpgp/commit/944e6b6c4461029c41b411556ebd1ba703fd6c56))

### Travis

- Build on osx and linux - ([f8d235a](https://github.com/rpgp/rpgp/commit/f8d235a485b3e811b57240e24dab5c7bd8cc57f7))


