# Examples for common OpenPGP operations with rPGP

## generate_keys

Produces a new private OpenPGP key, and the equivalent certificate (aka public key).
These two artifacts are stored in `example-key.priv` and `example-key.pub`.

## encrypt_decrypt

This example uses the keys generated in the previous example (from the files `example-key.priv` and `example-key.pub`).
It first produces an encrypted message by encrypting a cleartext to `example-key.pub`.
In a second step, it decrypts that message with the private key `example-key.priv`.

# Speed tests

## decrypt_seipdv1 / decrypt_seipdv2

These two examples each decrypt a large message and measure the speed of that operation.

To run the tests, local setup must be performed for each. See the comments in the source files for setup instructions.
