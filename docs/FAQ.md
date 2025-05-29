## FAQs

### Is rPGP adding support for Post Quantum Cryptography (PQC)? 

Yes, rPGP implements the IETF draft [Post-Quantum Cryptography in OpenPGP](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/), gated behind the feature `draft-pqc`.

NOTE: draft-ietf-openpgp-pqc is not finalized, the format should NOT be used in production yet! This feature is currently only intended for testing purposes.

### What other standards are you considering for implementation? 

IETF standards currently tracked for implementation in rPGP 
use the ["ietf-draft" label on the issues](https://github.com/rpgp/rpgp/labels/ietf-draft). 

If you want to help either with coding or with funding,
please get in contact. 

We are also participating in renewed [Autocrypt specification efforts](https://autocrypt.org),
a multi-stakeholder community-driven specification for automated e-mail encryption. 


### Is rPGP considering support for LibrePGP? 

No, at least not soon. 

While we might not agree with, or not praise every detail of the V6 crypto refresh,
we highly appreciate the work of the IETF OpenPGP WG and the contributors and stakeholders around it. 

If [LibrePGP](https://librepgp.org/) evolves towards a multi-stakeholder community-driven specification, 
we might consider partially supporting LibrePGP keys and formats. 

Helping to smoothly and securely move the many [Delta Chat](https://delta.chat) users of rPGP
to V6 keys is sufficiently challenging for us without considering LibrePGP. 


### How is rPGP different from Sequoia?

The [Sequoia project](https://sequoia-pgp.org/) offers an alternative 
Rust implementation of OpenPGP. 
Here are some key differences, without claiming to exhaust the question: 

- rPGP has a more permissive license than Sequoia.

- rPGP is a library with a low-level API and relatively small feature-set 
  (with higher level APIs evolving in https://codeberg.org/heiko/rpgpie ) 
  whereas Sequoia has a comprehensive set of crates and also offers
  the `sq` CLI and aims to be a replacement for the GPG command line tool. 

- All cryptographic primitives used in rPGP are implemented in Rust,
  whereas Sequoia by default uses Nettle, which is implemented in C, 
  but also offers optional Rust backends. 

### Community standards

The rPGP project is affiliated with the [Delta Chat](https://delta.chat/) project.
The [Delta Chat Community Standards](https://delta.chat/en/community-standards) also apply for the rPGP project.
