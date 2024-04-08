## FAQs

### How is rPGP different from Sequoia?

Some key differences:
- rPGP has a more permissive license than Sequoia, which allows a broader usage
- rPGP is a library with a well-defined, relatively small feature-set
  where Sequoia also tries to be a replacement for the GPG command line tool
- All crypto used in rPGP is implemented in pure Rust,
  whereas Sequoia by default uses Nettle, which is implemented in C.
