;; Copyright (C) 2016 g10 Code GmbH
;;
;; This file is part of GnuPG.
;;
;; GnuPG is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3 of the License, or
;; (at your option) any later version.
;;
;; GnuPG is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, see <http://www.gnu.org/licenses/>.

;; A plain signed message created using
;;  echo abc | gpg --homedir . --passphrase-fd 0 -u Alpha -z0 -sa msg
(define msg_ols_asc "
-----BEGIN PGP MESSAGE-----

kA0DAAIRLXJ8x2hpdzQBrQEHYgNtc2dEDFJaSSB0aGluayB0aGF0IGFsbCByaWdo
dC10aGlua2luZyBwZW9wbGUgaW4gdGhpcyBjb3VudHJ5IGFyZSBzaWNrIGFuZAp0
aXJlZCBvZiBiZWluZyB0b2xkIHRoYXQgb3JkaW5hcnkgZGVjZW50IHBlb3BsZSBh
cmUgZmVkIHVwIGluIHRoaXMKY291bnRyeSB3aXRoIGJlaW5nIHNpY2sgYW5kIHRp
cmVkLiAgSSdtIGNlcnRhaW5seSBub3QuICBCdXQgSSdtCnNpY2sgYW5kIHRpcmVk
IG9mIGJlaW5nIHRvbGQgdGhhdCBJIGFtLgotIE1vbnR5IFB5dGhvbgqIPwMFAEQM
UlotcnzHaGl3NBECR4IAoJlEGTY+bHjD2HYuCixLQCmk01pbAKCIjkzLOAmkZNm0
D8luT78c/1x45Q==
=a29i
-----END PGP MESSAGE-----
")

;; A plain signed message created using
;;  echo abc | gpg --homedir . --passphrase-fd 0 -u Alpha -sa msg
(define msg_cols_asc "
-----BEGIN PGP MESSAGE-----

owGbwMvMwCSoW1RzPCOz3IRxLSN7EnNucboLT6Cgp0JJRmZeNpBMLFFIzMlRKMpM
zyjRBQtm5qUrFKTmF+SkKmTmgdQVKyTnl+aVFFUqJBalKhRnJmcrJOalcJVkFqWm
KOSnKSSlgrSU5OekQMzLL0rJzEsEKk9JTU7NK4EZBtKcBtRRWgAzlwtmbnlmSQbU
GJjxCmDj9RQUPNVzFZJTi0oSM/NyKhXy8kuAYk6lJSBxLlTF2NziqZCYq8elq+Cb
n1dSqRBQWZKRn8fVYc/MygAKBljYCDIFiTDMT+9seu836Q+bevyHTJ0dzPNuvCjn
ZpgrwX38z58rJsfYDhwOSS4SkN/d6vUAAA==
=s6sY
-----END PGP MESSAGE-----
")

;; A PGP 2 style message.
(define msg_sl_asc "
-----BEGIN PGP MESSAGE-----

iD8DBQBEDFJaLXJ8x2hpdzQRAkeCAKCZRBk2Pmx4w9h2LgosS0AppNNaWwCgiI5M
yzgJpGTZtA/Jbk+/HP9ceOWtAQdiA21zZ0QMUlpJIHRoaW5rIHRoYXQgYWxsIHJp
Z2h0LXRoaW5raW5nIHBlb3BsZSBpbiB0aGlzIGNvdW50cnkgYXJlIHNpY2sgYW5k
CnRpcmVkIG9mIGJlaW5nIHRvbGQgdGhhdCBvcmRpbmFyeSBkZWNlbnQgcGVvcGxl
IGFyZSBmZWQgdXAgaW4gdGhpcwpjb3VudHJ5IHdpdGggYmVpbmcgc2ljayBhbmQg
dGlyZWQuICBJJ20gY2VydGFpbmx5IG5vdC4gIEJ1dCBJJ20Kc2ljayBhbmQgdGly
ZWQgb2YgYmVpbmcgdG9sZCB0aGF0IEkgYW0uCi0gTW9udHkgUHl0aG9uCg==
=0ukK
-----END PGP MESSAGE-----
")

;; An OpenPGP message lacking the onepass packet.  We used to accept
;; such messages but now consider them invalid.
(define bad_ls_asc "
-----BEGIN PGP MESSAGE-----

rQEHYgNtc2dEDFJaSSB0aGluayB0aGF0IGFsbCByaWdodC10aGlua2luZyBwZW9w
bGUgaW4gdGhpcyBjb3VudHJ5IGFyZSBzaWNrIGFuZAp0aXJlZCBvZiBiZWluZyB0
b2xkIHRoYXQgb3JkaW5hcnkgZGVjZW50IHBlb3BsZSBhcmUgZmVkIHVwIGluIHRo
aXMKY291bnRyeSB3aXRoIGJlaW5nIHNpY2sgYW5kIHRpcmVkLiAgSSdtIGNlcnRh
aW5seSBub3QuICBCdXQgSSdtCnNpY2sgYW5kIHRpcmVkIG9mIGJlaW5nIHRvbGQg
dGhhdCBJIGFtLgotIE1vbnR5IFB5dGhvbgqIPwMFAEQMUlotcnzHaGl3NBECR4IA
oJlEGTY+bHjD2HYuCixLQCmk01pbAKCIjkzLOAmkZNm0D8luT78c/1x45Q==
=Mpiu
-----END PGP MESSAGE-----
")


;; A signed message prefixed with an unsigned literal packet.
;; (fols = faked-literal-data, one-pass, literal-data, signature)
;; This should throw an error because running gpg to extract the
;; signed data will return both literal data packets
(define bad_fols_asc "
-----BEGIN PGP MESSAGE-----

rF1iDG1zZy51bnNpZ25lZEQMY0x0aW1lc2hhcmluZywgbjoKCUFuIGFjY2VzcyBt
ZXRob2Qgd2hlcmVieSBvbmUgY29tcHV0ZXIgYWJ1c2VzIG1hbnkgcGVvcGxlLgqQ
DQMAAhEtcnzHaGl3NAGtAQdiA21zZ0QMUlpJIHRoaW5rIHRoYXQgYWxsIHJpZ2h0
LXRoaW5raW5nIHBlb3BsZSBpbiB0aGlzIGNvdW50cnkgYXJlIHNpY2sgYW5kCnRp
cmVkIG9mIGJlaW5nIHRvbGQgdGhhdCBvcmRpbmFyeSBkZWNlbnQgcGVvcGxlIGFy
ZSBmZWQgdXAgaW4gdGhpcwpjb3VudHJ5IHdpdGggYmVpbmcgc2ljayBhbmQgdGly
ZWQuICBJJ20gY2VydGFpbmx5IG5vdC4gIEJ1dCBJJ20Kc2ljayBhbmQgdGlyZWQg
b2YgYmVpbmcgdG9sZCB0aGF0IEkgYW0uCi0gTW9udHkgUHl0aG9uCog/AwUARAxS
Wi1yfMdoaXc0EQJHggCgmUQZNj5seMPYdi4KLEtAKaTTWlsAoIiOTMs4CaRk2bQP
yW5Pvxz/XHjl
=UNM4
-----END PGP MESSAGE-----
")

;; A signed message suffixed with an unsigned literal packet.
;; (fols = faked-literal-data, one-pass, literal-data, signature)
;; This should throw an error because running gpg to extract the
;; signed data will return both literal data packets
(define bad_olsf_asc "
-----BEGIN PGP MESSAGE-----

kA0DAAIRLXJ8x2hpdzQBrQEHYgNtc2dEDFJaSSB0aGluayB0aGF0IGFsbCByaWdo
dC10aGlua2luZyBwZW9wbGUgaW4gdGhpcyBjb3VudHJ5IGFyZSBzaWNrIGFuZAp0
aXJlZCBvZiBiZWluZyB0b2xkIHRoYXQgb3JkaW5hcnkgZGVjZW50IHBlb3BsZSBh
cmUgZmVkIHVwIGluIHRoaXMKY291bnRyeSB3aXRoIGJlaW5nIHNpY2sgYW5kIHRp
cmVkLiAgSSdtIGNlcnRhaW5seSBub3QuICBCdXQgSSdtCnNpY2sgYW5kIHRpcmVk
IG9mIGJlaW5nIHRvbGQgdGhhdCBJIGFtLgotIE1vbnR5IFB5dGhvbgqIPwMFAEQM
UlotcnzHaGl3NBECR4IAoJlEGTY+bHjD2HYuCixLQCmk01pbAKCIjkzLOAmkZNm0
D8luT78c/1x45axdYgxtc2cudW5zaWduZWREDGNMdGltZXNoYXJpbmcsIG46CglB
biBhY2Nlc3MgbWV0aG9kIHdoZXJlYnkgb25lIGNvbXB1dGVyIGFidXNlcyBtYW55
IHBlb3BsZS4K
=3gnG
-----END PGP MESSAGE-----
")


;; Two standard signed messages in a row
(define msg_olsols_asc_multiple "
-----BEGIN PGP MESSAGE-----

kA0DAAIRLXJ8x2hpdzQBrQEHYgNtc2dEDFJaSSB0aGluayB0aGF0IGFsbCByaWdo
dC10aGlua2luZyBwZW9wbGUgaW4gdGhpcyBjb3VudHJ5IGFyZSBzaWNrIGFuZAp0
aXJlZCBvZiBiZWluZyB0b2xkIHRoYXQgb3JkaW5hcnkgZGVjZW50IHBlb3BsZSBh
cmUgZmVkIHVwIGluIHRoaXMKY291bnRyeSB3aXRoIGJlaW5nIHNpY2sgYW5kIHRp
cmVkLiAgSSdtIGNlcnRhaW5seSBub3QuICBCdXQgSSdtCnNpY2sgYW5kIHRpcmVk
IG9mIGJlaW5nIHRvbGQgdGhhdCBJIGFtLgotIE1vbnR5IFB5dGhvbgqIPwMFAEQM
UlotcnzHaGl3NBECR4IAoJlEGTY+bHjD2HYuCixLQCmk01pbAKCIjkzLOAmkZNm0
D8luT78c/1x45ZANAwACES1yfMdoaXc0Aa0BB2IDbXNnRAxSWkkgdGhpbmsgdGhh
dCBhbGwgcmlnaHQtdGhpbmtpbmcgcGVvcGxlIGluIHRoaXMgY291bnRyeSBhcmUg
c2ljayBhbmQKdGlyZWQgb2YgYmVpbmcgdG9sZCB0aGF0IG9yZGluYXJ5IGRlY2Vu
dCBwZW9wbGUgYXJlIGZlZCB1cCBpbiB0aGlzCmNvdW50cnkgd2l0aCBiZWluZyBz
aWNrIGFuZCB0aXJlZC4gIEknbSBjZXJ0YWlubHkgbm90LiAgQnV0IEknbQpzaWNr
IGFuZCB0aXJlZCBvZiBiZWluZyB0b2xkIHRoYXQgSSBhbS4KLSBNb250eSBQeXRo
b24KiD8DBQBEDFJaLXJ8x2hpdzQRAkeCAKCZRBk2Pmx4w9h2LgosS0AppNNaWwCg
iI5MyzgJpGTZtA/Jbk+/HP9ceOU=
=8nLN
-----END PGP MESSAGE-----
")

;; A standard message with two signatures (actually the same signature
;; duplicated).
(define msg_oolss_asc "
-----BEGIN PGP MESSAGE-----

kA0DAAIRLXJ8x2hpdzQBkA0DAAIRLXJ8x2hpdzQBrQEHYgNtc2dEDFJaSSB0aGlu
ayB0aGF0IGFsbCByaWdodC10aGlua2luZyBwZW9wbGUgaW4gdGhpcyBjb3VudHJ5
IGFyZSBzaWNrIGFuZAp0aXJlZCBvZiBiZWluZyB0b2xkIHRoYXQgb3JkaW5hcnkg
ZGVjZW50IHBlb3BsZSBhcmUgZmVkIHVwIGluIHRoaXMKY291bnRyeSB3aXRoIGJl
aW5nIHNpY2sgYW5kIHRpcmVkLiAgSSdtIGNlcnRhaW5seSBub3QuICBCdXQgSSdt
CnNpY2sgYW5kIHRpcmVkIG9mIGJlaW5nIHRvbGQgdGhhdCBJIGFtLgotIE1vbnR5
IFB5dGhvbgqIPwMFAEQMUlotcnzHaGl3NBECR4IAoJlEGTY+bHjD2HYuCixLQCmk
01pbAKCIjkzLOAmkZNm0D8luT78c/1x45Yg/AwUARAxSWi1yfMdoaXc0EQJHggCg
mUQZNj5seMPYdi4KLEtAKaTTWlsAoIiOTMs4CaRk2bQPyW5Pvxz/XHjl
=KVw5
-----END PGP MESSAGE-----
")

;; A standard message with two one-pass packet but only one signature
;; packet
(define bad_ools_asc "
-----BEGIN PGP MESSAGE-----

kA0DAAIRLXJ8x2hpdzQBkA0DAAIRLXJ8x2hpdzQBrQEHYgNtc2dEDFJaSSB0aGlu
ayB0aGF0IGFsbCByaWdodC10aGlua2luZyBwZW9wbGUgaW4gdGhpcyBjb3VudHJ5
IGFyZSBzaWNrIGFuZAp0aXJlZCBvZiBiZWluZyB0b2xkIHRoYXQgb3JkaW5hcnkg
ZGVjZW50IHBlb3BsZSBhcmUgZmVkIHVwIGluIHRoaXMKY291bnRyeSB3aXRoIGJl
aW5nIHNpY2sgYW5kIHRpcmVkLiAgSSdtIGNlcnRhaW5seSBub3QuICBCdXQgSSdt
CnNpY2sgYW5kIHRpcmVkIG9mIGJlaW5nIHRvbGQgdGhhdCBJIGFtLgotIE1vbnR5
IFB5dGhvbgqIPwMFAEQMUlotcnzHaGl3NBECR4IAoJlEGTY+bHjD2HYuCixLQCmk
01pbAKCIjkzLOAmkZNm0D8luT78c/1x45Q==
=1/ix
-----END PGP MESSAGE-----
")

;; Standard cleartext signature
(define msg_cls_asc "
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

I think that all right-thinking people in this country are sick and
tired of being told that ordinary decent people are fed up in this
country with being sick and tired.  I'm certainly not.  But I'm
sick and tired of being told that I am.
- - Monty Python
-----BEGIN PGP SIGNATURE-----

iD8DBQFEDVp1LXJ8x2hpdzQRAplUAKCMfpG3GPw/TLN52tosgXP5lNECkwCfQhAa
emmev7IuQjWYrGF9Lxj+zj8=
=qJsY
-----END PGP SIGNATURE-----
")

;; Cleartext signature with two signatures
(define msg_clss_asc "
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

What is the difference between a Turing machine and the modern computer?
It's the same as that between Hillary's ascent of Everest and the
establishment of a Hilton on its peak.
-----BEGIN PGP SIGNATURE-----

iD8DBQFEDVz6LXJ8x2hpdzQRAtkGAKCeMhNbHnh339fpjNj9owsYcC4zBwCfYO5l
2u+KEfXX0FKyk8SMzLjZ536IPwMFAUQNXPr+GAsdqeOwshEC2QYAoPOWAiQm0EF/
FWIAQUplk7JWbyRKAJ92ZJyJpWfzb0yc1s7MY65r2qEHrg==
=1Xvv
-----END PGP SIGNATURE-----
")

;; Two clear text signatures in a row
(define msg_clsclss_asc_multiple (string-append msg_cls_asc msg_clss_asc))


;; An Ed25519 cleartext message with an R parameter of only 247 bits
;; so that the code to re-insert the stripped zero byte kicks in.  The
;; S parameter has 253 bits but that does not strip a full byte.
;;
;; Note that the message has a typo ("the the"), but this should not
;; be fixed because it breaks this test.
(define msg_ed25519_rshort "
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Dear Emily:
	I'm still confused as to what groups articles should be posted
to.  How about an example?
		-- Still Confused

Dear Still:
	Ok.  Let's say you want to report that Gretzky has been traded from
the Oilers to the Kings.  Now right away you might think rec.sport.hockey
would be enough.  WRONG.  Many more people might be interested.  This is a
big trade!  Since it's a NEWS article, it belongs in the news.* hierarchy
as well.  If you are a news admin, or there is one on your machine, try
news.admin.  If not, use news.misc.
	The Oilers are probably interested in geology, so try sci.physics.
He is a big star, so post to sci.astro, and sci.space because they are also
interested in stars.  Next, his name is Polish sounding.  So post to
soc.culture.polish.  But that group doesn't exist, so cross-post to
news.groups suggesting it should be created.  With this many groups of
interest, your article will be quite bizarre, so post to talk.bizarre as
well.  (And post to comp.std.mumps, since they hardly get any articles
there, and a \"comp\" group will propagate your article further.)
	You may also find it is more fun to post the article once in each
group.  If you list all the newsgroups in the same article, some newsreaders
will only show the the article to the reader once!  Don't tolerate this.
		-- Emily Postnews Answers Your Questions on Netiquette
-----BEGIN PGP SIGNATURE-----

iJEEARYIADoWIQSyHeq0+HX7PaQvHR0TlWNoKgINCgUCV772DhwccGF0cmljZS5s
dW11bWJhQGV4YW1wbGUubmV0AAoJEBOVY2gqAg0KMAIA90EtUwAja0iJGpO91wyz
GLh9pS5v495V0r94yU6uUyUA/RT/StyPWe1wbnEZuacZnLbUV6Yy/aTXCVAlxf0r
TusO
=vQ3f
-----END PGP SIGNATURE-----
")

;; An Ed25519 cleartext message with an S parameter of only 248 bits
;; so that the code to re-insert the stripped zero byte kicks in.
(define msg_ed25519_sshort "
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

All articles that coruscate with resplendence are not truly auriferous.
-----BEGIN PGP SIGNATURE-----

iJEEARYIADoWIQSyHeq0+HX7PaQvHR0TlWNoKgINCgUCV771QhwccGF0cmljZS5s
dW11bWJhQGV4YW1wbGUubmV0AAoJEBOVY2gqAg0KHVEBAI66OPDYXKWO3r6SaFT+
uxmh8x4ZerW41vMA9gkJ4AEKAPjoe/Z7fDqo1lCptIFutFAGbfNxcm/53prfx2fT
GisM
=L7sk
-----END PGP SIGNATURE-----
")
