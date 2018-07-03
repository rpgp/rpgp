#!/usr/bin/env gpgscm

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

;; Check that gpg verifies only signatures where there is no ambiguity
;; in the order of packets.  Needs the Demo Keys Lima and Mike.
;;
;; Note: We do not support multiple signatures anymore thus this test is
;; not really needed because verify could do the same.  We keep it anyway.

(load (in-srcdir "tests" "openpgp" "defs.scm"))
(setup-legacy-environment)

(define sig-1ls1ls-valid "
-----BEGIN PGP ARMORED FILE-----

kA0DAAIRN8q1H7eRA/gBrCdiBXRleHQxOogq9EkgYW0gc29ycnksIEkgY2FuJ3Qg
ZG8gdGhhdAqIPwMFADqIKvQ3yrUft5ED+BEC2joAoJaSaXOZEtSZqQ780HIXG77e
8PB7AJ4wCprmaFTO0fBaTcXDuEOBdAWnOZANAwACETfKtR+3kQP4AawnYgV0ZXh0
MTqIKvRJIGFtIHNvcnJ5LCBJIGNhbid0IGRvIHRoYXQKiD8DBQA6iCr0N8q1H7eR
A/gRAto6AKCWkmlzmRLUmakO/NByFxu+3vDwewCeMAqa5mhUztHwWk3Fw7hDgXQF
pzk=
=8jSC
-----END PGP ARMORED FILE-----
")
(define sig-ls-valid "
-----BEGIN PGP ARMORED FILE-----

rCdiBXRleHQxOogrS0kgYW0gc29ycnksIEkgY2FuJ3QgZG8gdGhhdAqIPwMFADqI
K0s3yrUft5ED+BECLQMAn2jZUNOpB4OuurSQkc2TRfg6ek02AJ9+oJS0frQ+yUsT
QDUFTH2PvZRxjw==
=J+lb
-----END PGP ARMORED FILE-----
")
(define sig-sl-valid "
-----BEGIN PGP ARMORED FILE-----

iD8DBQA6iCtLN8q1H7eRA/gRAi0DAJ9o2VDTqQeDrrq0kJHNk0X4OnpNNgCffqCU
tH60PslLE0A1BUx9j72UcY+sJ2IFdGV4dDE6iCtLSSBhbSBzb3JyeSwgSSBjYW4n
dCBkbyB0aGF0Cg==
=N9MP
-----END PGP ARMORED FILE-----
")
(define sig-11lss-valid-but-is-not "
-----BEGIN PGP ARMORED FILE-----

kA0DAAIRN8q1H7eRA/gAkA0DAAIRN8q1H7eRA/gBrCdiBXRleHQxOogyXUkgYW0g
c29ycnksIEkgY2FuJ3QgZG8gdGhhdAqIPwMFADqIMl03yrUft5ED+BECwQAAnRXT
mXjVd385oD38W80XuheWKTGcAJ9pZ6/flaKDfw+SLido7xaUHuhp5Yg/AwUAOogy
XTfKtR+3kQP4EQLBAACgnN0IP+NztE0aAc/DZ17yHWR9diwAniN0P01WmbgZJoZB
Q341WRXKS/at
=Ekrs
-----END PGP ARMORED FILE-----
")
(define sig-11lss11lss-valid-but-is-not "
-----BEGIN PGP ARMORED FILE-----

kA0DAAIRN8q1H7eRA/gAkA0DAAIRN8q1H7eRA/gBrCdiBXRleHQxOogyXUkgYW0g
c29ycnksIEkgY2FuJ3QgZG8gdGhhdAqIPwMFADqIMl03yrUft5ED+BECwQAAnRXT
mXjVd385oD38W80XuheWKTGcAJ9pZ6/flaKDfw+SLido7xaUHuhp5Yg/AwUAOogy
XTfKtR+3kQP4EQLBAACgnN0IP+NztE0aAc/DZ17yHWR9diwAniN0P01WmbgZJoZB
Q341WRXKS/atkA0DAAIRN8q1H7eRA/gAkA0DAAIRN8q1H7eRA/gBrCdiBXRleHQx
OogyXUkgYW0gc29ycnksIEkgY2FuJ3QgZG8gdGhhdAqIPwMFADqIMl03yrUft5ED
+BECwQAAnRXTmXjVd385oD38W80XuheWKTGcAJ9pZ6/flaKDfw+SLido7xaUHuhp
5Yg/AwUAOogyXTfKtR+3kQP4EQLBAACgnN0IP+NztE0aAc/DZ17yHWR9diwAniN0
P01WmbgZJoZBQ341WRXKS/at
=P1Mu
-----END PGP ARMORED FILE-----
")
(define sig-ssl-valid-but-is-not "
-----BEGIN PGP ARMORED FILE-----

iD8DBQA6iCtLN8q1H7eRA/gRAi0DAJ9o2VDTqQeDrrq0kJHNk0X4OnpNNgCffqCU
tH60PslLE0A1BUx9j72UcY+IPwMFADqIK0s3yrUft5ED+BECLQMAn2jZUNOpB4Ou
urSQkc2TRfg6ek02AJ9+oJS0frQ+yUsTQDUFTH2PvZRxj6wnYgV0ZXh0MTqIK0tJ
IGFtIHNvcnJ5LCBJIGNhbid0IGRvIHRoYXQK
=Zven
-----END PGP ARMORED FILE-----
")
(define sig-1lsls-invalid "
-----BEGIN PGP ARMORED FILE-----

kA0DAAIRN8q1H7eRA/gBrCdiBXRleHQxOogq9EkgYW0gc29ycnksIEkgY2FuJ3Qg
ZG8gdGhhdAqIPwMFADqIKvQ3yrUft5ED+BEC2joAoJaSaXOZEtSZqQ780HIXG77e
8PB7AJ4wCprmaFTO0fBaTcXDuEOBdAWnOawnYgV0ZXh0MTqIK0tJIGFtIHNvcnJ5
LCBJIGNhbid0IGRvIHRoYXQKiD8DBQA6iCtLN8q1H7eRA/gRAi0DAJ9o2VDTqQeD
rrq0kJHNk0X4OnpNNgCffqCUtH60PslLE0A1BUx9j72UcY8=
=nkeu
-----END PGP ARMORED FILE-----
")
(define sig-lsls-invalid "
-----BEGIN PGP ARMORED FILE-----

rCdiBXRleHQxOogrS0kgYW0gc29ycnksIEkgY2FuJ3QgZG8gdGhhdAqIPwMFADqI
K0s3yrUft5ED+BECLQMAn2jZUNOpB4OuurSQkc2TRfg6ek02AJ9+oJS0frQ+yUsT
QDUFTH2PvZRxj6wnYgV0ZXh0MTqIK0tJIGFtIHNvcnJ5LCBJIGNhbid0IGRvIHRo
YXQKiD8DBQA6iCtLN8q1H7eRA/gRAi0DAJ9o2VDTqQeDrrq0kJHNk0X4OnpNNgCf
fqCUtH60PslLE0A1BUx9j72UcY8=
=BlZH
-----END PGP ARMORED FILE-----
")
(define sig-lss-invalid "
-----BEGIN PGP ARMORED FILE-----

rCdiBXRleHQxOogrS0kgYW0gc29ycnksIEkgY2FuJ3QgZG8gdGhhdAqIPwMFADqI
K0s3yrUft5ED+BECLQMAn2jZUNOpB4OuurSQkc2TRfg6ek02AJ9+oJS0frQ+yUsT
QDUFTH2PvZRxj4g/AwUAOogrSzfKtR+3kQP4EQItAwCfaNlQ06kHg666tJCRzZNF
+Dp6TTYAn36glLR+tD7JSxNANQVMfY+9lHGP
=jmt6
-----END PGP ARMORED FILE-----
")
(define sig-slsl-invalid "
-----BEGIN PGP ARMORED FILE-----

iD8DBQA6iCtLN8q1H7eRA/gRAi0DAJ9o2VDTqQeDrrq0kJHNk0X4OnpNNgCffqCU
tH60PslLE0A1BUx9j72UcY+sJ2IFdGV4dDE6iCtLSSBhbSBzb3JyeSwgSSBjYW4n
dCBkbyB0aGF0Cog/AwUAOogrSzfKtR+3kQP4EQItAwCfaNlQ06kHg666tJCRzZNF
+Dp6TTYAn36glLR+tD7JSxNANQVMfY+9lHGPrCdiBXRleHQxOogrS0kgYW0gc29y
cnksIEkgY2FuJ3QgZG8gdGhhdAo=
=phBF
-----END PGP ARMORED FILE-----
")

(for-each-p
 "Checking that a valid signature is verified as such"
 (lambda (armored-file)
   (tr:do
    (tr:pipe-do
     (pipe:echo (eval armored-file (current-environment)))
     (pipe:spawn `(,@GPG --dearmor)))
    (tr:spawn "" `(,@GPG --verify **in**))))
 '(sig-sl-valid))

;; ???
;;
;; #for i in "$sig-11lss-valid-but-is-not" "$sig-11lss11lss-valid-but-is-not" \
;; #         "$sig-ssl-valid-but-is-not"; do
;; #    echo "$i" | $GPG --dearmor >x
;; #    $GPG --verify <x 2>/dev/null || error "valid is invalid"
;; #done

(for-each-p
 "Checking that an invalid signature is verified as such"
 (lambda (armored-file)
   (lettmp (file)
     (pipe:do
      (pipe:echo (eval armored-file (current-environment)))
      (pipe:spawn `(,@GPG --dearmor))
      (pipe:write-to file (logior O_WRONLY O_CREAT O_BINARY) #o600))

     (if (= 0 (call `(,@GPG --verify ,file)))
	 (fail "Bad signature verified ok"))))
 '(sig-1ls1ls-valid sig-ls-valid sig-1lsls-invalid
		    sig-lsls-invalid sig-lss-invalid sig-slsl-invalid))
