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

(load (in-srcdir "tests" "openpgp" "defs.scm"))
(setup-legacy-environment)

(define keygrips '("8E06A180EFFE4C65B812150CAF19BF30C0689A4C"
		   "E4403F3FD7A443FAC29FEF288FA0D20AC212851E"
		   "0B7554421FFB14A06CB9F63FB49A85A58E97ABAC"
		   "303ACC892C2D786C8A789677C0BE54DA8538F903"
		   "9FE5C36985351524B6AFA19FDCBC1A3A750B6F5F"
		   "145A52CC7ED3FD41C5B0A26BE220FEED36AF24DE"))
(define mainkeyids '("BAA59D9C" "0F54719F" "45AF2FFE"))

(unless (have-pubkey-algo? "ECDH")
	(skip "No ECC support due to an old Libgcrypt"))

(info "Preparing for ECC test")
(for-each
 (lambda (grip)
   (catch '() (unlink (string-append "private-keys-v1.d/" grip ".key")))
   (call-check `(,(tool 'gpg-preset-passphrase)
		 --preset --passphrase ecc ,grip)))
 keygrips)

(info "Importing ECC public keys")
(for-each
 (lambda (keyid)
   (call `(,(tool 'gpg) --delete-key --batch --yes ,keyid)))
 mainkeyids)

(for-each
 (lambda (n)
   (call-check `(,(tool 'gpg) --import
		 ,(in-srcdir "tests" "openpgp" (string-append
			      "samplekeys/ecc-sample-"
			      (number->string n)
			      "-pub.asc")))))
 '(1 2 3))

;; The following is an opaque ECDSA signature on a message "This is one
;; line\n" (17 byte long) by the primary 256 bit key:
(define msg_opaque_signed_256 "-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.1.0-ecc (GNU/Linux)

owGbwMvMwCHMvVT3w66lc+cwrlFK4k5N1k3KT6nUK6ko8Zl8MSEkI7NYAYjy81IV
cjLzUrk64lgYhDkY2FiZQNIMXJwCMO31rxgZ+tW/zesUPxWzdKWrtLGW/LkP5rXL
V/Yvnr/EKjBbQuvZSYa/klsum6XFmTze+maVgclT6Rc6hzqqxNy6o6qdTTmLJuvp
AQA=
=GDv4
-----END PGP MESSAGE----")

;; The following is an opaque ECDSA signature on a message "This is one
;; line\n" (17 byte long) by the primary 384 bit key:
(define msg_opaque_signed_384 "-----BEGIN PGP MESSAGE-----
Version: PGP Command Line v10.0.0 (Linux)

qANQR1DIqwE7wsvMwCnM2WDcwR9SOJ/xtFISd25qcXFieqpeSUUJAxCEZGQWKwBR
fl6qQk5mXirXoXJmVgbfYC5xmC5hzsDPjHXqbDLzpXpTBXSZV3L6bAgP3Kq7Ykmo
7Ds1v4UfBS+3CSSon7Pzq79WLjzXXEH54MkjPxnrw+8cfMVnY7Bi18J702Nnsa7a
9lMv/PM0/ao9CZ3KX7Q+Tv1rllTZ5Hj4V1frw431QnHfAA==
=elKT
-----END PGP MESSAGE-----")

;; The following is an opaque ECDSA signature on a message "This is one
;; line\n" (17 byte long) by the primary 521 bit key:
(define msg_opaque_signed_521 "-----BEGIN PGP MESSAGE-----
Version: PGP Command Line v10.0.0 (Linux)

qANQR1DIwA8BO8LLzMAlnO3Y8tB1vf4/xtNKSdy5qcXFiempeiUVJQxAEJKRWawA
RPl5qQo5mXmpXIdmMLMy+AaLnoLpEubatpeJY2Lystd7Qt32q2UcvRS5kNPWtDB7
ryufvcrWtFM7Jx8qXKDxZuqr7b9PGv1Ssk+I8TzB2O9dZC+n/jv+PAdbuu7mLe33
Gf9pLd3weV3Qno6FOqxGa5ZszQx+uer2xH3/El9x/2pVeO4l15ScsL7qWMTmffmG
Ic1RdzgeCfosMF+l/zVRchcLKzenEQA=
=ATtX
-----END PGP MESSAGE-----")

(lettmp (z)
  (letfd ((fd (open z (logior O_WRONLY O_CREAT O_BINARY) #o600)))
	 (display "This is one line\n" (fdopen fd "wb")))

  (for-each-p
   "Checking opaque ECDSA signatures"
   (lambda (test)
     (lettmp (x y)
       (call-with-output-file
	   x (lambda (p) (display (eval test (current-environment)) p)))
       (call-check `(,(tool 'gpg) --output ,y --verify ,x))
       (unless (file=? y z) (fail "mismatch"))))
   '(msg_opaque_signed_256 msg_opaque_signed_384 msg_opaque_signed_521)))

;;
;; Import the secret keys so that we now can sign and decrypt.
;;
;; Note that the PGP generated secret keys are not self-signed, thus we
;; need to pass an appropriate option.
;;
(info "Importing ECC secret keys")
(setenv "PINENTRY_USER_DATA" "ecc" #t)
(for-each
 (lambda (n)
   (call-check `(,(tool 'gpg) --import
		 ,@(if (> n 1) '(--allow-non-selfsigned-uid) '())
		 ,(in-srcdir "tests" "openpgp" (string-append
			      "samplekeys/ecc-sample-"
			      (number->string n)
			      "-sec.asc")))))
 '(1 2 3))

;;
;; Check a few sample encrtpted messages.
;;
(info "Checking ECC encryption")

;; The following block encrypts the text "This is one line\n", 17 bytes,
;; with the subkey 4089AB73.
(define msg_encrypted_256 "-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.1.0-ecc (GNU/Linux)

hH4Dd863o0CJq3MSAgMEHdIYZQx+rV1cjy7qitIOEICFFzp4cjsRX4r+rDdMcQUs
h7VZmbP1c9C0s9sgCKwubWfkcYUl2ZOju4gy+s4MYTBb4/j8JjnJ9Bqn6LWutTXJ
zwsdP13VIJLnhiNqISdR3/6xWQ0ICRYzwb95nUZ1c1DSVgFpjPgUvi4pgYbTpcDB
jzILKWBfBDT/jck169XE8vgtbcqVQYZ7lZpaY9CzEbC+4dXZmV1gm5MafpTyFWgH
VnyrZB4gad9Lp9e0RKHHcOOE7s/NeLuu
=odUZ
-----END PGP MESSAGE-----")

;; The following block encrypts the text "This is one line\n", 17 bytes,
;; with the subkey 9A201946:
(define msg_encrypted_384 "-----BEGIN PGP MESSAGE-----
Version: PGP Command Line v10.0.0 (Linux)

qANQR1DBngOqi5OPmiAZRhIDAwQqIr/00cJyf+QP+VA4QKVkk77KMHdz9OVaR2XK
0VYu0F/HPm89vL2orfm2hrAZxY9G2R0PG4Wk5Lg04UjKca/O72uWtjdPYulFidmo
uB0QpzXFz22ZZinxeVPLPEr19Pow0EwCc95cg4HAgrD0nV9vRcTJ/+juVfvsJhAO
isMKqrFNMvwnK5A1ECeyVXe7oLZl0lUBRhLr59QTtvf85QJjg/m5kaGy8XCJvLv3
61pZa6KUmw89PjtPak7ebcjnINL01vwmyeg1PAyW/xjeGGvcO+R4P1b4ewyFnJyR
svzIJcP7d4DqYOw7
=oiTJ
-----END PGP MESSAGE-----")

;; The following block encrypts the text "This is one line\n", 17 bytes,
;; with the subkey A81C4838:
(define msg_encrypted_521 "-----BEGIN PGP MESSAGE-----
Version: PGP Command Line v10.0.0 (Linux)

qANQR1DBwAIDB+qqSKgcSDgSBCMEAKpzTUxB4c56C7g09ekD9I+ttC5ER/xzDmXU
OJmFqU5w3FllhFj4TgGxxdH+8fv4W2Ag0IKoJvIY9V1V7oUCClfqAR01QbN7jGH/
I9GFFnH19AYEgMKgFmh14ZwN1BS6/VHh+H4apaYqapbx8/09EL+DV9zWLX4GRLXQ
VqCR1N2rXE29MJFzGmDOCueQNkUjcbuenoCSKcNT+6xhO27U9IYVCg4BhRUDGfD6
dhfRzBLxL+bKR9JVAe46+K8NLjRVu/bd4Iounx4UF5dBk8ERy+/8k9XantDoQgo6
RPqCad4Dg/QqkpbK3y574ds3VFNJmc4dVpsXm7lGV5w0FBxhVNPoWNhhECMlTroX
Rg==
=5GqW
-----END PGP MESSAGE-----")

(lettmp (z)
  (letfd ((fd (open z (logior O_WRONLY O_CREAT O_BINARY) #o600)))
	 (display "This is one line\n" (fdopen fd "wb")))

  (for-each-p
   "Checking ECDSA decryption"
   (lambda (test)
     (lettmp (x y)
       (call-with-output-file
	   x (lambda (p) (display (eval test (current-environment)) p)))
       (call-check `(,@GPG --yes --output ,y --decrypt ,x))
       (unless (file=? y z) (fail "mismatch"))))
   '(msg_encrypted_256 msg_encrypted_384 msg_encrypted_521)))

;;
;; Now check that we can encrypt and decrypt our own messages.
;;
;; Note that we don't need to provide a passphrase because we already
;; preset the passphrase into the gpg-agent.
;;
(for-each-p
 "Checking ECC encryption and decryption"
 (lambda (source)
   (for-each-p
    ""
    (lambda (keyid)
      (tr:do
       (tr:open source)
       (tr:gpg "" `(--yes --encrypt --recipient ,keyid))
       (tr:gpg "" '(--yes --decrypt))
       (tr:assert-identity source)))
    mainkeyids))
 (append plain-files data-files))

;;
;; Now check that we can sign and verify our own messages.
;;
(for-each-p
 "Checking ECC signing and verifiction"
 (lambda (source)
   (for-each-p
    ""
    (lambda (keyid)
      (tr:do
       (tr:open source)
       (tr:gpg "" `(--yes --sign --local-user ,keyid))
       (tr:gpg "" '(--yes --decrypt))
       (tr:assert-identity source)))
    mainkeyids))
 (append plain-files data-files))

;;
;; Let us also try to import the keys only from a secret keyblock.
;;
;; Because PGP does not sign the UID, it is not very useful to work
;; with this key unless we go into the trouble of adding the
;; self-signature.
;;
(info "Importing ECC secret keys directly")
(for-each
 (lambda (keyid)
   (catch '() (unlink (string-append "private-keys-v1.d/" keyid ".key"))))
 keygrips)
(for-each
 (lambda (keyid)
   (call `(,(tool 'gpg) --delete-key --batch --yes ,keyid)))
 mainkeyids)

(for-each
 (lambda (n)
   (call-check `(,(tool 'gpg) --import
		 ,@(if (> n 1) '(--allow-non-selfsigned-uid) '())
		 ,(in-srcdir "tests" "openpgp" (string-append
			      "samplekeys/ecc-sample-"
			      (number->string n)
			      "-sec.asc")))))
 '(1 2 3))
