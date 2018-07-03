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

(define msg_signed_asc "
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

This is an example text file to demonstrate a problem.

Using forged-keyring.gpg with signature cache, it looks like it is
signed by the following key:

    Echo Test (demo key) <echo@example.net>

But actually not.

It is signed by a key (steve.biko@example.net) distributed as:

    gnupg/tests/openpgp/samplekeys/rsa-rsa-sample-1.asc

in GnuPG.

The forged-keyring.gpg file is created by a key in

    gnupg/tests/openpgp/pubdemo.asc

Replacing the raw key material packet by one of rsa-rsa-sample-1.asc.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iQEcBAEBCAAGBQJXp+5MAAoJEKpD8dzH/tG3bGMH/1idFLJAaMxkrq+JguvAboiN
tAA44IdAgJvAxtR5w5fgfed7PfsH70+tj54/ZTObt7rZDIlj/YBQ7XeCwd7/O5vx
W0QtjjAxMuAPH80rVv4JIoflxV/deD8YaV9EhPE+6W5G0Z8SYL9B2RzdBVMwJY9+
OZGJeKnUZ92Zg9jFr+H5gQNSeYdDHVDWYxr/xJUf0jYsZvAIBfB1mcSK1niiiVBv
GAcUC/I8g18a7pCS9Qf9iZflqxX4AXfocAGQqQAiG4744OCNhVa5q6TScqhaGUah
N1Glbw1OJfP1q+QFPMPKoCsTYmZpuugq2b5gV/eH0Abvk2pG4Fo/YTDPHhec7Jk=
=NnY/
-----END PGP SIGNATURE-----
")

(for-each-p
 "Checking that a signature by bad key should not be verified"
 (lambda (armored-file)
   (catch '()
	  (pipe:do
	   (pipe:echo (eval armored-file (current-environment)))
	   (pipe:spawn `(,@GPGV --keyring ,(in-srcdir "tests" "openpgp" "forged-keyring.gpg"))))
	  (fail "verification succeeded but should not")))
 '(msg_signed_asc))
