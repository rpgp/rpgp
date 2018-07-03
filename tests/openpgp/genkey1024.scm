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
(setup-environment)

(define (genkey config)
  (pipe:do
   (pipe:echo config)
   (pipe:spawn `(,(tool 'gpg) --quiet --batch --generate-key))))

(info "Checking batch key generation")
(genkey "Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG
Subkey-Length: 1024
Name-Real: Harry H.
Name-Comment: test key
Name-Email: hh@@ddorf.de
Expire-Date: 1
%no-protection
%transient-key
%commit
")

(if (have-pubkey-algo? "RSA")
    (genkey "Key-Type: RSA
Key-Length: 1024
Key-Usage: sign,encrypt
Name-Real: Harry A.
Name-Comment: RSA test key
Name-Email: hh@@ddorf.de
Expire-Date: 2
%no-protection
%transient-key
%commit
"))
