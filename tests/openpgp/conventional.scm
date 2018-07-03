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

(define s2k '--s2k-count=65536)
(define passphrase "Hier spricht HAL")

(for-each-p
 "Checking conventional encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
     (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k -c))
     (tr:gpg passphrase `(--yes --passphrase-fd "0" --decrypt ,s2k))
     (tr:assert-identity source)))
 '("plain-2" "data-32000"))

(for-each-p
 "Checking conventional encryption using a specific cipher"
 (lambda (algo)
   (for-each-p
    ""
    (lambda (source)
      (tr:do
       (tr:open source)
       (tr:gpg passphrase `(--yes --passphrase-fd "0" ,s2k -c
				  --cipher-algo ,algo))
       (tr:gpg passphrase `(--yes --passphrase-fd "0" --decrypt ,s2k))
       (tr:assert-identity source)))
    '("plain-1" "data-80000")))
 (force all-cipher-algos))
