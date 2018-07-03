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

(for-each-p
 "Checking signing using DSA with the default hash algorithm"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" `(--yes --sign --user ,dsa-usrname1))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity source)))
 (append plain-files data-files))

(define algos (if (have-hash-algo? "RIPEMD160")
		  '("SHA1" "RIPEMD160")
		  '("SHA1")))
(for-each-p
 "Checking signing using DSA with a specific hash algorithm"
 (lambda (hash)
   (tr:do
    (tr:open (car plain-files))
    (tr:gpg "" `(--yes --sign --user ,dsa-usrname1 --digest-algo ,hash))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity (car plain-files))))
 algos)
