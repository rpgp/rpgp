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
 "Checking signing with the default hash algorithm"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg "" '(--yes --sign))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity source)))
 (append plain-files data-files))

(for-each-p
 "Checking signing with a specific hash algorithm"
 (lambda (hash)
   (if (have-pubkey-algo? "RSA")
       ;; RSA key, so any hash is okay.
       (tr:do
	(tr:open (car plain-files))
	(tr:gpg "" `(--yes --sign --user ,usrname3 --digest-algo ,hash))
	(tr:gpg "" '(--yes --decrypt))
	(tr:assert-identity (car plain-files))))
   (if (not (equal? "MD5" hash))
       ;; Using the DSA sig key - only 160 bit or larger hashes
       (tr:do
	(tr:open (car plain-files))
	(tr:gpg usrpass1
		`(--yes --sign --passphrase-fd "0" --digest-algo ,hash))
	(tr:gpg "" '(--yes --decrypt))
	(tr:assert-identity (car plain-files)))))
 (force all-hash-algos))
