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
 "Checking signing and encryption"
 (lambda (source)
   (tr:do
    (tr:open source)
    (tr:gpg usrpass1 `(--yes --passphrase-fd "0" -se --recipient ,usrname2))
    (tr:gpg "" '(--yes --decrypt))
    (tr:assert-identity source)))
 (append plain-files data-files))

(info "Checking bug 537: MDC problem with old style compressed packets.")
(lettmp (tmp)
  (call-popen `(,@GPG --yes --passphrase-fd "0"
		      --output ,tmp --decrypt ,(in-srcdir "tests" "openpgp"
							  "bug537-test.data.asc"))
	      usrpass1)
  (if (not (string=? "4336AE2A528FAE091E73E59E325B588FEE795F9B"
		     (cadar (gpg-hash-string `(--print-md SHA1 ,tmp) ""))))
      (fail "bug537-test.data.asc: mismatch (bug 537)")))
