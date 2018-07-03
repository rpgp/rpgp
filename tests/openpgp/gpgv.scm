#!/usr/bin/env gpgscm

;; Copyright (C) 2016-2017 g10 Code GmbH
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
(load (in-srcdir "tests" "openpgp" "signed-messages.scm"))
(setup-legacy-environment)

(define keyring (if (file-exists? "pubring.kbx") "pubring.kbx" "pubring.gpg"))

;;
;; Two simple tests to check that verify fails for bad input data
;;
(for-each-p
 "Checking bogus signature"
 (lambda (char)
   (lettmp (x)
     (call-with-binary-output-file
      x
      (lambda (port)
	(display (make-string 64 (integer->char (string->number char)))
		 port)))
     (if (= 0 (call `(,@gpgv --keyring ,keyring ,x data-500)))
	 (fail "no error code from verify"))))
 '("#x2d" "#xca"))

;; Fixme:  We need more tests with manipulated cleartext signatures.

;;
;; Now run the tests.
;;
(for-each-p
 "Checking that a valid signature is verified as such"
 (lambda (armored-file)
   (pipe:do
    (pipe:echo (eval armored-file (current-environment)))
    (pipe:spawn `(,@gpgv --keyring ,keyring))))
 '(msg_ols_asc msg_cols_asc msg_sl_asc msg_oolss_asc msg_cls_asc msg_clss_asc))

(for-each-p
 "Checking that an invalid signature is verified as such"
 (lambda (armored-file)
   (catch '()
	  (pipe:do
	   (pipe:echo (eval armored-file (current-environment)))
	   (pipe:spawn `(,@gpgv --keyring ,keyring)))
	  (fail "verification succeeded but should not")))
 '(bad_ls_asc bad_fols_asc bad_olsf_asc bad_ools_asc))


;; Need to import the ed25519 sample key used for the next two tests.
(call-check `(,@gpg --quiet --yes
		    --import ,(in-srcdir "tests" "openpgp" key-file2)))
(for-each-p
 "Checking that a valid Ed25519 signature is verified as such"
 (lambda (armored-file)
   (pipe:do
    (pipe:echo (eval armored-file (current-environment)))
    (pipe:spawn `(,@gpgv --keyring ,keyring))))
 '(msg_ed25519_rshort msg_ed25519_sshort))
