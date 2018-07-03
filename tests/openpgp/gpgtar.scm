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

(catch (skip "gpgtar not built")
       (call-check `(,(tool 'gpgtar) --help)))

(define testfiles (append plain-files data-files))
(define gpgargs
  (if have-opt-always-trust
      "--no-permission-warning --always-trust"
      "--no-permission-warning"))

(define (do-test create-flags inspect-flags extract-flags)
  (lettmp (archive)
    (call-check `(,(tool 'gpgtar) --gpg ,(tool 'gpg) --gpg-args ,gpgargs
		  ,@create-flags
		  --output ,archive
		  ,@testfiles))
    (tr:do
     (tr:pipe-do
      (pipe:spawn `(,(tool 'gpgtar) --gpg ,(tool 'gpg) --gpg-args ,gpgargs
		    --list-archive ,@inspect-flags
		    ,archive)))
     (tr:call-with-content
      (lambda (c)
	(unless (all (lambda (f) (string-contains? c f)) testfiles)
		(fail "some file(s) are missing from archive")))))

    (with-temporary-working-directory
     (call-check `(,(tool 'gpgtar) --gpg ,(tool 'gpg) --gpg-args ,gpgargs
		   --tar-args --directory=.
		   ,@extract-flags
		   ,archive))

     (for-each
      (lambda (f) (unless (call-with-input-file f (lambda (x) #t))
			  (fail (string-append "missing file: " f))))
      testfiles))))

(info "Checking gpgtar without encryption")
(do-test '(--skip-crypto --encrypt) '(--skip-crypto)
	 '(--skip-crypto --decrypt))

(info "Checking gpgtar without encryption with nicer actions")
(do-test '(--create) '(--skip-crypto) '(--extract))

(info "Checking gpgtar with asymmetric encryption")
(do-test `(--encrypt --recipient ,usrname2) '() '(--decrypt))

(info "Checking gpgtar with asymmetric encryption and signature")
(do-test `(--encrypt --recipient ,usrname2 --sign --local-user ,usrname3)
	 '() '(--decrypt))

(info "Checking gpgtar with signature")
(do-test `(--sign --local-user ,usrname3) '() '(--decrypt))

(lettmp (passphrasefile)
  (letfd ((fd (open passphrasefile (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (display "streng geheimes hupsipupsi" (fdopen fd "wb")))

  (let ((ppflags `(--gpg-args ,(string-append "--passphrase-file="
					      passphrasefile))))
    (info "Checking gpgtar with symmetric encryption")
    (do-test `(,@ppflags --symmetric) ppflags (cons '--decrypt ppflags))

    (info "Checking gpgtar with symmetric encryption and chosen cipher")
    (do-test `(,@ppflags --symmetric --gpg-args
			 ,(string-append "--cipher="
					 (car (force all-cipher-algos))))
	     ppflags (cons '--decrypt ppflags))

    (info "Checking gpgtar with both symmetric and asymmetric encryption")
    (do-test `(,@ppflags --symmetric --encrypt --recipient ,usrname2
			 --sign --local-user ,usrname3)
	     ppflags (cons '--decrypt ppflags))))
