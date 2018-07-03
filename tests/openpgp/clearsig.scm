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

(define (check-signing args input)
  (lambda (source sink)
    (lettmp (signed)
	    (call-popen `(,@GPG --output ,signed --yes
				,@args ,source) input)
	    (call-popen `(,@GPG --output ,sink --yes --verify ,signed) ""))))

(for-each-p
 "Checking signing and verifying plain text messages"
 (lambda (source)
   ((if (equal? "plain-3" source)
	;; plain-3 does not end in a newline, and gpg will add one.
	;; Therefore, we merely check that the verification is ok.
	check-execution
	;; Otherwise, we do check that we recover the original file.
	check-identity)
    source
    (check-signing '(--passphrase-fd "0" --clear-sign) usrpass1)))
 (append plain-files '("plain-large")))

;; The test vectors are lists of length three, containing
;; - a string to be signed,
;; - a flag indicating whether we verify that the exact message is
;;   reconstructed (whitespace at the end is normalized for plain text
;;   messages),
;; - and a list of arguments to add to gpg when encoding
;;   the string.

(define :string car)
(define :check-equality cadr)
(define :options caddr)

(define
  vectors
  '(;; one with long lines
    ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxyx

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
" #t ())

    ;; one with only one long line
    ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxyx
" #t ())

    ;; and one with an empty body
    ("" #f ())

    ;; and one with one empty line at the end
    ("line 1
line 2
line 3
there is a blank line after this

" #t ())

    ;; I think this file will be constructed wrong (gpg 0.9.3) but it
    ;; should verify okay anyway.
    ("this is a sig test
 " #f ())

    ;; check our special diff mode
    ("--- mainproc.c	Tue Jun 27 09:28:11 2000
+++ mainproc.c~ Thu Jun  8 22:50:25 2000
@@ -1190,16 +1190,13 @@
		md_enable( c->mfx.md, n1->pkt->pkt.signature->digest_algo);
	    }
	    /* ask for file and hash it */
-	    if( c->sigs_only ) {
+	    if( c->sigs_only )
		rc = hash_datafiles( c->mfx.md, NULL,
				     c->signed_data, c->sigfilename,
			n1? (n1->pkt->pkt.onepass_sig->sig_class == 0x01):0 );
" #t (--not-dash-escaped))))

(let ((counter (make-counter)))
  (for-each-p'
   "Checking signing and verifying test vectors"
   (lambda (vec)
     (lettmp (tmp)
       (with-output-to-file tmp (lambda () (display (:string vec))))
       ((if (:check-equality vec) check-identity check-execution)
	tmp
	(check-signing `(--passphrase-fd "0" --clear-sign ,@(:options vec))
		       usrpass1))))
   (lambda (vec) (counter))
   vectors))
