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

(define cache (flag "--create-tarball" *args*))
(unless (and cache (= 1 (length cache)))
	(fail "Usage: setup.scm --create-tarball <file> [--use-keyring]"))

(when (> (*verbose*) 0)
      (define (pad symbol length)
	(let loop ((cs (string->list (symbol->string symbol)))
		   (result (make-string length #\space))
		   (i 0))
	  (if (null? cs)
	      result
	      (begin
		(string-set! result i (car cs))
		(loop (cdr cs) result (+ 1 i))))))
      (log " I am going to use these tools:\n"
	   "==============================")
      (for-each
       (lambda (t)
	 (log (pad t 25) (tool t)))
       '(gpgconf gpg gpg-agent scdaemon gpgsm dirmngr gpg-connect-agent
		 gpg-preset-passphrase gpgtar pinentry)))

(setenv "GNUPGHOME" (getcwd) #t)
(create-gpghome)
(start-agent)
(create-legacy-gpghome)
(stop-agent)
(call-check `(,(tool 'gpgtar) --create --output ,(car cache) "."))
