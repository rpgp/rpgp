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

(define key
  `(,(in-srcdir "tests" "openpgp" "samplekeys" "authenticate-only.sec.asc")
    "927EF377FD1A1B6F795E40C02A87917D8FFBA49F"
    "72360FDB6380212D5DAF2FA9E51185A9253C496D"
    "ssh-rsa"))

(define :file car)
(define :fpr cadr)
(define :subkey-fpr caddr)
(define :kind cadddr)

;; Return true if a-str and b-str share a suffix of length n.
(define (string-common-suffix? n a-str b-str)
  (let ((a-len (string-length a-str))
	(b-len (string-length b-str)))
  (if (> n (min a-len b-len))
      #f
      (string=? (substring a-str (- a-len n) a-len)
		(substring b-str (- b-len n) b-len)))))

(info "Checking ssh export...")
(call-check `(,@GPG --yes --import ,(:file key)))

(let* ((result (call-check `(,@GPG --export-ssh-key ,(:fpr key))))
       (parts (string-splitp (string-trim char-whitespace? result)
			     char-whitespace? -1)))
  (assert (string=? (car parts) (:kind key)))
  ;; XXX: We should not use a short keyid as the comment when
  ;; exporting an ssh key.
  (assert (string-common-suffix? 8 (caddr parts) (:subkey-fpr key))))
