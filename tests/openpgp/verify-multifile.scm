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

(define files '("clearsig-1-key-1.asc" "signed-1-key-1.asc"))

(info "Checking verification of supplied files using --multifile.")

(let* ((status
	(call-popen
	 `(,@gpg --verify --multifile --status-fd=1
		 ,@(map (lambda (name) (in-srcdir "tests" "openpgp" "samplemsgs" name)) files))
	 ""))
       (lines (map (lambda (l)
		     (assert (string-prefix? l "[GNUPG:] "))
		     ;; Split, and strip the prefix.
		     (cdr (string-split l #\space)))
		   (string-split-newlines status))))
  (assert
   (= 2 (length (filter (lambda (l)
			  (and (equal? (car l) "GOODSIG")
			       (equal? (caddr l) "steve.biko@example.net")))
			lines)))))
