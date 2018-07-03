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

;; XXX because of --always-trust, the trustdb is not created.
;; Therefore, we redefine GPG without --always-trust.
(define gpg `(,(tool 'gpg) --no-permission-warning))

(info "Checking key revocation.")
(call-check `(,@gpg --import ,(in-srcdir "tests" "openpgp" "samplemsgs"
					 "revoke-2D727CC768697734.asc")))
(let loop ((output (gpg-with-colons '(--list-secret-keys "2D727CC768697734"))))
  (unless (null? output)
	  (let ((line (car output))
		(rest (cdr output)))
	    (when (member (car line) '("sec" "uid" "ssb"))
		  (unless (equal? (cadr line) "r")
			  (fail (car line) "not revoked.")))
	    (loop rest))))
