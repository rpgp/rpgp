#!/usr/bin/env gpgscm

;; Copyright (C) 2017 g10 Code GmbH
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

(define (get-session-key filename)
  (lettmp (sink)
    (let* ((status' (call-popen `(,@gpg --status-fd=1 --decrypt
					--show-session-key
					--output ,sink ,filename) ""))
	   (status (map (lambda (l)
			  (assert (string-prefix? l "[GNUPG:] "))
			  (string-splitp (substring l 9 (string-length l))
					 char-whitespace? -1))
			(string-split-newlines status'))))
      (cadr (assoc "SESSION_KEY" status)))))

(for-each-p
 "Checking decryption of supplied files using the session key."
 (lambda (name)
   (let* ((source (in-srcdir "tests" "openpgp" (string-append name ".asc")))
	  (key (get-session-key source)))
     (with-ephemeral-home-directory setup-environment-no-atexit stop-agent
      (tr:do
       (tr:open source)
       (tr:gpg "" `(--yes --decrypt --override-session-key ,key))
       (tr:assert-identity name)))))
 plain-files)
