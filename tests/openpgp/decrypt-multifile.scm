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

(info "Checking decryption of supplied files using --multifile.")

(define my-wd (getcwd))
(define encrypted-files (map (lambda (name)
			       (string-append name ".asc"))
			     plain-files))

(with-temporary-working-directory
 ;; First, copy the files so that GnuPG writes the decrypted files here
 ;; and not into the source directory.
 (for-each (lambda (name)
	     (file-copy (in-srcdir "tests" "openpgp" name) name))
	   encrypted-files)

 ;; Now decrypt all files.
 (call-check `(,@gpg --decrypt --multifile ,@encrypted-files))

 ;; And verify the result.  Reference files are in our original
 ;; working directory courtesy of setup-legacy-environment.
 (for-each-p
  "Verifying files:"
  (lambda (name)
    (unless (file=? (path-join my-wd name) name)
	    (fail "decrypted file differs")))
  plain-files))
