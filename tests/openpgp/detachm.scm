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

(define files (append plain-files data-files))

(info "Checking detached signatures of multiple files")
(lettmp (tmp)
  (call-popen `(,@GPG --yes --passphrase-fd "0" -sb
		      --output ,tmp ,@files) usrpass1)
  (pipe:do
   (pipe:defer (lambda (sink)
		 (for-each (lambda (file)
			     (pipe:do
			      (pipe:open file (logior O_RDONLY O_BINARY))
			      (pipe:splice sink)))
			   files)))
   (pipe:spawn `(,@GPG --yes --verify ,tmp -))))
