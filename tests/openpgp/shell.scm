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

;; This is not a test, but can be used to inspect the test
;; environment.  Simply execute
;;
;;   make -Ctests/openpgp check XTESTS=shell.scm
;;
;; to run it.

(if (prompt-yes-no? "Load legacy test environment" #t)
    (setup-legacy-environment)
    (setup-environment))

(if (prompt-yes-no? "Drop 'batch' from gpg.conf" #t)
    (apply create-file
	   (cons "gpg.conf"
		 (filter (lambda (line) (not (equal? "batch" line)))
			 (string-split-newlines
			  (call-with-input-file "gpg.conf" read-all)))))
    (begin
      (echo "Note that gpg.conf includes 'batch'.  If you want to use gpg")
      (echo "interactively you should drop that.")))

;; Add paths to tools to PATH.
(setenv "PATH" (pathsep-join
		(append (map (lambda (t) (dirname (tool t)))
			     '(gpg gpg-agent scdaemon gpgsm dirmngr gpgconf))
			(pathsep-split (getenv "PATH"))))
	#t)

(echo "\nEnjoy your test environment. "
      "Type 'exit' to exit it, it will be cleaned up after you.\n")

(interactive-shell)
