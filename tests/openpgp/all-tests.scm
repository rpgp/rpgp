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

(export all-tests
 ;; Parse the Makefile.am to find all tests.

 (load (with-path "makefile.scm"))

 (define (expander filename port key)
   (parse-makefile port key))

 (define (parse filename key)
   (parse-makefile-expand filename expander key))

 (define setup
   (make-environment-cache
    (test::scm
     #f
     (path-join "tests" "openpgp" "setup.scm")
     (in-srcdir "tests" "openpgp" "setup.scm"))))

 (define (qualify path variant)
   (string-append "<" variant ">" path))

 (define (setup* variant)
   (make-environment-cache
    (test::scm
     #f
     (qualify (path-join "tests" "openpgp" "setup.scm") variant)
     (in-srcdir "tests" "openpgp" "setup.scm")
     (string-append "--" variant))))

 (define setup-use-keyring (setup* "use-keyring"))
 (define setup-extended-key-format (setup* "extended-key-format"))

 (define all-tests
   (parse-makefile-expand "Makefile"
			  (lambda (filename port key) (parse-makefile port key))
			  "XTESTS"))

 (define tests
   (map (lambda (name)
	  (test::scm setup
		     (path-join "tests" "openpgp" name)
		     (in-srcdir "tests" "openpgp" name))) all-tests))

 (when *run-all-tests*
       (set! tests
	     (append
	      tests
	      (map (lambda (name)
		     (test::scm setup-use-keyring
				(qualify (path-join "tests" "openpgp" name)
					 "use-keyring")
				(in-srcdir "tests" "openpgp" name)
				"--use-keyring")) all-tests)
	      (map (lambda (name)
		     (test::scm setup-extended-key-format
				(qualify (path-join "tests" "openpgp" name)
					 "extended-key-format")
				(in-srcdir "tests" "openpgp" name)
				"--extended-key-format")) all-tests))))

 tests)
