;; Test-suite runner.
;;
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

(if (string=? "" (getenv "abs_top_srcdir"))
    (begin
      (echo "Environment variable 'abs_top_srcdir' not set.  Please point it to"
	    "tests/openpgp.")
      (exit 2)))

;; Set objdir so that the tests can locate built programs.
(setenv "objdir" (getcwd) #f)

(define setup
  (make-environment-cache (test::scm
			   #f
			   (path-join "tests" "openpgp" "setup.scm")
			   (in-srcdir "tests" "openpgp" "setup.scm"))))

(define tests (filter (lambda (arg) (not (string-prefix? arg "--"))) *args*))

(run-tests (if (null? tests)
	       (load-tests "tests" "openpgp")
	       (map (lambda (name)
		      (test::scm setup
				 (path-join "tests" "openpgp" name)
				 (in-srcdir "tests" "openpgp" name))) tests)))
