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
(setup-environment)

(for-each-p'
 "Checking reading and writing configuration via gpgconf... "
 (lambda (name opt make-value)
   (call-with-progress
    ""
    (lambda (progress)
      (do ((i 0 (+ 1 i))) ((> i 12) #t)
	(let ((value (make-value i)))
	  (if value
	      (begin
		(opt::update value)
		(assert (equal? value (opt::value))))
	      (begin
		(opt::clear)
		(assert (or (not (opt::value)) (string=? "" (opt::value)))))))
	(progress ".")))))
 (lambda (name . rest) name)
 (list "keyserver" "verbose" "quiet")
 (list (gpg-config 'gpg "keyserver")
       (gpg-config 'gpg "verbose")
       (gpg-config 'gpg "quiet"))
 (list (lambda (i) (if (even? i) "hkp://foo.bar" "hkps://bar.baz"))
       ;; gpgconf: argument for option verbose of type 0 (none) must
       ;; be positive
       (lambda (i) (+ 1 i))
       (lambda (i) (if (even? i) #f 1))))
