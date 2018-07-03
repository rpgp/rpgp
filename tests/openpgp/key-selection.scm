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

;; This test assumes a fixed time of 2004-01-01.

 ;; Redefine gpg with a fixed time.
(define gpg `(,@gpg --faked-system-time=1072911600))

;; We have a number of keys for Mr. Acejlnu Acdipr <acdipr@example.org>.
(define mailbox "acdipr@example.org")

;; The keys are sorted, from the least relevant to the most relevant
;; key.
(define keys
  '(("ED087E9D3394340738E20A244892A3CF8F65EBAC"
     "no encryption-capable subkey, created: 2003-11-30, expires: 2006-11-29"
     4)
    ("D7388651A1B7466D03B538428178E04B0BAA385B"
     "encryption-capable subkey, created: 2000-12-31, expired: 2001-12-31"
     0)
    ("DDEF1BEC66C8BAC8D69CED2AEABED840EC98B024"
     "encryption-capable subkey, created: 2001-12-31, expires: 2006-12-30"
     1)
    ("03FCFEDE014027DD897AD2F23D32670A96A9C2BF"
     "encryption-capable subkey, created: 2002-12-31, expires: 2005-12-30"
     2)
    ("B95BD6175CB6339244355BA160B8117E6119CED6"
     "encryption-capable subkeys, last created: 2003-05-31, expires: 2005-05-30"
     3)))

;; Accessors for the elements of KEYS.
(define :fpr car)
(define :comment cadr)
(define :number caddr)
(define (:filename key)
  (in-srcdir "tests" "openpgp" "key-selection"
	     (string-append (number->string (:number key)) ".asc")))

(define (delete-keys which)
  (call-check `(,@gpg --delete-keys ,@(map :fpr which))))

(define (import-keys which)
  (call-check `(,@gpg --import ,@(map :filename which))))

(for-each-p'
 "Checking key selection"
 (lambda (set)
   (import-keys set)
   (let ((fpr (list-ref (assoc "fpr"
			       (gpg-with-colons `(--locate-key ,mailbox)))
			9))
	 (expected (:fpr (last set))))
     (unless (equal? fpr expected)
	     (display "Given keys ")
	     (apply echo (map :fpr set))
	     (echo "This is what --locate-key says:")
	     (display (call-popen `(,@gpg --locate-key ,mailbox) ""))
	     (echo "This is the key we expected:")
	     (display (call-popen `(,@gpg --list-keys ,expected) ""))
	     (fail "Expected" expected "but got" fpr)))
   (delete-keys set))
 (lambda (set)
   (length set))
 (filter (lambda (x) (not (null? x))) (powerset keys)))
