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
(setup-environment)

(define empty-string-hashes
  `((1 "D41D8CD98F00B204E9800998ECF8427E" "MD5")
    (2 "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709" "SHA1")
    (3 "9C1185A5C5E9FC54612808977EE8F548B2258D31" "RIPEMD160")
    (11 "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F" "SHA224")
    (8 "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" "SHA256")
    (9 "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B" "SHA384")
    (10
     "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
     "SHA512")))

(define abc-hashes
  `((1 "C3FCD3D76192E4007DFB496CCA67E13B" "MD5")
    (2 "32D10C7B8CF96570CA04CE37F2A19D84240D3A89" "SHA1")
    (3 "F71C27109C692C1B56BBDCEB5B9D2865B3708DBC" "RIPEMD160")
    (11 "45A5F72C39C5CFF2522EB3429799E49E5F44B356EF926BCF390DCCC2" "SHA224")
    (8 "71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73" "SHA256")
    (9 "FEB67349DF3DB6F5924815D6C3DC133F091809213731FE5C7B5F4999E463479FF2877F5F2936FA63BB43784B12F3EBB4" "SHA384")
    (10 "4DBFF86CC2CA1BAE1E16468A05CB9881C97F1753BCE3619034898FAA1AABE429955A1BF8EC483D7421FE3C1646613A59ED5441FB0F321389F77F48A879C7B1F1" "SHA512")))

;; Symbolic names for the triples above.
(define :algo car)
(define :value cadr)
(define :name caddr)

;; Test whether HASH matches REF.
(define (test-hash hash ref)
  (unless (eq? #f ref)
	  (if (not (string=? (:value hash) (:value ref)))
	    (fail "failed"))))

;; Test whether the hashes computed over S match the REFERENCE set.
(define (test-hashes msg s reference)
  (for-each-p'
   msg
   (lambda (hash) (test-hash hash (assv (:algo hash) reference)))
   (lambda (hash)
     (let ((ref (assv (:algo hash) reference)))
       (if (eq? #f ref)
	   (string-append "no-ref-for:" (number->string (:algo hash)))
	   (:name ref))))
   (gpg-hash-string '(--print-mds) s)))

(test-hashes "Hashing the empty string"
 "" empty-string-hashes)
(test-hashes "Hashing the string \"abcdefghijklmnopqrstuvwxyz\""
 "abcdefghijklmnopqrstuvwxyz" abc-hashes)
