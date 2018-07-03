#!/usr/bin/env gpgscm

;; Copyright (C) 2017 Damien Goutte-Gattat
;;
;; This file is part of GnuPG.
;;
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

(load (in-srcdir "tests" "openpgp" "trust-pgp" "common.scm"))

(display "Checking basic WoT (classic trust model)...\n")

(initscenario "scenario1")

;; Check initial state.
(checktrust BOBBY "f")	;; Directly signed by Alice's key.
(checktrust CAROL "q")	;; Signed by Bobby, whose key has
			;; no explicit ownertrust.
(checktrust DAVID "q")	;; Likewise.
(checktrust FRANK "q")	;; Likewise.
(checktrust GRACE "-")	;; Signed by the previous three keys;
			;; not evaluated since they are not valid.

;; Let's trust Bobby.
;; This should make Carol's, David's, and Frank's keys valid.
(setownertrust BOBBY FULLTRUST)
(updatetrustdb)
(checktrust CAROL "f")
(checktrust DAVID "f")
(checktrust FRANK "f")
(checktrust GRACE "q")	;; Now evaluated, but validity still unknown.

;; Let's trust (marginally) Carol and David.
;; This should not be enough to make Grace's key fully valid
;; since marginals-needed defaults to 3.
(setownertrust CAROL MARGINALTRUST)
(setownertrust DAVID MARGINALTRUST)
(updatetrustdb)
(checktrust GRACE "m")

;; Add marginal ownertrust to Frank's key.
;; This should make Grace's key fully valid.
(setownertrust FRANK MARGINALTRUST)
(updatetrustdb)
(checktrust GRACE "f")

;; Now let's play with the length of certification chains.
;; Setting max-cert-length to 2 should put Grace's key
;; one step too far from Alice's key.
(let ((max-cert-depth (gpg-config 'gpg "max-cert-depth")))
  (max-cert-depth::update 2))
(updatetrustdb)
(checktrust GRACE "-")

;; Raise the bar for assigning full validity.
;; Bobby's key should be the only one retaining full validity.
(let ((completes-needed (gpg-config 'gpg "completes-needed")))
  (completes-needed::update 2))
(updatetrustdb)
(checktrust BOBBY "f")
(checktrust CAROL "m")
(checktrust DAVID "m")
(checktrust FRANK "m")
(checktrust GRACE "-")
