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

(display "Checking WoT with trust signatures (PGP trust model)...\n")

(initscenario "scenario2")

(checktrust BOBBY "f")	;; Tsigned by Alice with trust=120.
(checktrust CAROL "f")	;; Signed by Bobby, whose key should have full
			;; ownertrust due to the tsig.
(checktrust DAVID "f")	;; Signed by Alice.
(checktrust FRANK "q")	;; Tsigned by David, whose key has no ownertrust.
(checktrust GRACE "-")	;; Signed by Frank.

(setownertrust DAVID FULLTRUST)
(updatetrustdb)
(checktrust FRANK "f")	;; David's key has now full ownertrust.
(checktrust GRACE "q")	;; David is not authorized to emit tsigs,
			;; so his tsig on Frank's key should be treated
			;; like a normal sig (confering no ownertrust).
