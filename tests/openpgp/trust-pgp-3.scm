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

(display "Checking max depth of trust signature chains...\n")

(initscenario "scenario3")

(checktrust BOBBY "f")	;; Tsigned by Alice (level=2, trust=120).
(checktrust CAROL "f")	;; Tsigned by Bobby (level=2, trust=120).
(checktrust DAVID "f")	;; Tsigned by Carol (level=2, trust=120).
(checktrust FRANK "q")	;; The tsig from Carol does not confer
			;; ownertrust to David's key (too deep).
