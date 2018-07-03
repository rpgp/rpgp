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

(display "Checking trust signature with domain restrictions...\n")

(initscenario "scenario4")

(checktrust BOBBY "f")	;; Tsigned by Alice, allowed to sign for example.com.
(checktrust CAROL "-")	;; Signed by Bobby, but the signature should be
			;; ignored since Carol has an address in example.net.

(checktrust DAVID "f")	;; Tsigned by Alice, allowed to sign for example.net.
(checktrust FRANK "-")	;; Tsignature from David should be ignored because
			;; Frank has an address in example.com.

(checktrust HEIDI "f")	;; Tsigned by David, should be valid since Heidi
			;; has an address in example.org.
(checktrust GRACE "f")	;; Signed by Heidi.
