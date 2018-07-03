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

;; GnuPG through 2.1.7 would incorrect mark packets whose size is
;; 2^32-1 as invalid and exit with status code 2.

(load (in-srcdir "tests" "openpgp" "defs.scm"))
(setup-environment)

(unless (have-compression-algo? "BZIP2")
	(skip "BZIP2 support not compiled in."))

(call-check `(,@GPG --list-packets ,(in-srcdir "tests" "openpgp" "4gb-packet.asc")))
