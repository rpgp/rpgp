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

(define key (in-srcdir "tests" "openpgp" "samplekeys/issue2346.gpg"))

(info "Checking import statistics (issue2346)...")
(let ((status (call-popen `(,@GPG --status-fd=1 --import ,key) "")))
  (unless (string-contains? status "IMPORT_RES 1 0 1 0 0 0 0 0 0 1 1 0 0 0 0")
	  (fail "Unexpected number of keys imported" status)))
