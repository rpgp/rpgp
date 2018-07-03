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

(info "Checking passphrase cache (issue2015)...")
(call-check `(,(tool 'gpg-preset-passphrase)
	      --preset --passphrase some_passphrase some_id))

(let ((response (call-popen `(,(tool 'gpg-connect-agent))
			    "GET_PASSPHRASE --no-ask some_id X X X")))
  (unless (string=? (string-rtrim char-whitespace? response)
		    "OK 736F6D655F70617373706872617365")
	  (fail "Could not retrieve passphrase from cache:" response)))
