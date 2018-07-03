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

(catch (skip "Tofu not supported")
       (call-check `(,@gpg --trust-model=tofu --list-config)))

;; Redefine GPG without --always-trust and TOFU trust model.
(define gpg `(,(tool 'gpg) --no-permission-warning --trust-model=tofu))

(info "Checking TOFU trust model with ultimately trusted keys (issue2929).")
(call-check `(,@gpg --quick-generate-key frob@example.org))
(call-check `(,@gpg --sign gpg.conf))
(call-check `(,@gpg --verify gpg.conf.gpg))
