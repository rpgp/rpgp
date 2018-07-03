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
(setup-legacy-environment)

(lettmp (steve's-key)
  (call-check `(,@gpg --output ,steve's-key --export "1D777619BE310D79"))

  (for-each-p
   "Checking unwrapping the encryption."
   (lambda (name)
     ;; First, unwrap the encrypted message using Steve's secret key.
     (lettmp (unwrapped)
       (tr:do
	(tr:open (in-srcdir "tests" "openpgp" "samplemsgs" (string-append name ".asc")))
	(tr:gpg "" `(--yes --decrypt --unwrap))
	(tr:write-to unwrapped))

       ;; Then, verify the signature with a clean working directory
       ;; containing only Steve's public key.
       (with-ephemeral-home-directory setup-environment-no-atexit stop-agent
	(call-check `(,@gpg --import ,steve's-key))
	(call-check `(,@gpg --verify ,unwrapped)))))
  '("encsig-2-keys-3" "encsig-2-keys-4")))
