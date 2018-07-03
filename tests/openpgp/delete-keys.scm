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
(setup-legacy-environment)

(let* ((key keys::alfa)
      (subkey (car key::subkeys)))
  (assert (have-public-key? key))
  (assert (have-public-key? subkey))
  (assert (have-secret-key? key))
  (assert (have-secret-key-file? key))
  (assert (have-secret-key? subkey))
  (assert (have-secret-key-file? subkey))

  ;; Firstly, delete the secret key.
  (call-check `(,@gpg --delete-secret-keys ,key::fpr))
  (assert (have-public-key? key))
  (assert (have-public-key? subkey))
  (assert (not (have-secret-key? key)))
  (assert (not (have-secret-key-file? key)))
  (assert (not (have-secret-key? subkey)))
  (assert (not (have-secret-key-file? subkey)))

  ;; Now, delete the public key.
  (call-check `(,@gpg --delete-keys ,key::fpr))
  (assert (not (have-public-key? key)))
  (assert (not (have-public-key? subkey))))

;; Do the same for key one, but do the subkeys separately.
(let* ((key keys::one)
       (subkey (car key::subkeys)))
  (assert (have-public-key? key))
  (assert (have-public-key? subkey))
  (assert (have-secret-key? key))
  (assert (have-secret-key-file? key))
  (assert (have-secret-key-file? key))
  (assert (have-secret-key? subkey))
  (assert (have-secret-key-file? subkey))

  ;; Firstly, delete the secret subkey.
  (call-check `(,@gpg --delete-secret-keys ,subkey::fpr))
  (assert (have-public-key? key))
  (assert (have-public-key? subkey))
  ;; JW: Deleting the secret subkey also deletes the secret key.  This
  ;; is a deliberate design choice, and currently there is no way to
  ;; delete the subkey without using --edit-key.
  ;; XXX (assert (have-secret-key? key))
  ;; XXX (assert (have-secret-key-file? key))
  (assert (not (have-secret-key? subkey)))
  (assert (not (have-secret-key-file? subkey)))

  ;; Then, delete the secret key.
  ;; JW: We already deleted the key.  See above.
  ;; XXX (call-check `(,@gpg --delete-secret-keys ,key::fpr))
  (assert (have-public-key? key))
  (assert (have-public-key? subkey))
  (assert (not (have-secret-key? key)))
  (assert (not (have-secret-key-file? key)))
  (assert (not (have-secret-key? subkey)))
  (assert (not (have-secret-key-file? subkey)))

  ;; Now, delete the public subkey.
  (call-check `(,@gpg --delete-keys ,subkey::fpr))
  ;; JW: Deleting the subkey also deletes the key.  This
  ;; is a deliberate design choice, and currently there is no way to
  ;; delete the subkey without using --edit-key.
  ;; XXX (assert (have-public-key? key))
  (assert (not (have-public-key? subkey)))

  ;; Now, delete the public key.
  ;; JW: We already deleted the key.  See above.
  ;; XXX (call-check `(,@gpg --delete-keys ,key::fpr))
  (assert (not (have-public-key? key)))
  (assert (not (have-public-key? subkey))))

(let* ((key keys::two)
      (subkey (car key::subkeys)))
  (assert (have-public-key? key))
  (assert (have-public-key? subkey))
  (assert (have-secret-key? key))
  (assert (have-secret-key-file? key))
  (assert (have-secret-key? subkey))
  (assert (have-secret-key-file? subkey))

  ;; Delete everything at once.
  (call-check `(,@gpg --delete-secret-and-public-key ,key::fpr))
  (assert (not (have-public-key? key)))
  (assert (not (have-public-key? subkey)))
  (assert (not (have-secret-key? key)))
  (assert (not (have-secret-key-file? key)))
  (assert (not (have-secret-key? subkey)))
  (assert (not (have-secret-key-file? subkey))))
