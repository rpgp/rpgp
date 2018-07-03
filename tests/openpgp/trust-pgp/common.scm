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

(load (in-srcdir "tests" "openpgp" "defs.scm"))

;; Redefine GPG without --always-trust.
(define GPG `(,(tool 'gpg)))

;; Helper constants for setownertrust.
(define MARGINALTRUST "4")
(define FULLTRUST "5")
(define ULTIMATETRUST "6")

;; Assign OWNERTRUST to the key identified by the provided
;; fingerprint KEYFPR.
(define (setownertrust keyfpr ownertrust)
  (pipe:do
    (pipe:echo (string-append keyfpr ":" ownertrust ":\n"))
    (pipe:gpg `(--import-ownertrust))))

;; Force a trustdb update.
(define (updatetrustdb)
  (call-check `(,@GPG --check-trustdb --yes)))

;; IDs of all the keys involved in those tests.
(define ALICE "FD9B20DD3C98123EEEAF8CC51BA41538D2E656B5")
(define BOBBY "4D3F59F4D8030FD2D844AFEBA5BAC3ED125CCAE5")
(define CAROL "6C62735E454CCDD79FA6CA601079113AEC1282FD")
(define DAVID "A0607635198CABA2C467FAA64CE5BB42E3984000")
(define FRANK "CE1A0E07CF8A20CBF8DC47D6DB9017DBAE6CD0EF")
(define GRACE "B935F4B8DA009AFBCCDD41386653A183007F8345")
(define HEIDI "0389C0B7990E10520B334F23756F1571EDA9184B")

;; Initialize a given scenario.
;; NAME should be the basename of the scenario file
;; in this directory.
(define (initscenario name)
  (setup-environment)
  ;; Make sure we are using the PGP trust model. This may no
  ;; be the default model in the future.
  (let ((trust-model (gpg-config 'gpg "trust-model")))
    (trust-model::update "pgp"))
  ;; Load the scenario's public keys.
  (call-check `(,@GPG --import
		      ,(in-srcdir "tests" "openpgp" "trust-pgp"
				  (string-append name ".asc"))))
  ;; Use Alice's key as root for all trust evaluations.
  (setownertrust ALICE ULTIMATETRUST)
  (updatetrustdb))
