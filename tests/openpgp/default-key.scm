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

;; Import the sample key
;;
;; pub   1024R/8BC90111 2015-12-02
;;       Key fingerprint = E657 FB60 7BB4 F21C 90BB  6651 BC06 7AF2 8BC9 0111
;; uid       [ultimate] Barrett Brown <barrett@example.org>
;; sub   1024R/3E880CFF 2015-12-02 (encryption)
;; sub   1024R/F5F77B83 2015-12-02 (signing)
;; sub   1024R/45117079 2015-12-02 (encryption)
;; sub   1024R/1EA97479 2015-12-02 (signing)

(info "Importing public key.")
(call-check
 `(,(tool 'gpg) --import
   ,(in-srcdir "tests" "openpgp" "samplekeys/E657FB607BB4F21C90BB6651BC067AF28BC90111.asc")))

;; By default, the most recent, valid signing subkey (1EA97479).
(for-each-p
 "Checking that the most recent, valid signing subkey is used by default"
 (lambda (keyid)
   (tr:do
     (tr:pipe-do
      (pipe:defer (lambda (sink) (display "" (fdopen sink "w"))))
      (pipe:gpg `(--default-key ,keyid -s))
      (pipe:gpg '(--verify --status-fd=1)))
     (tr:call-with-content
      (lambda (c)
	(unless (string-contains?
		 c "VALIDSIG 5FBA84ACE02DCB17DA3DFF6BBCA43C441EA97479")
	    (exit 1))))))
 '("8BC90111" "3E880CFF" "F5F77B83" "45117079" "1EA97479"))

;; But, if we request a particular signing key, we should get it.
(for-each-p
 "Checking that the most recent, valid encryption subkey is used by default"
 (lambda (keyid)
   (tr:do
     (tr:pipe-do
      (pipe:defer (lambda (sink) (display "" (fdopen sink "w"))))
      ;; We need another recipient, because --encrypt-to-default-key is
      ;; not considered a recipient and gpg doesn't encrypt without any
      ;; recipients.
      ;;
      ;; Note: it doesn't matter whether we specify the primary key or
      ;; a subkey: the newest encryption subkey will be used.
      (pipe:gpg `(--default-key ,keyid --encrypt-to-default-key
				-r "439F02CA" -e))
      (pipe:gpg '(--list-packets)))
     (tr:call-with-content
      (lambda (c)
	(unless (any (lambda (line)
		       (and (string-prefix? line ":pubkey enc packet:")
			    (string-suffix? line "45117079")))
		     (string-split-newlines c))
	    (exit 1))))))
 '("8BC90111" "3E880CFF" "F5F77B83" "45117079" "1EA97479"))
