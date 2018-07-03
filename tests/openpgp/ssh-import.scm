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

(setenv "SSH_AUTH_SOCK"
        (call-check `(,(tool 'gpgconf) --null --list-dirs agent-ssh-socket))
        #t)

(define path (string-split (getenv "PATH") *pathsep*))
(define ssh #f)
(catch (skip "ssh not found") (set! ssh (path-expand "ssh" path)))

(define ssh-add #f)
(catch (skip "ssh-add not found")
       (set! ssh-add (path-expand "ssh-add" path)))

(define ssh-keygen #f)
(catch (skip "ssh-keygen not found")
       (set! ssh-keygen (path-expand "ssh-keygen" path)))

(define ssh-version-string
  (:stderr (call-with-io `(,ssh "-V") "")))

(log "Using" ssh "version:" ssh-version-string)

(define ssh-version
  (let ((tmp ssh-version-string)
	(prefix "OpenSSH_"))
    (unless (string-prefix? tmp prefix)
	    (skip "This doesn't look like OpenSSH:" tmp))
    (string->number (substring tmp (string-length prefix)
			       (+ 3 (string-length prefix))))))

(define (ssh-supports? algorithm)
  ;; We exploit ssh-keygen as an oracle to test what algorithms ssh
  ;; supports.
  (cond
   ((equal? algorithm "ed25519")
    ;; Unfortunately, our oracle does not work for ed25519 because
    ;; this is a specific curve and not a family, so the key size
    ;; parameter is ignored.
    (>= ssh-version 6.5))
   (else
    ;; We call ssh-keygen with the algorithm to test, specify an
    ;; invalid key size, and observe the error message.
    (let ((output (:stderr (call-with-io `(,ssh-keygen
					   -t ,algorithm
					   -b "1009") ""))))
      (log "(ssh-supports?" algorithm "), ssh algorithm oracle replied:" output)
      (not (string-contains? output "unknown key type"))))))

(define keys
  '(("dsa" "9a:e1:f1:5f:46:ea:a5:06:e1:e2:f8:38:8e:06:54:58")
    ("rsa" "c9:85:b5:55:00:84:a9:82:5a:df:d6:62:1b:5a:28:22")
    ("ecdsa" "93:37:30:a6:4e:e7:6a:22:79:77:8e:bf:ed:14:e9:8e")
    ("ed25519" "08:df:be:af:d2:f5:32:20:3a:1c:56:06:be:31:0f:bf")))

(for-each-p'
 "Importing ssh keys..."
 (lambda (key)
   (let ((file (path-join (in-srcdir "tests" "openpgp" "samplekeys")
			  (string-append "ssh-" (car key) ".key")))
	 (hash (cadr key)))
     ;; We pipe the key to ssh-add so that it won't complain about
     ;; file's permissions.
     (pipe:do
      (pipe:open file (logior O_RDONLY O_BINARY))
      (pipe:spawn `(,SSH-ADD -)))
     (unless (string-contains? (call-popen `(,SSH-ADD -l "-E" md5) "") hash)
	     (fail "key not added"))))
 car (filter (lambda (x) (ssh-supports? (car x))) keys))

(info "Checking for issue2316...")
(unlink (path-join GNUPGHOME "sshcontrol"))
(pipe:do
 (pipe:open (path-join (in-srcdir "tests" "openpgp" "samplekeys")
		       (string-append "ssh-rsa.key"))
	    (logior O_RDONLY O_BINARY))
 (pipe:spawn `(,SSH-ADD -)))
(unless
 (string-contains? (call-popen `(,SSH-ADD -l "-E" md5) "")
		   "c9:85:b5:55:00:84:a9:82:5a:df:d6:62:1b:5a:28:22")
 (fail "known private key not (re-)added to sshcontrol"))
