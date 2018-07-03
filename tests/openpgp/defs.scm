;; Common definitions for the OpenPGP test scripts.
;;
;; Copyright (C) 2016, 2017 g10 Code GmbH
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

;;
;; Constants.
;;

(define usrname1 "one@example.com")
(define usrpass1 "def")
(define usrname2 "two@example.com")
(define usrpass2 "")
(define usrname3 "three@example.com")
(define usrpass3 "")

(define dsa-usrname1 "pgp5")
;; we use the sub key because we do not yet have the logic to derive
;; the first encryption key from a keyblock (I guess) (Well of course
;; we have this by now and the notation below will lookup the primary
;; first and then search for the encryption subkey.)
(define dsa-usrname2 "0xCB879DE9")

(define keys
  (package
   (define (new fpr grip uids subkeys)
     (package))
   (define (subkey fpr grip)
     (package))
   (define alfa (new "A0FF4590BB6122EDEF6E3C542D727CC768697734"
		     "76F7E2B35832976B50A27A282D9B87E44577EB66"
		     '("alfa@example.net" "alpha@example.net")
		     (list
		      (subkey "3B3FBC948FE59301ED629EFB6AE6D7EE46A871F8"
			      "A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD"))))
   (define one (new "289B0EF1D105E124B6F626020EF77096D74C5F22"
		    "50B2D4FA4122C212611048BC5FC31BD44393626E"
		    '("one@example.com")
		    (list
		     (subkey "EB467DCA4AD7676A6A62B2ABABAB28A247BE2775"
			     "7E201E28B6FEB2927B321F443205F4724EBE637E"))))
   (define two (new "C1DEBB34EA8B71009EAFA474973D50E1C40FDECF"
		    "343D8AF79796EE107D645A2787A9D9252F924E6F"
		    '("two@example.com")
		    (list
		     (subkey "CD3D0F5701CBFCACB2A4907305A37887B27907AA"
			     "8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34"))))))

(define key-file1 "samplekeys/rsa-rsa-sample-1.asc")
(define key-file2 "samplekeys/ed25519-cv25519-sample-1.asc")

(define plain-files '("plain-1" "plain-2" "plain-3" "plain-large"))
(define data-files '("data-500" "data-9000" "data-32000" "data-80000"))
(define exp-files '())
(define all-files (append plain-files data-files))

(let ((verbose (string->number (getenv "verbose"))))
  (if (number? verbose)
      (*set-verbose!* verbose)))

(define (qualify executable)
  (string-append executable (getenv "EXEEXT")))

(define (getenv' key default)
  (let ((value (getenv key)))
    (if (string=? "" value)
	default
	value)))

(define (percent-decode s)
  (define (decode c)
    (if (and (> (length c) 2) (char=? #\% (car c)))
	(integer->char (string->number (string #\# #\x (cadr c) (caddr c))))
	#f))
  (let loop ((i 0) (c (string->list s)) (r (make-string (string-length s))))
    (if (null? c)
	(substring r 0 i)
	(let ((decoded (decode c)))
	  (string-set! r i (if decoded decoded (car c)))
	  (loop (+ 1 i) (if decoded (cdddr c) (cdr c)) r)))))
(assert (equal? (percent-decode "") ""))
(assert (equal? (percent-decode "%61") "a"))
(assert (equal? (percent-decode "foob%61r") "foobar"))

(define (percent-encode s)
  (define (encode c)
    `(#\% ,@(string->list (number->string (char->integer c) 16))))
  (let loop ((acc '()) (cs (reverse (string->list s))))
    (if (null? cs)
	(list->string acc)
	(case (car cs)
	  ((#\: #\%)
	   (loop (append (encode (car cs)) acc) (cdr cs)))
	  (else
	   (loop (cons (car cs) acc) (cdr cs)))))))
(assert (equal? (percent-encode "") ""))
(assert (equal? (percent-encode "%61") "%2561"))
(assert (equal? (percent-encode "foob%61r") "foob%2561r"))

(define tools
  '((gpgv "GPGV" "g10/gpgv")
    (gpg-connect-agent "GPG_CONNECT_AGENT" "tools/gpg-connect-agent")
    (gpgconf "GPGCONF" "tools/gpgconf")
    (gpg-preset-passphrase "GPG_PRESET_PASSPHRASE"
			   "agent/gpg-preset-passphrase")
    (gpgtar "GPGTAR" "tools/gpgtar")
    (gpg-zip "GPGZIP" "tools/gpg-zip")
    (pinentry "PINENTRY" "tests/openpgp/fake-pinentry")))

(define bin-prefix (getenv "BIN_PREFIX"))
(define installed? (not (string=? "" bin-prefix)))

(define (tool-hardcoded which)
  (let ((t (assoc which tools)))
    (getenv' (cadr t)
	     (qualify (if installed?
			  (string-append bin-prefix "/" (basename (caddr t)))
			  (string-append (getenv "objdir") "/" (caddr t)))))))

;; You can splice VALGRIND into your argument vector to run programs
;; under valgrind.  For example, to run valgrind on gpg, you may want
;; to redefine gpg:
;;
;; (set! gpg `(,@valgrind ,@gpg))
;;
(define valgrind
  '("/usr/bin/valgrind" --leak-check=full --error-exitcode=154))

(unless installed?
	(setenv "GNUPG_BUILDDIR" (getenv "objdir") #t))

(define (gpg-conf . args)
  (gpg-conf' "" args))
(define (gpg-conf' input args)
  (let ((s (call-popen `(,(tool-hardcoded 'gpgconf)
			 ,@(if installed? '()
			       (list '--build-prefix (getenv "objdir")))
			 ,@args) input)))
    (map (lambda (line) (map percent-decode (string-split line #\:)))
	 (string-split-newlines s))))
(define :gc:c:name car)
(define :gc:c:description cadr)
(define :gc:c:pgmname caddr)
(define (:gc:o:name x)             (list-ref x 0))
(define (:gc:o:flags x)            (string->number (list-ref x 1)))
(define (:gc:o:level x)            (string->number (list-ref x 2)))
(define (:gc:o:description x)      (list-ref x 3))
(define (:gc:o:type x)             (string->number (list-ref x 4)))
(define (:gc:o:alternate-type x)   (string->number (list-ref x 5)))
(define (:gc:o:argument-name x)    (list-ref x 6))
(define (:gc:o:default-value x)    (list-ref x 7))
(define (:gc:o:default-argument x) (list-ref x 8))
(define (:gc:o:value x)            (if (< (length x) 10) "" (list-ref x 9)))

(define (gpg-config component key)
  (package
   (define (value)
     (let* ((conf (assoc key (gpg-conf '--list-options component)))
	    (type (:gc:o:type conf))
	    (value (:gc:o:value conf)))
       (case type
	 ((0 2 3) (string->number value))
	 ((1 32) (substring value 1 (string-length value))))))
   (define (update value)
     (let ((value' (cond
		    ((string? value) (string-append "\"" value))
		    ((number? value) (number->string value))
		    (else (throw "Unsupported value" value)))))
       (gpg-conf' (string-append key ":0:" (percent-encode value'))
		  `(--change-options ,component))))
   (define (clear)
     (gpg-conf' (string-append key ":16:")
		`(--change-options ,component)))))

(define gpg-components (apply gpg-conf '(--list-components)))

(define (tool which)
  (case which
    ((gpg gpg-agent scdaemon gpgsm dirmngr)
     (:gc:c:pgmname (assoc (symbol->string which) gpg-components)))
    (else
     (tool-hardcoded which))))

(define (gpg-has-option? option)
  (string-contains? (call-popen `(,(tool 'gpg) --dump-options) "")
		    option))

(define have-opt-always-trust
  (catch #f
	 (with-ephemeral-home-directory (lambda ()) (lambda ())
	   (call-check `(,(tool 'gpg) --gpgconf-test --always-trust)))
	 #t))

(define GPG `(,(tool 'gpg) --no-permission-warning
	      ,@(if have-opt-always-trust '(--always-trust) '())))
(define GPGV `(,(tool 'gpgv)))
(define PINENTRY (tool 'pinentry))

(define (tr:gpg input args)
  (tr:spawn input `(,@GPG --output **out** ,@args **in**)))

(define (pipe:gpg args)
  (pipe:spawn `(,@GPG --output - ,@args -)))

(define (gpg-with-colons args)
  (let ((s (call-popen `(,@GPG --with-colons ,@args) "")))
    (map (lambda (line) (string-split line #\:))
	 (string-split-newlines s))))

;; Convenient accessors for the colon output.
(define (:type x)   (string->symbol (list-ref x 0)))
(define (:length x) (string->number (list-ref x 2)))
(define (:alg x) (string->number (list-ref x 3)))
(define (:expire x) (list-ref x 6))
(define (:fpr x) (list-ref x 9))
(define (:cap x) (list-ref x 11))

(define (have-public-key? key)
  (catch #f
	 (pair? (filter (lambda (l) (and (equal? 'fpr (:type l))
					 (equal? key::fpr (:fpr l))))
			(gpg-with-colons `(--list-keys ,key::fpr))))))

(define (have-secret-key? key)
  (catch #f
	 (pair? (filter (lambda (l) (and (equal? 'fpr (:type l))
					 (equal? key::fpr (:fpr l))))
			(gpg-with-colons `(--list-secret-keys ,key::fpr))))))

(define (have-secret-key-file? key)
  (file-exists? (path-join (getenv "GNUPGHOME") "private-keys-v1.d"
			   (string-append key::grip ".key"))))

(define (get-config what)
  (string-split (caddar (gpg-with-colons `(--list-config ,what))) #\;))

(define all-pubkey-algos (delay (get-config "pubkeyname")))
(define all-hash-algos (delay (get-config "digestname")))
(define all-cipher-algos (delay (get-config "ciphername")))
(define all-compression-algos (delay (get-config "compressname")))

(define (have-pubkey-algo? x)
  (not (not (member x (force all-pubkey-algos)))))
(define (have-hash-algo? x)
  (not (not (member x (force all-hash-algos)))))
(define (have-cipher-algo? x)
  (not (not (member x (force all-cipher-algos)))))
(define (have-compression-algo? x)
  (not (not (member x (force all-compression-algos)))))

(define (gpg-pipe args0 args1 errfd)
  (lambda (source sink)
    (let* ((p (pipe))
	   (task0 (spawn-process-fd `(,@GPG ,@args0)
		   source (:write-end p) errfd))
	   (_ (close (:write-end p)))
	   (task1 (spawn-process-fd `(,@GPG ,@args1)
		   (:read-end p) sink errfd)))
      (close (:read-end p))
      (wait-processes (list GPG GPG) (list task0 task1) #t))))

(setenv "GPG_AGENT_INFO" "" #t)
(setenv "GNUPGHOME" (getcwd) #t)
(define GNUPGHOME (getcwd))

;;
;; GnuPG helper.
;;

;; Call GPG to obtain the hash sums.  Either specify an input file in
;; ARGS, or an string in INPUT.  Returns a list of (<algo>
;; "<hashsum>") lists.
(define (gpg-hash-string args input)
  (map
   (lambda (line)
     (let ((p (string-split line #\:)))
       (list (string->number (cadr p)) (caddr p))))
   (string-split-newlines
    (call-popen `(,@GPG --with-colons ,@args) input))))

;; Dearmor a file.
(define (dearmor source-name sink-name)
  (pipe:do
   (pipe:open source-name (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --dearmor))
   (pipe:write-to sink-name (logior O_WRONLY O_CREAT O_BINARY) #o600)))

(define (gpg-dump-packets source-name sink-name)
  (pipe:do
   (pipe:open source-name (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --list-packets))
   (pipe:write-to sink-name (logior O_WRONLY O_CREAT O_BINARY) #o600)))

;;
;; Support for test environment creation and teardown.
;;

(define (make-test-data filename size)
  (call-with-binary-output-file
   filename
   (lambda (port)
     (display (make-random-string size) port))))

(define (create-file name . lines)
  (catch #f (unlink name))
  (letfd ((fd (open name (logior O_WRONLY O_CREAT O_BINARY) #o600)))
    (let ((port (fdopen fd "wb")))
      (for-each (lambda (line) (display line port) (newline port))
		lines))))

(define (create-gpghome)
  (log "Creating test environment...")

  (srandom (getpid))
  (make-test-data "random_seed" 600)

  (log "Creating configuration files")

  (if (flag "--use-keyring" *args*)
      (create-file "pubring.gpg"))

  (create-file "gpg.conf"
	       "no-greeting"
	       "no-secmem-warning"
	       "no-permission-warning"
	       "batch"
               "no-auto-key-retrieve"
               "no-auto-key-locate"
	       "allow-weak-digest-algos"
               "ignore-mdc-error"
	       (if have-opt-always-trust
		   "no-auto-check-trustdb" "#no-auto-check-trustdb")
	       (string-append "agent-program "
			      (tool 'gpg-agent)
			      "|--debug-quick-random\n")
	       )
  (create-file "gpg-agent.conf"
	       "allow-preset-passphrase"
	       "no-grab"
	       "enable-ssh-support"
               "s2k-count 65536"
	       (if (flag "--extended-key-format" *args*)
		   "enable-extended-key-format" "#enable-extended-key-format")
	       (string-append "pinentry-program " (tool 'pinentry))
	       (if (assoc "scdaemon" gpg-components)
		   (string-append "scdaemon-program " (tool 'scdaemon))
		   "# No scdaemon available")
	       ))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, without any keys.
(define (setup-environment)
  (create-gpghome)
  (start-agent))

(define (setup-environment-no-atexit)
  (create-gpghome)
  (start-agent #t))

(define (create-sample-files)
  (log "Creating sample data files")
  (for-each
   (lambda (size)
     (make-test-data (string-append "data-" (number->string size))
		     size))
   '(500 9000 32000 80000))

  (log "Unpacking samples")
  (for-each
   (lambda (name)
     (dearmor (in-srcdir "tests" "openpgp" (string-append name "o.asc")) name))
   plain-files))

(define (create-legacy-gpghome)
  (create-sample-files)

  (log "Storing private keys")
  (for-each
   (lambda (name)
     (dearmor (in-srcdir "tests" "openpgp" "privkeys" (string-append name ".asc"))
	      (string-append "private-keys-v1.d/" name ".key")))
   '("50B2D4FA4122C212611048BC5FC31BD44393626E"
     "7E201E28B6FEB2927B321F443205F4724EBE637E"
     "13FDB8809B17C5547779F9D205C45F47CE0217CE"
     "343D8AF79796EE107D645A2787A9D9252F924E6F"
     "8B5ABF3EF9EB8D96B91A0B8C2C4401C91C834C34"
     "0D6F6AD4C4C803B25470F9104E9F4E6A4CA64255"
     "FD692BD59D6640A84C8422573D469F84F3B98E53"
     "76F7E2B35832976B50A27A282D9B87E44577EB66"
     "A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD"
     "00FE67F28A52A8AA08FFAED20AF832DA916D1985"
     "1DF48228FEFF3EC2481B106E0ACA8C465C662CC5"
     "A2832820DC9F40751BDCD375BB0945BA33EC6B4C"
     "ADE710D74409777B7729A7653373D820F67892E0"
     "CEFC51AF91F68A2904FBFF62C4F075A4785B803F"
     "1E28F20E41B54C2D1234D896096495FF57E08D18"
     "EB33B687EB8581AB64D04852A54453E85F3DF62D"
     "C6A6390E9388CDBAD71EAEA698233FE5E04F001E"
     "D69102E0F5AC6B6DB8E4D16DA8E18CF46D88CAE3"))

  (log "Importing public demo and test keys")
  (for-each
   (lambda (file)
     (call-check `(,@GPG --yes --import ,(in-srcdir "tests" "openpgp" file))))
   (list "pubdemo.asc" "pubring.asc" key-file1))

  (pipe:do
   (pipe:open (in-srcdir "tests" "openpgp" "pubring.pkr.asc") (logior O_RDONLY O_BINARY))
   (pipe:spawn `(,@GPG --dearmor))
   (pipe:spawn `(,@GPG --yes --import))))

(define (preset-passphrases)
  (log "Presetting passphrases")
  ;; one@example.com
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase def
		"50B2D4FA4122C212611048BC5FC31BD44393626E"))
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase def
		"7E201E28B6FEB2927B321F443205F4724EBE637E"))
  ;; alpha@example.net
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase abc
		"76F7E2B35832976B50A27A282D9B87E44577EB66"))
  (call-check `(,(tool 'gpg-preset-passphrase)
		--preset --passphrase abc
		"A0747D5F9425E6664F4FFBEED20FBCA79FDED2BD")))

;; Initialize the test environment, install appropriate configuration
;; and start the agent, with the keys from the legacy test suite.
(define (setup-legacy-environment)
  (create-gpghome)
  (if (member "--unpack-tarball" *args*)
      (begin
	(call-check `(,(tool 'gpgtar) --extract --directory=. ,(cadr *args*)))
	(start-agent))
      (begin
	(start-agent)
	(create-legacy-gpghome)))
  (preset-passphrases))

;; Create the socket dir and start the agent.
(define (start-agent . args)
  (log "Starting gpg-agent...")
  (let ((gnupghome (getenv "GNUPGHOME")))
    (if (null? args)
	(atexit (lambda ()
		  (with-home-directory gnupghome (stop-agent))))))
  (catch (log "Warning: Creating socket directory failed:" (car *error*))
	 (gpg-conf '--create-socketdir))
  (call-check `(,(tool 'gpg-connect-agent) --verbose
		,(string-append "--agent-program=" (tool 'gpg-agent)
				"|--debug-quick-random")
		/bye)))

;; Stop the agent and other daemons and remove the socket dir.
(define (stop-agent)
  (log "Stopping gpg-agent...")
  (gpg-conf '--kill 'all)
  (catch (log "Warning: Removing socket directory failed.")
	 (gpg-conf '--remove-socketdir)))

;; Get the trust level for KEYID.  Any remaining arguments are simply
;; passed to GPG.
;;
;; This function only supports keys with a single user id.
(define (gettrust keyid . args)
  (let ((trust
	  (list-ref (assoc "pub" (gpg-with-colons
				   `(,@args
				      --list-keys ,keyid))) 1)))
    (unless (and (= 1 (string-length trust))
		 (member (string-ref trust 0) (string->list "oidreqnmfuws-")))
	    (fail "Bad trust value:" trust))
    trust))

;; Check that KEYID's trust level matches EXPECTED-TRUST.  Any
;; remaining arguments are simply passed to GPG.
;;
;; This function only supports keys with a single user id.
(define (checktrust keyid expected-trust . args)
  (let ((trust (apply gettrust `(,keyid ,@args))))
    (unless (string=? trust expected-trust)
	    (fail keyid ": Expected trust to be" expected-trust
		   "but got" trust))))


;; end
