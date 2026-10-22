; # x-ssh -- SSH on x-lang
;
; ## ssh/server.x -- the server: commands run for authenticated users
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What OpenSSH's sshd does, for the user it runs as: settle the
; configuration -- the command line's options, then sshd_config, the
; first value holding -- listen, take each connection in a process of its
; own, exchange keys under the host key, let the user in by an Ed25519,
; RSA or ECDSA key in an authorized_keys file or by the password in the
; shadow file, as PermitRootLogin and the rest allow, and run the
; command an "exec" asks for in the user's shell, its standard input the
; channel's data and its output the channel's, its exit status sent back.
; Forwarding is served both ways.  One suite: curve25519-sha256,
; ssh-ed25519, chacha20-poly1305@openssh.com.  Not served yet: other
; users than the one the server runs as (that is a root server's
; business, dropping privileges), terminals and shells.  The log goes to
; syslog in OpenSSH's words, or to standard error.

(module ssh/server)

(import x/type/vector)
(import x/sys/socket)
(import x/sys/file)
(import x/sys/posix)
(import x/sys/gc)
(import x/codec/base64)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-text ssh-put-string ssh-put-bytes ssh-put-names ssh-out-run
  ssh-in ssh-in-buf ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-bytes ssh-get-text ssh-copy)
(import ssh/transport ssh-open ssh-fd ssh-session-id ssh-pending? ssh-engines! ssh-exchange-versions! ssh-kex-server!
  ssh-send-packet! ssh-next-packet! ssh-expect! ssh-msg-service-request ssh-msg-service-accept
  ssh-msg-userauth-request ssh-msg-userauth-failure ssh-msg-userauth-success ssh-msg-disconnect
  ssh-msg-global-request ssh-msg-request-success ssh-msg-request-failure)
(import ssh/keys ssh-identity-read-file ssh-key-wrong-passphrase)
(import x/codec/ed25519)
(import x/codec/crypt)
(import x/sys/syslog)
(import ssh/keygen ssh-key-fingerprint ssh-blob-fingerprint)
(import ssh/pubkey ssh-pubkey-of ssh-pubkey-type ssh-pubkey-label ssh-pubkey-blob ssh-pubkey-algorithms ssh-pubkey-verify?
  ssh-identity-pubkey)
(import ssh/pty ssh-pty-open ssh-pty-window! ssh-pty-attach!)
(import ssh/config ssh-config-read ssh-config-options ssh-config-first ssh-config-all ssh-config-faults
  ssh-config-time ssh-config-patterns? ssh-config-sshd-keywords)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %cvt (prim-ref (lit convert) (lit to)))

(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))
(def %get (fn (_ s k) (rest (List find (fn (_ p) (eq? (first p) k)) s))))

; An error's message: an Err's own, or a word for what the engine raised.
(def %message
  (fn (_ e)
    (guard (e2 "an internal error")
      (if (Err engine? e) (Str8 append (Err %str (Err code-of e)) ": " (Err %str (Err subject-of e))) (e msg)))))

; --- the log ---------------------------------------------------------------

; The levels, quietest first, and the syslog severity each is sent at.
(def %levels
  (list (list "quiet" () ) (list "fatal" (lit crit)) (list "error" (lit err)) (list "info" (lit info))
        (list "verbose" (lit info)) (list "debug1" (lit debug)) (list "debug2" (lit debug)) (list "debug3" (lit debug))))

(def %rank
  (fn (_ level)
    (def l (if (str=? level "debug") "debug1" level))
    ((fn (self ls i) (if (null? ls) 3 (if (str=? (first (first ls)) l) i (self (rest ls) (+ i 1))))) %levels 0)))

; Where the log goes, set once by the server, inherited by each
; connection's process: 1 syslog, or #f for the descriptor in 2; 3 the
; facility; 4 the rank of the most verbose level written.
(def %log-to (Vector make 4 ()))
(%oset! %log-to 1 #f) (%oset! %log-to 2 2) (%oset! %log-to 3 (lit auth)) (%oset! %log-to 4 3)

; A line logged at a level, when the log level takes it: to syslog under
; the ident sshd in the facility, or, under -e, -E or where no daemon
; listens, to the descriptor, a debug line led by its level.
(def %log-at
  (fn (_ level text)
    (def rank (%rank level))
    (when (<= rank (%oref %log-to 4))
      (do (def severity (first (rest (List ref rank %levels))))
          (unless (if (%oref %log-to 1) (Syslog send "sshd" (%oref %log-to 3) severity text) #f)
            (do (def line (Str8 append (if (>= rank 5) (Str8 append level ": ") "") text "\n"))
                (File write (%oref %log-to 2) line (%byte-len line))))))))

(def %log (fn (_ text) (%log-at "info" text)))
(def %debug (fn (_ text) (%log-at "debug1" text)))

(def %msg-userauth-pk-ok 60)
(def %msg-channel-open 90) (def %msg-channel-open-confirmation 91)
(def %msg-channel-open-failure 92) (def %msg-channel-window-adjust 93)
(def %msg-channel-data 94) (def %msg-channel-extended-data 95)
(def %msg-channel-eof 96) (def %msg-channel-close 97)
(def %msg-channel-request 98) (def %msg-channel-success 99) (def %msg-channel-failure 100)

(def %window 2097152)
(def %max-packet 32768)
(def %chunk 16384)

(def %send
  (fn (_ c out)
    (def r (ssh-out-run out))
    (ssh-send-packet! c (first r) (rest r))
    (%oset! %clock %SENT (Sys now))))

(def %packet-of
  (fn (_ type)
    (def out (ssh-out))
    (ssh-put-byte out type)
    out))

(def %bytes
  (fn (_ s start n)
    ((fn (self i acc) (if (< i start) acc (self (- i 1) (pair (%byte s i) acc))))
     (- (+ start n) 1) ())))

; --- the settings ----------------------------------------------------------

; What sshd_config may say that this server does not do: refused unless
; given the value that leaves it off, since each would let in someone the
; configuration means to keep out.
(def %refused
  (list (pair "allowusers" "") (pair "denyusers" "") (pair "allowgroups" "") (pair "denygroups" "")
        (pair "match" "") (pair "forcecommand" "none") (pair "chrootdirectory" "none")
        (pair "authenticationmethods" "any") (pair "permitopen" "any") (pair "permitlisten" "any")
        (pair "authorizedkeyscommand" "none") (pair "authorizedprincipalsfile" "none")
        (pair "authorizedprincipalscommand" "none") (pair "trustedusercakeys" "none") (pair "revokedkeys" "none")
        (pair "refuseconnection" "no") (pair "setenv" "none")))

(def %line (fn (_ lines kw) (List find (fn (_ l) (str=? (first l) kw)) lines)))
(def %bad (fn (_ l what) (Err raise 'value (Str8 append (List ref 2 l) ": " what) ())))
(def %arg (fn (_ l) (if (null? (first (rest l))) "" (first (first (rest l))))))
(def %one (fn (_ lines kw default) (def l (%line lines kw)) (if (null? l) default (%arg l))))

(def %choice
  (fn (_ lines kw choices default)
    (def l (%line lines kw))
    (if (null? l) default
      (do (def v (Str8 downcase (%arg l)))
          (if (List any? (fn (_ c) (str=? c v)) choices) v
            (%bad l (Str8 append "unsupported option \"" v "\".")))))))

(def %yes? (fn (_ lines kw default) (str=? (%choice lines kw (list "yes" "no") (if default "yes" "no")) "yes")))

; A decimal's value, or () when the text is not all digits.
(def %int-or-nil
  (fn (_ t)
    (def n (Str8 length t))
    (if (if (> n 0) ((fn (self i) (if (= i n) #t (if (if (>= (%byte-ref t i) #\0) (<= (%byte-ref t i) #\9) #f) (self (+ i 1)) #f))) 0) #f)
      (%cvt t (Type named INTEGER) 10)
      ())))

(def %port
  (fn (_ l text)
    ((fn (_ n) (if (if (null? n) #t (if (< n 1) #t (> n 65535))) (%bad l "Badly formatted port number.") n)) (%int-or-nil text))))

(def %count
  (fn (_ lines kw default)
    (def l (%line lines kw))
    (if (null? l) default ((fn (_ n) (if (null? n) (%bad l "invalid number.") n)) (%int-or-nil (%arg l))))))

(def %seconds
  (fn (_ lines kw default)
    (def l (%line lines kw))
    (if (null? l) default ((fn (_ n) (if (null? n) (%bad l "invalid time value.") n)) (ssh-config-time (%arg l))))))

; ChannelTimeout's global time, in seconds, 0 for none.
(def %channel-timeout
  (fn (_ lines)
    (def l (%line lines "channeltimeout"))
    (if (if (null? l) #t (str=? (Str8 downcase (%arg l)) "none")) 0
      (List fold
        (fn (_ acc a)
          (def eq (Str8 index-of "=" a))
          (def t (if (null? eq) () (ssh-config-time (Str8 sub (+ eq 1) (- (Str8 length a) eq 1) a))))
          (match
            ((null? t) (%bad l (Str8 append "invalid channel timeout " a)))
            ((str=? (Str8 sub 0 eq a) "global") t)
            (#t (%bad l (Str8 append "the channel timeout " a " is not served; global= is")))))
        0 (first (rest l))))))

; An algorithm list that would leave out the one served is refused: a
; plain list must name it, a `-` list must not; `+` and `^` lists only add.
(def %algorithms
  (fn (_ lines kw ours)
    (def l (%line lines kw))
    (unless (null? l)
      (do (def v (%arg l))
          (def c (if (> (Str8 length v) 0) (Str8 sub 0 1 v) ""))
          (def names (Str8 split "," (if (List any? (fn (_ p) (str=? p c)) (list "+" "-" "^")) (Str8 sub 1 (- (Str8 length v) 1) v) v)))
          (def named (List any? (fn (_ n) (ssh-config-patterns? (list n) ours)) names))
          (when (if (str=? c "-") named (if (if (str=? c "+") #f (not (str=? c "^"))) (not named) #f))
            (%bad l (Str8 append kw " leaves out " ours ", the one served")))))))

; An algorithm list as a filter of ours: a plain list keeps what it
; names, a `-` list drops what it names, `+` and `^` lists keep them all;
; one that would keep none is refused.
(def %algorithm-list
  (fn (_ lines kw ours)
    (def l (%line lines kw))
    (if (null? l) ours
      (do (def v (%arg l))
          (def c (if (> (Str8 length v) 0) (Str8 sub 0 1 v) ""))
          (def names (Str8 split "," (if (List any? (fn (_ p) (str=? p c)) (list "+" "-" "^")) (Str8 sub 1 (- (Str8 length v) 1) v) v)))
          (def named? (fn (_ a) (List any? (fn (_ n) (ssh-config-patterns? (list n) a)) names)))
          (def kept (match ((str=? c "-") (List filter (fn (_ a) (not (named? a))) ours))
                           ((if (str=? c "+") #t (str=? c "^")) ours)
                           (#t (List filter named? ours))))
          (when (null? kept) (%bad l (Str8 append kw " leaves out every algorithm served")))
          kept))))

; A ListenAddress as (ADDRESS . PORT), PORT () when it names none:
; host, host:port, [host]:port; 0.0.0.0 or :: is every address, ().
(def %listen
  (fn (_ l)
    (def a (%arg l))
    (def n (Str8 length a))
    (def close (Str8 index-of "]" a))
    (def colons (List length (List filter (fn (_ i) (= (%byte-ref a i) #\:)) (List range 0 n))))
    (def split
      (match
        ((if (> n 0) (= (%byte-ref a 0) #\[) #f)
          (if (null? close) (%bad l "invalid ListenAddress")
            (pair (Str8 sub 1 (- close 1) a)
                  (if (< (+ close 1) n) (%port l (Str8 sub (+ close 2) (- n close 2) a)) ()))))
        ((= colons 1) (do (def i (Str8 index-of ":" a)) (pair (Str8 sub 0 i a) (%port l (Str8 sub (+ i 1) (- n i 1) a)))))
        (#t (pair a ()))))
    (def addr (first split))
    (pair (if (if (str=? addr "0.0.0.0") #t (if (str=? addr "::") #t (str=? addr "*"))) () addr) (rest split))))

; The settings in force, from the lines in order: an alist.  Command-line
; Port lines, from -p or -o, stand in place of the file's.  Raises a
; label 'value Err whose message is OpenSSH's for a value it refuses.
(def ssh-server-settings
  (fn (_ lines)
    (def port-lines (List filter (fn (_ l) (str=? (first l) "port")) lines))
    (def from-command-line (List filter (fn (_ l) (%prefix? "command-line" (List ref 2 l))) port-lines))
    (def ports (List map (fn (_ l) (%port l (%arg l))) (if (null? from-command-line) port-lines from-command-line)))
    (def ports* (if (null? ports) (list 22) ports))
    (def listens (List map %listen (List filter (fn (_ l) (str=? (first l) "listenaddress")) lines)))
    (def keys (List flat-map (fn (_ a) a) (ssh-config-all lines "hostkey")))
    (def akf (ssh-config-first lines "authorizedkeysfile"))
    (%algorithms lines "ciphers" "chacha20-poly1305@openssh.com")
    (%algorithms lines "kexalgorithms" "curve25519-sha256")
    (list (pair (lit ports) ports*)
          (pair (lit listen)
            (if (null? listens) (List map (fn (_ p) (pair () p)) ports*)
              (List flat-map (fn (_ a) (if (null? (rest a)) (List map (fn (_ p) (pair (first a) p)) ports*) (list a))) listens)))
          (pair (lit hostkeys) (if (null? keys) (list "/etc/ssh/ssh_host_rsa_key" "/etc/ssh/ssh_host_ecdsa_key" "/etc/ssh/ssh_host_ed25519_key") keys))
          (pair (lit hostkeys-given) (not (null? keys)))
          (pair (lit pidfile) ((fn (_ p) (if (str=? (Str8 downcase p) "none") () p)) (%one lines "pidfile" "/var/run/sshd.pid")))
          (pair (lit authorized) (if (null? akf) (list ".ssh/authorized_keys" ".ssh/authorized_keys2")
                                   (if (if (= (List length akf) 1) (str=? (Str8 downcase (first akf)) "none") #f) () akf)))
          (pair (lit password) (%yes? lines "passwordauthentication" #t))
          (pair (lit pubkey) (%yes? lines "pubkeyauthentication" #t))
          (pair (lit hostkey-algs) (%algorithm-list lines "hostkeyalgorithms"
                                     (list "ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "rsa-sha2-512" "rsa-sha2-256")))
          (pair (lit pubkey-algs) (%algorithm-list lines "pubkeyacceptedalgorithms"
                                    (list "ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "rsa-sha2-512" "rsa-sha2-256")))
          (pair (lit empty) (%yes? lines "permitemptypasswords" #f))
          (pair (lit root) ((fn (_ v) (if (str=? v "without-password") "prohibit-password" v))
                             (%choice lines "permitrootlogin" (list "yes" "no" "prohibit-password" "without-password" "forced-commands-only") "prohibit-password")))
          (pair (lit tcp) ((fn (_ v) (if (%yes? lines "disableforwarding" #f) "no" (if (str=? v "yes") "all" v)))
                            (%choice lines "allowtcpforwarding" (list "yes" "all" "no" "local" "remote") "yes")))
          (pair (lit gateway) (%choice lines "gatewayports" (list "no" "yes" "clientspecified") "no"))
          (pair (lit limits) (list (%seconds lines "clientaliveinterval" 0) (%count lines "clientalivecountmax" 3) (%channel-timeout lines)))
          (pair (lit facility) (%choice lines "syslogfacility"
                                 (list "daemon" "user" "auth" "authpriv" "local0" "local1" "local2" "local3" "local4" "local5" "local6" "local7") "auth"))
          (pair (lit level) (%choice lines "loglevel" (list "quiet" "fatal" "error" "info" "verbose" "debug" "debug1" "debug2" "debug3") "info"))
          (pair (lit tries) (%count lines "maxauthtries" 6))
          (pair (lit accept) (List flat-map (fn (_ a) a) (ssh-config-all lines "acceptenv"))))))

; The settings as -T prints them, a keyword and its value a line.
(def %print
  (fn (_ s)
    (def yn (fn (_ b) (if b "yes" "no")))
    (def limits (%get s (lit limits)))
    (Str8 join ""
      (List map (fn (_ l) (Str8 append l "\n"))
        (List append
          (List map (fn (_ p) (Str8 append "port " (%num p))) (%get s (lit ports)))
          (List map (fn (_ a) (Str8 append "listenaddress " (if (null? (first a)) "0.0.0.0" (first a)) ":" (%num (rest a)))) (%get s (lit listen)))
          (List map (fn (_ k) (Str8 append "hostkey " k)) (%get s (lit hostkeys)))
          (list (Str8 append "pidfile " (if (null? (%get s (lit pidfile))) "none" (%get s (lit pidfile))))
                (Str8 append "authorizedkeysfile " (if (null? (%get s (lit authorized))) "none" (Str8 join " " (%get s (lit authorized)))))
                (Str8 append "passwordauthentication " (yn (%get s (lit password))))
                (Str8 append "pubkeyauthentication " (yn (%get s (lit pubkey))))
                (Str8 append "pubkeyacceptedalgorithms " (Str8 join "," (%get s (lit pubkey-algs))))
                (Str8 append "hostkeyalgorithms " (Str8 join "," (%get s (lit hostkey-algs))))
                (Str8 append "permitemptypasswords " (yn (%get s (lit empty))))
                (Str8 append "permitrootlogin " (%get s (lit root)))
                (Str8 append "allowtcpforwarding " (if (str=? (%get s (lit tcp)) "all") "yes" (%get s (lit tcp))))
                (Str8 append "gatewayports " (%get s (lit gateway)))
                (Str8 append "clientaliveinterval " (%num (first limits)))
                (Str8 append "clientalivecountmax " (%num (List ref 1 limits)))
                (Str8 append "channeltimeout " (if (= (List ref 2 limits) 0) "none" (Str8 append "global=" (%num (List ref 2 limits)))))
                (Str8 append "syslogfacility " (Str8 upcase (%get s (lit facility))))
                (Str8 append "loglevel " (Str8 upcase (%get s (lit level))))
                (Str8 append "maxauthtries " (%num (%get s (lit tries)))))
          (List map (fn (_ e) (Str8 append "acceptenv " e)) (%get s (lit accept))))))))

; --- authorized_keys --------------------------------------------------------

; The files AuthorizedKeysFile names for a user: %h the home directory,
; %u the user, %% a percent; a relative one under the home directory.
(def %key-files
  (fn (_ names user home)
    (List map
      (fn (_ n)
        (def e (Str8 join "%" (List map (fn (_ part) (Str8 join user (Str8 split "%u" (Str8 join home (Str8 split "%h" part)))))
                                (Str8 split "%%" n))))
        (if (if (> (Str8 length e) 0) (= (%byte-ref e 0) #\/) #f) e (Str8 append home "/" e)))
      names)))

; The keys of the files, options or not, of every type served, as (TYPE
; . BASE64).
(def %authorized
  (fn (_ paths)
    (def types (list "ssh-ed25519" "ssh-rsa" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521"))
    (List flat-map
      (fn (_ path)
        (def text (guard (e ()) (File read-all path)))
        (if (null? text) ()
          (List flat-map
            (fn (_ line)
              (def ws (List filter (fn (_ w) (> (Str8 length w) 0))
                        (Str8 split " " (Str8 join " " (Str8 split "\t" line)))))
              ; the key follows its type, wherever options put the type
              (def at ((fn (self ws) (if (null? ws) () (if (List any? (fn (_ t) (str=? t (first ws))) types) ws (self (rest ws))))) ws))
              (if (if (null? at) #t (null? (rest at))) () (list (pair (first at) (first (rest at))))))
            (Str8 split "\n" text))))
      paths)))

; --- authentication (RFC 4252): publickey, Ed25519, RSA or ECDSA, and password

; The methods a failure offers.
(def %failure
  (fn (_ c s)
    (def f (%packet-of ssh-msg-userauth-failure))
    (ssh-put-names f (List append (if (%get s (lit pubkey)) (list "publickey") ())
                                  (if (%get s (lit password)) (list "password") ())))
    (ssh-put-bool f #f)
    (%send c f)))

; A colon-separated file's line for name, as its fields, or ().
(def %entry
  (fn (_ path name)
    (def text (guard (e ()) (File read-all path)))
    (if (null? text) ()
      (List find (fn (_ fs) (if (null? fs) #f (str=? (first fs) name)))
        (List map (fn (_ l) (Str8 split ":" l)) (Str8 split "\n" text))))))

; The user this server runs as: USER, or the passwd entry of its uid.
(def %me
  (fn (_)
    (def u (Sys getenv "USER"))
    (if (if (null? u) #f (> (Str8 length u) 0)) u
      ((fn (_ e) (if (null? e) "" (first e)))
        (List find (fn (_ fs) (if (> (List length fs) 2) (str=? (List ref 2 fs) (%num (Sys getuid))) #f))
          (List map (fn (_ l) (Str8 split ":" l))
            (Str8 split "\n" (guard (e "") (File read-all "/etc/passwd")))))))))

; A user's home directory: the passwd entry's, or HOME.
(def %home
  (fn (_ user)
    (def pw (%entry "/etc/passwd" user))
    (if (> (List length pw) 5) (List ref 5 pw) (Sys getenv "HOME"))))

; A user's password hash: the passwd entry's, or the shadow entry's when
; that is "x"; () when there is none.
(def %hash-of
  (fn (_ user)
    (def pw (%entry "/etc/passwd" user))
    (def h (if (< (List length pw) 2) () (List ref 1 pw)))
    (if (if (null? h) #f (str=? h "x"))
      ((fn (_ sh) (if (< (List length sh) 2) () (List ref 1 sh))) (%entry "/etc/shadow" user))
      h)))

(def %prefix?
  (fn (_ p s) (if (< (Str8 length s) (Str8 length p)) #f (str=? (Str8 sub 0 (Str8 length p) s) p))))

; crypt(3) of a password with a stored hash as its salt, through x-lang's
; Crypt: $1$, $5$, $6$ or traditional DES; () for a hash crypt refuses,
; a locked account's "!" or "*".
(def %crypt
  (fn (_ password stored)
    (def after (fn (_ n) (Str8 sub n (- (Str8 length stored) n) stored)))
    (match
      ((%prefix? "$1$" stored) (Crypt md5 password (after 3)))
      ((%prefix? "$5$" stored) (Crypt sha256 password (after 3)))
      ((%prefix? "$6$" stored) (Crypt sha512 password (after 3)))
      ((if (= (Str8 length stored) 13) (not (%prefix? "$" stored)) #f)
        (guard (e ()) (Crypt des password stored)))
      (#t ()))))

; A password request checked: no change asked, root let in only as
; PermitRootLogin yes allows, a hash there, not locked, not blank unless
; PermitEmptyPasswords, and the crypt equal.  Each refusal logged as
; OpenSSH logs it.
(def %password-ok
  (fn (_ in user from s)
    (def change (ssh-get-bool in))
    (def password (ssh-get-text in))
    (def stored (if change () (%hash-of user)))
    (def test (if (null? stored) () (%crypt password stored)))
    (def failed (fn (_) (%log (Str8 append "Failed password for " user " from " from " ssh2")) #f))
    (match
      ((if (str=? user "root") (not (str=? (%get s (lit root)) "yes")) #f)
        (do (%log (Str8 append "ROOT LOGIN REFUSED FROM " from)) (failed)))
      ((null? stored) (failed))
      ((null? test) (do (%log (Str8 append "User " user " not allowed because account is locked")) (failed)))
      ((if (= (Str8 length stored) 0) (not (%get s (lit empty))) #f) (failed))
      ((str=? test stored) (do (%log (Str8 append "Accepted password for " user " from " from " ssh2")) #t))
      (#t (failed)))))

; Requests answered until one succeeds, for the user this server runs as:
; a key in an authorized_keys file whose signature over the session id
; and the request checks, or the user's password.  A key request with no
; signature asks whether the key would do, and is answered PK_OK when it
; would.  MaxAuthTries failures disconnect.  Answers the user.
(def %authenticate
  (fn (_ c s from)
    (def sr (ssh-expect! c ssh-msg-service-request "SERVICE_REQUEST"))
    (def sin (ssh-in (first sr) 1 (- (rest sr) 1)))
    (unless (str=? (ssh-get-text sin) "ssh-userauth")
      (Err raise 'value "a service other than ssh-userauth asked for" ()))
    (def sa (%packet-of ssh-msg-service-accept))
    (ssh-put-text sa "ssh-userauth")
    (%send c sa)
    (def me (%me))
    (def keys (%authorized (%key-files (%get s (lit authorized)) me (%home me))))
    (def root-key? (if (str=? me "root") (List any? (fn (_ v) (str=? v (%get s (lit root)))) (list "yes" "prohibit-password")) #t))
    ((fn (self failures)
       (def fail
         (fn (_ user counted)
           (def n (if counted (+ failures 1) failures))
           (if (>= n (%get s (lit tries)))
             (do (%log-at "error" (Str8 append "maximum authentication attempts exceeded for " user " from " from " ssh2 [preauth]"))
                 (def d (%packet-of ssh-msg-disconnect))
                 (ssh-put-uint32 d 2)
                 (ssh-put-text d "Too many authentication failures")
                 (ssh-put-text d "")
                 (%send c d)
                 (Err raise 'io "too many authentication failures" ()))
             (do (%failure c s) (self n)))))
       (def p (ssh-expect! c ssh-msg-userauth-request "USERAUTH_REQUEST"))
       (def in (ssh-in (first p) 1 (- (rest p) 1)))
       (def user (ssh-get-text in))
       (def service (ssh-get-text in))
       (def method (ssh-get-text in))
       (match
         ((str=? method "none") (do (%failure c s) (self failures)))
         ((not (str=? user me))
           (do (%log (if (null? (%entry "/etc/passwd" user)) (Str8 append "Invalid user " user " from " from)
                       (Str8 append "User " user " from " from " not allowed because this server serves only " me)))
               (fail user #t)))
         ((if (%get s (lit password)) (str=? method "password") #f)
           (if (%password-ok in user from s)
             (do (%send c (%packet-of ssh-msg-userauth-success)) user)
             (fail user #t)))
         ((if (%get s (lit pubkey)) (str=? method "publickey") #f)
           (do (def signed? (ssh-get-bool in))
               (def alg (ssh-get-text in))
               (def blob (ssh-get-string in))
               (def b64 (Base64 encode-bytes (%bytes (ssh-in-buf in) (first blob) (rest blob))))
               ; the key, of any type served, offered with an algorithm it
               ; signs with and PubkeyAcceptedAlgorithms allows
               (def key (guard (e ()) (ssh-pubkey-of (ssh-in-buf in) (first blob) (rest blob))))
               (def known
                 (if (if root-key? (not (null? key)) #f)
                   (if (List any? (fn (_ a) (str=? a alg)) (ssh-pubkey-algorithms key))
                     (if (List any? (fn (_ a) (str=? a alg)) (%get s (lit pubkey-algs)))
                       (List any? (fn (_ k) (if (str=? (first k) (ssh-pubkey-type key)) (str=? (rest k) b64) #f)) keys)
                       #f)
                     #f)
                   #f))
               (match
                 ((not known) (fail user #t))
                 ((not signed?)
                   (do (def ok (%packet-of %msg-userauth-pk-ok))
                       (ssh-put-text ok alg)
                       (ssh-put-string ok (ssh-in-buf in) (first blob) (rest blob))
                       (%send c ok)
                       (self failures)))
                 (#t
                   (do (def sig (ssh-get-string in))
                       ; what was signed: the session id as a string, then the
                       ; request up to the signature's own length field
                       (def data (ssh-out))
                       (ssh-put-string data (ssh-session-id c) 0 32)
                       (ssh-put-bytes data (first p) 0 (- (first sig) 4))
                       (def msg (ssh-out-run data))
                       (def line (Str8 append " for " user " from " from " ssh2: " (ssh-pubkey-label key) " "
                                              (ssh-blob-fingerprint (ssh-pubkey-blob key))))
                       (if (ssh-pubkey-verify? key (list (first p) (first sig) (rest sig)) (list (first msg) 0 (rest msg)))
                         (do (%send c (%packet-of ssh-msg-userauth-success))
                             (%log (Str8 append "Accepted publickey" line))
                             user)
                         (do (%log (Str8 append "Failed publickey" line)) (fail user #t))))))))
         (#t (fail user #t))))
     0)))

; --- the command, on three pipes ------------------------------------------

; The command run in the user's shell, or the shell itself when command
; is (), in the user's home directory as OpenSSH's sessions start: on
; three pipes, (PID IN OUT ERR), IN the end we write, OUT and ERR the
; ends we read; or on the session's terminal, its master both IN and OUT
; and ERR (), the shell interactive since its input is a terminal, TERM
; and the window set as the client gave them.
(def %spawn
  (fn (_ command sock env pty term home)
    (def pipes (if (null? pty) (list (Sys pipe) (Sys pipe) (Sys pipe)) ()))
    (def pid (Sys fork))
    (when (= pid 0)
      (if (null? pty)
        (do (def i (first pipes)) (def o (List ref 1 pipes)) (def e (List ref 2 pipes))
            (Sys dup2 (first i) 0) (Sys dup2 (rest o) 1) (Sys dup2 (rest e) 2)
            (List for-each (fn (_ fd) (Sys close fd))
              (list (first i) (rest i) (first o) (rest o) (first e) (rest e))))
        (do (Sys close (first pty))
            (ssh-pty-attach! (rest pty) (List ref 1 term) (List ref 2 term))
            (Sys setenv "TERM" (first term))))
      (Sys close sock)
      (List for-each (fn (_ v) (Sys setenv (first v) (rest v))) env)
      (guard (e ()) (Sys chdir home))
      (def shell ((fn (_ s) (if (if (null? s) #t (= (Str8 length s) 0)) "/bin/sh" s)) (Sys getenv "SHELL")))
      (Sys exec shell (if (null? command) () (list "-c" command)))
      (Sys exit 127))
    (if (null? pty)
      (do (def i (first pipes)) (def o (List ref 1 pipes)) (def e (List ref 2 pipes))
          (Sys close (first i)) (Sys close (rest o)) (Sys close (rest e))
          (list pid (rest i) (first o) (first e)))
      (list pid (first pty) (first pty) ()))))

; --- the clocks ------------------------------------------------------------
;
; The clocks ClientAliveInterval and ChannelTimeout read, seconds since
; the epoch: 1 the last packet sent, 2 the last received, 3 the last
; carrying data either way, 4 the last keepalive asked.  A keepalive is
; asked after the interval without sending or receiving; the connection
; is given up after ClientAliveCountMax intervals without receiving
; anything; the global ChannelTimeout without data either way closes
; it.  One connection a process.
(def %SENT 1) (def %RECV 2) (def %DATA 3) (def %ASKED 4)
(def %clock (Vector make 4 0))

(def %clocks-start! (fn (_) (def now (Sys now)) (%oset! %clock %SENT now) (%oset! %clock %RECV now) (%oset! %clock %DATA now) (%oset! %clock %ASKED now)))

; A keepalive asked: OpenSSH's global request, wanting the answer that
; counts as the other end alive.
(def %keepalive!
  (fn (_ c)
    (def req (%packet-of ssh-msg-global-request))
    (ssh-put-text req "keepalive@openssh.com")
    (ssh-put-bool req #t)
    (%send c req)
    (%oset! %clock %ASKED (Sys now))))

; How long a wait may last before a clock wants looking at, in
; milliseconds, or -1 for no limit: limits is (INTERVAL COUNT IDLE), an
; interval or idle time of 0 for never.
(def %wait-ms
  (fn (_ limits)
    (def now (Sys now))
    (def k (first limits)) (def n (List ref 1 limits)) (def i (List ref 2 limits))
    (def dues
      (List append
        (if (> k 0) (list (- (+ (%oref %clock %SENT) k) now) (- (+ (%oref %clock %RECV) k) now)
                          (- (+ (%oref %clock %RECV) (* k n)) now)) ())
        (if (> i 0) (list (- (+ (%oref %clock %DATA) i) now)) ())))
    (if (null? dues) -1
      (do (def least (List fold (fn (_ a b) (if (< a b) a b)) (first dues) (rest dues)))
          (if (< least 0) 0 (* 1000 least))))))

; The clocks read: a keepalive asked when due, the connection given up
; or closed when a limit has passed; the error's message names which.
(def %clocks!
  (fn (_ c limits)
    (def now (Sys now))
    (def k (first limits)) (def n (List ref 1 limits)) (def i (List ref 2 limits))
    (when (> k 0)
      (do (when (>= (- now (%oref %clock %RECV)) (* k n))
            (Err raise 'io "keepalive" ()))
          (when (if (>= (- now (%oref %clock %SENT)) k) #t
                  (if (>= (- now (%oref %clock %RECV)) k) (>= (- now (%oref %clock %ASKED)) k) #f))
            (%keepalive! c))))
    (when (if (> i 0) (>= (- now (%oref %clock %DATA)) i) #f)
      (Err raise 'io "idle" ()))))

; --- the channels (RFC 4254) ---------------------------------------------------
;
; A channel's state, in a vector: 1 the client's channel number, () until
; the client has confirmed one we opened, 2 ours, 3 its window, 4 its
; largest packet, 5 its kind, session or forward, 6 a session's command
; as (PID IN OUT ERR) or (), 7 whether OUT and 8 whether ERR are still
; open (a forward's OUT: whether its connection is still read), 9 a
; forward's connection, 10 whether the client has closed the
; channel, 11 whether we have, 12 whether the client has sent EOF, 13 a
; session's terminal as (MASTER . SLAVE-PATH) or (), 14 its TERM and window
; as (TERM COLUMNS ROWS).
(def %PEER 1) (def %OURS 2) (def %WINDOW 3) (def %MAX 4) (def %KIND 5) (def %CHILD 6)
(def %OUT 7) (def %ERR 8) (def %FD 9) (def %PEER-CLOSED 10) (def %CLOSED 11) (def %PEER-EOF 12)
(def %PTY 13) (def %TERM 14)
(def %ch (fn (_ ch i) (%oref ch i)))
(def %ch! (fn (_ ch i v) (%oset! ch i v)))

; The connection's state: 1 the channels, 2 the next channel number, 3
; the bytes moved since the last collect, 4 whether a client's forwards
; are served, 5 the session channel or (), 6 whether a client's remote
; forwards are served, 7 GatewayPorts, as the settings spell it, 8 the
; listeners as (FD ADDRESS PORT), ADDRESS as the client asked, 9
; AcceptEnv's patterns, 10 the variables the client sent that they
; accept, as (NAME . VALUE).
(def %CHANNELS 1) (def %NEXT 2) (def %MOVED 3) (def %FORWARDING 4) (def %SESSION 5)
(def %REMOTE 6) (def %GATEWAY 7) (def %LISTENERS 8) (def %ACCEPT 9) (def %ENV 10)
(def %rn (fn (_ run i) (%oref run i)))
(def %rn! (fn (_ run i v) (%oset! run i v)))
(def %min (fn (_ a b) (if (< a b) a b)))

(def %moved! (fn (_ run n) (%rn! run %MOVED (+ (%rn run %MOVED) n))))

; A channel added to the table, numbered next.
(def %channel!
  (fn (_ run kind peer window max)
    (def ch (Vector make 14 ()))
    (%ch! ch %PEER peer) (%ch! ch %OURS (%rn run %NEXT))
    (%rn! run %NEXT (+ (%rn run %NEXT) 1))
    (%ch! ch %WINDOW window) (%ch! ch %MAX max) (%ch! ch %KIND kind)
    (%ch! ch %OUT (eq? kind (lit forward))) (%ch! ch %ERR #f) (%ch! ch %PEER-CLOSED #f) (%ch! ch %CLOSED #f)
    (%ch! ch %PEER-EOF #f)
    (%rn! run %CHANNELS (List append (%rn run %CHANNELS) (list ch)))
    ch))

(def %find
  (fn (_ run ours)
    (List find (fn (_ ch) (= (%ch ch %OURS) ours)) (%rn run %CHANNELS))))

(def %drop!
  (fn (_ run ch)
    (%rn! run %CHANNELS (List filter (fn (_ x) (not (= (%ch x %OURS) (%ch ch %OURS)))) (%rn run %CHANNELS)))))

(def %forwards
  (fn (_ run) (List filter (fn (_ ch) (eq? (%ch ch %KIND) (lit forward))) (%rn run %CHANNELS))))

(def %reply
  (fn (_ c ch want-reply ok)
    (when want-reply
      (do (def r (%packet-of (if ok %msg-channel-success %msg-channel-failure)))
          (ssh-put-uint32 r (%ch ch %PEER))
          (%send c r)))))

; An open answered: confirmation with our number, or a failure with
; RFC 4254's reason code and a text.
(def %confirm!
  (fn (_ c ch)
    (def ok (%packet-of %msg-channel-open-confirmation))
    (ssh-put-uint32 ok (%ch ch %PEER))
    (ssh-put-uint32 ok (%ch ch %OURS))
    (ssh-put-uint32 ok %window)
    (ssh-put-uint32 ok %max-packet)
    (%send c ok)))

(def %refuse!
  (fn (_ c sender code text)
    (def no (%packet-of %msg-channel-open-failure))
    (ssh-put-uint32 no sender)
    (ssh-put-uint32 no code)
    (ssh-put-text no text)
    (ssh-put-text no "")
    (%send c no)))

; A dotted address for a name: what the resolver says, or the name when
; it already is one.
(def %address
  (fn (_ host)
    (def r (Socket resolve host))
    (if (null? r) host (if (pair? r) (first r) r))))

; A channel opened: one session a connection, its command to come by
; request; or, forwarding allowed, a direct-tcpip channel whose host and
; port are connected, the connection the channel's two ways.
(def %open!
  (fn (_ c run in)
    (def type (ssh-get-text in))
    (def sender (ssh-get-uint32 in))
    (def window (ssh-get-uint32 in))
    (def max (ssh-get-uint32 in))
    (match
      ((str=? type "session")
        (if (null? (%rn run %SESSION))
          (do (def ch (%channel! run (lit session) sender window max))
              (%rn! run %SESSION ch)
              (%confirm! c ch))
          (%refuse! c sender 1 "only one session channel is served")))
      ((str=? type "direct-tcpip")
        (do (def host (ssh-get-text in))
            (def port (ssh-get-uint32 in))
            (def fd (if (%rn run %FORWARDING) (guard (e ()) (Socket tcp-connect (%address host) port)) ()))
            (match
              ((not (%rn run %FORWARDING)) (%refuse! c sender 1 "port forwarding is disabled"))
              ((null? fd) (%refuse! c sender 2 (Str8 append "connect to " host ":" (%num port) " failed")))
              (#t (do (def ch (%channel! run (lit forward) sender window max))
                      (%ch! ch %FD fd)
                      (%debug (Str8 append "forward to " host ":" (%num port)))
                      (%confirm! c ch))))))
      (#t (%refuse! c sender 3 (Str8 append "channel type not served: " type))))))

; A global request from the client answered: tcpip-forward listens for
; a remote forward where GatewayPorts says: localhost under no, every
; interface under yes, under clientspecified the address the client asked,
; "" or * every one; cancel-tcpip-forward closes that listener; nothing
; else is served.
(def %global!
  (fn (_ c run in)
    (def name (ssh-get-text in))
    (def want-reply (ssh-get-bool in))
    (def ok
      (match
        ((str=? name "tcpip-forward")
          (do (def address (ssh-get-text in))
              (def port (ssh-get-uint32 in))
              (def gateway (%rn run %GATEWAY))
              (def bind (match ((str=? gateway "no") "127.0.0.1")
                               ((str=? gateway "yes") ())
                               ((if (str=? address "") #t (str=? address "*")) ())
                               ((str=? address "localhost") "127.0.0.1")
                               (#t (%address address))))
              (def fd (if (if (%rn run %REMOTE) (> port 0) #f)
                        (guard (e ()) (if (null? bind) (Socket tcp-listen port) (Socket tcp-listen-on bind port)))
                        ()))
              (unless (null? fd)
                (do (%debug (Str8 append "remote forward on " address ":" (%num port)))
                    (%rn! run %LISTENERS (List append (%rn run %LISTENERS) (list (list fd address port))))))
              (not (null? fd))))
        ((str=? name "cancel-tcpip-forward")
          (do (def address (ssh-get-text in))
              (def port (ssh-get-uint32 in))
              (def gone (List filter (fn (_ l) (= (List ref 2 l) port)) (%rn run %LISTENERS)))
              (List for-each (fn (_ l) (guard (e ()) (Socket close (first l)))) gone)
              (%rn! run %LISTENERS (List filter (fn (_ l) (not (= (List ref 2 l) port))) (%rn run %LISTENERS)))
              (not (null? gone))))
        (#t #f)))
    (when want-reply (%send c (%packet-of (if ok ssh-msg-request-success ssh-msg-request-failure))))))

; A connection accepted on a remote forward's listener opened to the
; client as a forwarded-tcpip channel, the connection its two ways; the
; client's confirmation sets its number and window.
(def %open-forwarded!
  (fn (_ c run fd address port)
    (def peer (Socket peer fd))
    (def ch (%channel! run (lit forward) () 0 32768))
    (%ch! ch %FD fd)
    (def open (%packet-of %msg-channel-open))
    (ssh-put-text open "forwarded-tcpip")
    (ssh-put-uint32 open (%ch ch %OURS))
    (ssh-put-uint32 open %window)
    (ssh-put-uint32 open %max-packet)
    (ssh-put-text open address)
    (ssh-put-uint32 open port)
    (ssh-put-text open (first peer))
    (ssh-put-uint32 open (rest peer))
    (%send c open)))

; One read of a session's output or error, or of a forward's connection,
; sent as the channel's data; a read of nothing is its end: a session's
; pipe closes, a forward's far end has no more, so EOF goes, and CLOSE
; once the client's EOF has come too: a half-close is only EOF.
(def %pump!
  (fn (_ c run ch fd slot extended)
    (def n (%min %chunk (%min (%ch ch %WINDOW) (- (%ch ch %MAX) 64))))
    (def buf (%make-str n))
    (def got (File read fd buf n))
    (if (< got 1)
      (if (eq? (%ch ch %KIND) (lit session))
        (do (Sys close fd) (%ch! ch slot #f))
        (do (def eof (%packet-of %msg-channel-eof))
            (ssh-put-uint32 eof (%ch ch %PEER))
            (%send c eof)
            (%ch! ch %OUT #f)
            (when (%ch ch %PEER-EOF) (%close! c ch))))
      (do (def d (%packet-of (if extended %msg-channel-extended-data %msg-channel-data)))
          (ssh-put-uint32 d (%ch ch %PEER))
          (when extended (ssh-put-uint32 d 1))
          (ssh-put-string d buf 0 got)
          (%send c d)
          (%oset! %clock %DATA (Sys now))
          (%ch! ch %WINDOW (- (%ch ch %WINDOW) got))
          (%moved! run got)))))

; Our CLOSE of a channel, once.
(def %close!
  (fn (_ c ch)
    (unless (%ch ch %CLOSED)
      (do (def cl (%packet-of %msg-channel-close))
          (ssh-put-uint32 cl (%ch ch %PEER))
          (%send c cl)
          (%ch! ch %CLOSED #t)))))

; The command finished: its status sent, then EOF and CLOSE.
(def %finish!
  (fn (_ c ch)
    (def status (Sys wait (first (%ch ch %CHILD))))
    (def r (%packet-of %msg-channel-request))
    (ssh-put-uint32 r (%ch ch %PEER))
    (ssh-put-text r "exit-status")
    (ssh-put-bool r #f)
    (ssh-put-uint32 r status)
    (%send c r)
    (def eof (%packet-of %msg-channel-eof))
    (ssh-put-uint32 eof (%ch ch %PEER))
    (%send c eof)
    (%close! c ch)
    status))

; One packet from the client handled: a channel message is for the
; channel it names, ours.
(def %handle!
  (fn (_ c run sock)
    (def p (ssh-next-packet! c))
    (%oset! %clock %RECV (Sys now))
    (def t (%byte (first p) 0))
    (when (if (= t %msg-channel-data) #t (= t %msg-channel-extended-data)) (%oset! %clock %DATA (Sys now)))
    (def in (ssh-in (first p) 1 (- (rest p) 1)))
    (def ch (if (if (>= t %msg-channel-open-confirmation) (<= t %msg-channel-failure) #f)
              (%find run (ssh-get-uint32 in))
              ()))
    (match
      ((= t ssh-msg-global-request) (%global! c run in))
      ((= t %msg-channel-open) (%open! c run in))
      ((null? ch) ())
      ((= t %msg-channel-open-confirmation)
        (do (%ch! ch %PEER (ssh-get-uint32 in))
            (%ch! ch %WINDOW (ssh-get-uint32 in))
            (%ch! ch %MAX (ssh-get-uint32 in))))
      ((= t %msg-channel-open-failure)
        (do (ssh-get-uint32 in)
            (%debug (Str8 append "the client refused a forwarded connection: " (ssh-get-text in)))
            (guard (e ()) (Socket close (%ch ch %FD)))
            (%drop! run ch)))
      ((= t %msg-channel-request)
        (do (def name (ssh-get-text in))
            (def want-reply (ssh-get-bool in))
            (def fresh (if (eq? (%ch ch %KIND) (lit session)) (null? (%ch ch %CHILD)) #f))
            (def start!
              (fn (_ command)
                (def pty (%ch ch %PTY))
                (%ch! ch %CHILD (%spawn command sock (%rn run %ENV) pty (%ch ch %TERM) (%home (%me))))
                (%ch! ch %OUT #t) (%ch! ch %ERR (null? pty))
                (%reply c ch want-reply #t)))
            (match
              ((if fresh (str=? name "exec") #f)
                (do (def command (ssh-get-text in))
                    (%debug (Str8 append "exec: " command))
                    (start! command)))
              ((if fresh (str=? name "shell") #f)
                (do (%debug (if (null? (%ch ch %PTY)) "shell" (Str8 append "shell on " (rest (%ch ch %PTY)))))
                    (start! ())))
              ; a terminal for the session (RFC 4254 6.2): TERM, the window
              ; in characters, then in pixels, and the modes, which are
              ; the terminal's own defaults here
              ((if fresh (if (str=? name "pty-req") (null? (%ch ch %PTY)) #f) #f)
                (do (def term (ssh-get-text in))
                    (def cols (ssh-get-uint32 in))
                    (def rows (ssh-get-uint32 in))
                    (def pty (ssh-pty-open))
                    (unless (null? pty)
                      (do (%ch! ch %PTY pty)
                          (%ch! ch %TERM (list term cols rows))))
                    (%debug (if (null? pty) "pty-req refused: no pseudo-terminal" (Str8 append "pty-req " term " on " (rest pty))))
                    (%reply c ch want-reply (not (null? pty)))))
              ((str=? name "window-change")
                (do (def cols (ssh-get-uint32 in))
                    (def rows (ssh-get-uint32 in))
                    (unless (null? (%ch ch %PTY)) (ssh-pty-window! (first (%ch ch %PTY)) cols rows))
                    (%reply c ch want-reply (not (null? (%ch ch %PTY))))))
              ; a variable kept for the command when AcceptEnv's
              ; patterns take its name
              ((if fresh (str=? name "env") #f)
                (do (def var (ssh-get-text in))
                    (def value (ssh-get-text in))
                    (def ok (ssh-config-patterns? (%rn run %ACCEPT) var))
                    (when ok (%rn! run %ENV (List append (%rn run %ENV) (list (pair var value)))))
                    (%reply c ch want-reply ok)))
              (#t (%reply c ch want-reply #f)))))
      ((= t %msg-channel-window-adjust)
        (%ch! ch %WINDOW (+ (%ch ch %WINDOW) (ssh-get-uint32 in))))
      ((= t %msg-channel-data)
        (do (def r (ssh-get-string in))
            (def bytes (ssh-copy (ssh-in-buf in) (first r) (rest r)))
            (if (eq? (%ch ch %KIND) (lit session))
              (unless (null? (%ch ch %CHILD)) (File write (List ref 1 (%ch ch %CHILD)) bytes (rest r)))
              (guard (e ()) (Socket send-run (%ch ch %FD) bytes (rest r))))
            (def adj (%packet-of %msg-channel-window-adjust))
            (ssh-put-uint32 adj (%ch ch %PEER))
            (ssh-put-uint32 adj (rest r))
            (%send c adj)
            (%moved! run (rest r))))
      ((= t %msg-channel-eof)
        ; a session's input ends with its pipe closed; a terminal's is
        ; left open, as OpenSSH leaves it: closing the master would end the
        ; session under the shell
        (if (eq? (%ch ch %KIND) (lit session))
          (unless (if (null? (%ch ch %CHILD)) #t (not (null? (%ch ch %PTY)))) (Sys close (List ref 1 (%ch ch %CHILD))))
          (do (guard (e ()) (Socket shutdown (%ch ch %FD) (lit write)))
              (%ch! ch %PEER-EOF #t)
              (unless (%ch ch %OUT) (%close! c ch)))))
      ((= t %msg-channel-close)
        (do (%ch! ch %PEER-CLOSED #t)
            (when (eq? (%ch ch %KIND) (lit forward))
              (do (%close! c ch)
                  (guard (e ()) (Socket close (%ch ch %FD)))
                  (%drop! run ch)))))
      (#t ()))))

(def %ready?
  (fn (_ ready fd)
    (List any? (fn (_ r) (if (= (first r) fd) (not (null? (rest r))) #f)) ready)))

; The connection's channels served: until the session channel has
; closed both ways and no forward remains, or, with no session opened,
; until the connection ends, under the settings s: AllowTcpForwarding,
; GatewayPorts, AcceptEnv and the clocks.
(def %serve-session
  (fn (_ c sock s)
    (def run (Vector make 10 ()))
    (def tcp (%get s (lit tcp)))
    (def limits (%get s (lit limits)))
    (%clocks-start!)
    (%rn! run %CHANNELS ()) (%rn! run %NEXT 0) (%rn! run %MOVED 0)
    (%rn! run %FORWARDING (if (str=? tcp "all") #t (str=? tcp "local"))) (%rn! run %SESSION ())
    (%rn! run %REMOTE (if (str=? tcp "all") #t (str=? tcp "remote"))) (%rn! run %GATEWAY (%get s (lit gateway)))
    (%rn! run %LISTENERS ()) (%rn! run %ACCEPT (%get s (lit accept))) (%rn! run %ENV ())
    ((fn (self)
       (def session (%rn run %SESSION))
       (unless (if (null? session) #f
                 (if (%ch session %PEER-CLOSED) (if (%ch session %CLOSED) (null? (%forwards run)) #f) #f))
         (do (def child (if (null? session) () (%ch session %CHILD)))
             (def room (if (null? session) #f (> (%ch session %WINDOW) 0)))
             (def out (if (if room (%ch session %OUT) #f) (List ref 2 child) ()))
             (def err (if (if room (%ch session %ERR) #f) (List ref 3 child) ()))
             (def open-forwards
               (List filter (fn (_ ch) (if (null? (%ch ch %PEER)) #f (if (%ch ch %CLOSED) #f (if (%ch ch %OUT) (> (%ch ch %WINDOW) 0) #f))))
                 (%forwards run)))
             (if (ssh-pending? c)
               (%handle! c run sock)
               (do (def ready
                     (Sys poll (List append (list (pair sock (list (lit in))))
                                            (if (null? out) () (list (pair out (list (lit in)))))
                                            (if (null? err) () (list (pair err (list (lit in)))))
                                            (List map (fn (_ l) (pair (first l) (list (lit in)))) (%rn run %LISTENERS))
                                            (List map (fn (_ ch) (pair (%ch ch %FD) (list (lit in)))) open-forwards))
                               (%wait-ms limits)))
                   (when (if (null? out) #f (%ready? ready out)) (%pump! c run session out %OUT #f))
                   (when (if (null? err) #f (%ready? ready err)) (%pump! c run session err %ERR #t))
                   (List for-each
                     (fn (_ l) (when (%ready? ready (first l))
                                 (%open-forwarded! c run (Socket accept (first l)) (List ref 1 l) (List ref 2 l))))
                     (%rn run %LISTENERS))
                   (List for-each
                     (fn (_ ch) (when (%ready? ready (%ch ch %FD)) (%pump! c run ch (%ch ch %FD) %FD #f)))
                     open-forwards)
                   (when (%ready? ready sock) (%handle! c run sock))
                   (%clocks! c limits)))
             (when (if (null? child) #f
                     (if (%ch session %CLOSED) #f (if (%ch session %OUT) #f (not (%ch session %ERR)))))
               (%debug (Str8 append "exit status " (%num (%finish! c session)))))
             (when (> (%rn run %MOVED) %chunk) (do (Heap collect) (%rn! run %MOVED 0)))
             (self)))))))

; --- the listener ----------------------------------------------------------

; The host keys: every HostKey file that reads as a key of a type served,
; as ssh/pubkey's identities, one a type, the first of each kept.  A
; named file that does not read is logged; the default names are passed
; over when absent.  A key sealed under a passphrase is opened with none,
; as OpenSSH's sshd opens it, and so refused, in its words.
(def %host-keys
  (fn (_ s)
    (List fold
      (fn (_ acc path)
        (def id (guard (e (do (when (str=? (guard (e2 "") (e msg)) ssh-key-wrong-passphrase)
                                (%log-at "error" (Str8 append "Unable to load host key \"" path "\": " ssh-key-wrong-passphrase)))
                              ()))
                  (ssh-identity-read-file path "")))
        (when (if (null? id) (if (%get s (lit hostkeys-given)) #t (File exists? path)) #f)
          (%log-at "error" (Str8 append "Unable to load host key: " path)))
        (if (if (null? id) #t (List any? (fn (_ k) (str=? (ssh-pubkey-type (ssh-identity-pubkey k)) (ssh-pubkey-type (ssh-identity-pubkey id)))) acc))
          acc
          (List append acc (list id))))
      () (%get s (lit hostkeys)))))

(def %dlopen (prim-ref (lit ffi) (lit dlopen)))
(def %dlsym (prim-ref (lit ffi) (lit dlsym)))
(def %ptr-call (prim-ref (lit ptr) (lit call)))

; setsid(2) through libc: the platform's Darwin syscall table has no
; number for it, and Sys has no door.
(def %setsid! (fn (_) (%ptr-call (%dlsym (%dlopen () 1) "setsid"))))

; Into the background as daemon(3) has it: the parent exits 0, the child
; leads a session of its own and works in /.
(def %background!
  (fn (_)
    (unless (= (Sys fork) 0) (Sys exit 0))
    (%setsid!)
    (Sys chdir "/")))

; The standard descriptors on /dev/null, as a daemon's are.
(def %quiet!
  (fn (_)
    (def null (File open "/dev/null" (lit rdwr)))
    (unless (< null 0)
      (do (Sys dup2 null 0) (Sys dup2 null 1) (Sys dup2 null 2)
          (when (> null 2) (File close null))))))

; The pid written to the PidFile; a path that cannot be written is
; logged and let be.
(def %pidfile!
  (fn (_ path)
    (def fd (File open path (list (lit wronly) (lit creat) (lit trunc)) 420))
    (if (< fd 0)
      (%log-at "error" (Str8 append "Couldn't create pid file \"" path "\""))
      (do (def line (Str8 append (%num (Sys getpid)) "\n"))
          (File write fd line (%byte-len line))
          (File close fd)))))

(def %signal-number
  (fn (_ name)
    (def e (List find (fn (_ p) (str=? (first p) name)) (Sys signals)))
    (if (null? e) () (rest e))))

; One connection served.
(def %serve-connection
  (fn (_ fd keys s)
    (def peer (Socket peer fd))
    (def from (Str8 append (first peer) " port " (%num (rest peer))))
    (%log-at "verbose" (Str8 append "Connection from " from))
    (def c (ssh-open fd ()))
    (def user
      (guard (e ())
        (ssh-exchange-versions! c)
        (ssh-kex-server! c keys (%get s (lit hostkey-algs)))
        (%authenticate c s from)))
    (if (null? user)
      (%log (Str8 append "Connection closed by " from " [preauth]"))
      (do (def done (Str8 append "Disconnected from user " user " " from))
          (%log (guard (e (match ((str=? (%message e) "keepalive") (Str8 append "Timeout, client not responding from user " user " " from))
                                 ((str=? (%message e) "idle") (Str8 append done ": the channels were idle past ChannelTimeout"))
                                 (#t (Str8 append done ": " (%message e)))))
                  (%serve-session c fd s)
                  done))))
    (Socket close fd)))

; The listening sockets, one a ListenAddress and port, each logged; an
; address that cannot be bound is logged and passed over.
(def %listeners
  (fn (_ s)
    (List flat-map
      (fn (_ a)
        (def where (Str8 append (if (null? (first a)) "0.0.0.0" (first a)) " port " (%num (rest a))))
        (def fd (guard (e ()) (if (null? (first a)) (Socket tcp-listen (rest a)) (Socket tcp-listen-on (first a) (rest a)))))
        (if (null? fd)
          (do (%log-at "error" (Str8 append "Bind to port " (%num (rest a)) " on " (if (null? (first a)) "0.0.0.0" (first a)) " failed: Address already in use."))
              ())
          (do (%log (Str8 append "Server listening on " where ".")) (list fd))))
      (%get s (lit listen)))))

; The server's plan done: (CONFIG OPTIONS MODE), MODE (FOREGROUND DEBUG
; STDERR LOGFILE TEST PRINT).  The configuration settled -- the options,
; then the file -- and checked; under -t the host key read and nothing
; more, under -T the settings printed; otherwise the listeners opened and
; connections taken until the process is stopped, each served in a
; process of its own, or the one connection served here under -d.  The
; exit status, when it ends.
(def ssh-server-main
  (fn (_ plan)
    (def mode (List ref 2 plan))
    (def foreground (first mode)) (def debug (List ref 1 mode)) (def stderr (List ref 2 mode))
    (def logfile (List ref 3 mode))
    (def say (fn (_ t) (File write 2 (Str8 append t "\n") (+ (%byte-len t) 1))))
    (def path (first plan))
    (def text (guard (e ()) (File read-all path)))
    (def lines
      (guard (e (do (say (%message e)) ()))
        (List append (ssh-config-options (List ref 1 plan))
                     (if (null? text) () (ssh-config-read text path () () () "/etc/ssh")))))
    (def faults (ssh-config-faults lines ssh-config-sshd-keywords %refused ()))
    (def s (if (null? faults) (guard (e (do (say (%message e)) ())) (ssh-server-settings lines)) ()))
    (match
      ((null? text) (do (say (Str8 append path ": No such file or directory")) 255))
      ((not (null? faults))
        (do (List for-each say faults)
            (say (Str8 append path ": terminating, " (%num (List length faults)) " bad configuration options"))
            255))
      ((null? s) 255)
      (#t
        (do (%oset! %log-to 3 (Str8 ->sym (%get s (lit facility))))
            (%oset! %log-to 4 (%rank (%get s (lit level))))
            (unless (null? logfile)
              ((fn (_ fd) (if (< fd 0) (say (Str8 append "Couldn't open logfile " logfile)) (%oset! %log-to 2 fd)))
               (File open logfile (list (lit wronly) (lit creat) (lit append)) 420)))
            ; the host keys are loaded before the log moves to syslog, as
            ; OpenSSH's sshd loads them: what does not load is said on
            ; standard error, or -E's file
            (%oset! %log-to 1 #f)
            (def key (%host-keys s))
            (%oset! %log-to 1 (not (if stderr #t (not (null? logfile)))))
            (match
              ((List ref 5 mode) (do (File write 1 (%print s) (%byte-len (%print s))) 0))
              ((null? key) (do (say "sshd: no hostkeys available -- exiting.") 1))
              ((List ref 4 mode) 0)
              (#t (%listen-and-serve s key foreground debug))))))))

(def %listen-and-serve
  (fn (_ s keys foreground debug)
    (def lfds (%listeners s))
    (when (null? lfds) (do (%log-at "fatal" "Cannot bind any address.") (Sys exit 255)))
    (unless foreground (%background!))
    (unless debug (unless (null? (%get s (lit pidfile))) (%pidfile! (%get s (lit pidfile)))))
    (unless foreground (%quiet!))
    ; the engines, built once: each connection's process inherits them
    (ssh-engines! ())
    ; and the heap collected before the first fork: x collects only when
    ; asked, so the boot's and the engines' garbage -- some 43 million
    ; objects from source -- would go to every connection's process,
    ; whose first collect marks and sweeps all of it, writing to every
    ; page it shares with this one: a copy of the whole heap a connection
    (Heap collect)
    (def chld (%signal-number "CHLD"))
    (unless (if debug #t (null? chld)) (Sys signal chld (Sys sig-ign)))
    ((fn (self)
       (def ready (Sys poll (List map (fn (_ l) (pair l (list (lit in)))) lfds) -1))
       (def lfd (first (List find (fn (_ r) (not (null? (rest r)))) ready)))
       (def fd (Socket accept lfd))
       (if debug
         (do (List for-each (fn (_ l) (Socket close l)) lfds)
             (%serve-connection fd keys s)
             0)
         (do (def pid (Sys fork))
             (if (= pid 0)
               (do (List for-each (fn (_ l) (Socket close l)) lfds)
                   (unless (null? chld) (Sys signal chld (Sys sig-dfl)))
                   (%serve-connection fd keys s)
                   (Sys exit 0))
               (do (Socket close fd)
                   (self)))))))))

(provide ssh/server ssh-server-main ssh-server-settings)
