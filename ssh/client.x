; # x-ssh -- SSH on x-lang
;
; ## ssh/client.x -- the client: one command on a host
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What OpenSSH's ssh does for `ssh user@host command`: settle the
; configuration -- the command line's options, then ~/.ssh/config, then
; /etc/ssh/ssh_config, the first value holding -- connect, exchange
; versions and keys, check the server's key against known_hosts under
; StrictHostKeyChecking, authenticate with each identity file in turn and
; then a password, run the command with this process's standard input as
; its own, pass its output through, and leave with its status; 255 when
; the connection or the client failed.

(module ssh/client)

(import x/sys/socket)
(import x/sys/file)
(import x/sys/posix)
(import x/repl/term)
(import x/sys/syslog)
(import ssh/ask ssh-ask-tty ssh-ask-secret)
(import ssh/bytes ssh-copy)
(import ssh/transport ssh-open ssh-host-key ssh-engines! ssh-exchange-versions! ssh-kex!
  ssh-auth-service! ssh-auth-publickey-query! ssh-auth-publickey! ssh-auth-password! ssh-hostkey-names ssh-server-sig-algs
  ssh-kex-names ssh-cipher-names ssh-mac-names ssh-algorithms!)
(import ssh/session ssh-session-run! ssh-disconnect!)
(import ssh/keys ssh-key-file-sealed? ssh-key-wrong-passphrase ssh-identity-read-file ssh-pubkey-of-key-file)
(import ssh/known ssh-known-name ssh-known-check ssh-known-types ssh-known-add!)
(import ssh/keygen ssh-blob-fingerprint)
(import ssh/pubkey ssh-pubkey-blob ssh-pubkey-label ssh-pubkey-algorithms ssh-pubkey-base64 ssh-pubkey-type)
(import ssh/agent ssh-agent-connect ssh-agent-identities ssh-agent-identity)
(import ssh/config ssh-config-read ssh-config-options ssh-config-first ssh-config-all ssh-config-faults
  ssh-config-tilde ssh-config-time ssh-config-patterns? ssh-config-ssh-keywords
  ssh-config-line ssh-config-bad ssh-config-arg ssh-config-one ssh-config-choice ssh-config-yes? ssh-config-int-or-nil
  ssh-config-count ssh-config-seconds ssh-config-channel-timeout ssh-config-algorithms)
(import ssh/sys ssh-sys-me ssh-sys-proxy ssh-sys-connect ssh-sys-output ssh-sys-after-op)

(import x/core/doors str-byte-len str-byte-ref str-make str->ptr ptr-set! char->int)
(def %cvt (prim-ref (lit convert) (lit to)))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))

(def %say (fn (_ fd text) (File write fd text (str-byte-len text))))

; --- the log ---------------------------------------------------------------

; Where the log goes, set once from -E and -y and SyslogFacility: 1 the
; descriptor -E's file is open on, or (); 2 #t for the system log; 3
; its facility.
(def %log-to (Vector make 3 ()))
(obj-set! %log-to 2 #f) (obj-set! %log-to 3 (lit user))

; A line of the log, given without its newline: to the system log under
; the ident ssh, to -E's file ending in \r\n as OpenSSH's log writes
; there, or to standard error.  A trailing \r is the terminal's, kept on
; standard error alone.
(def %log-at
  (fn (_ severity text)
    (def n (Str8 length text))
    (def bare (if (if (> n 0) (= (char->int (str-byte-ref text (- n 1))) 13) #f) (Str8 sub 0 (- n 1) text) text))
    (unless (if (obj-ref %log-to 2) (Syslog send "ssh" (obj-ref %log-to 3) severity bare) #f)
      (if (null? (obj-ref %log-to 1)) (%say 2 (Str8 append text "\n"))
        (%say (obj-ref %log-to 1) (Str8 append bare "\r\n"))))))

(def %log (fn (_ text) (%log-at (lit info) text)))

; The caller's standard input.  The platform keeps it on fd 3, fd 0
; carrying x's own program text; with none, fd 3 is not open, a read of
; it fails, and the command's input ends at once.
(def %stdin 3)

; The process's CPU time in milliseconds, as text: what -v stamps each
; trace line with.
(def %ms (fn (_) (%num (/ (Sys clock) 1000))))

; A dotted address for a name: what the resolver says, or the name when
; it already is one.
(def %address
  (fn (_ host)
    (def r (Socket resolve host))
    (if (null? r) host (if (pair? r) (first r) r))))

(def %get (fn (_ s k) (rest (List find (fn (_ p) (eq? (first p) k)) s))))

; An error's message: an Err's own, or a word for what the engine raised.
(def %message
  (fn (_ e)
    (guard (e2 "an internal error")
      (if (Err engine? e) (Str8 append (Err %str (Err code-of e)) ": " (Err %str (Err subject-of e))) (e msg)))))

; --- the settings ----------------------------------------------------------

; What ssh_config may say that this client does not do: refused unless
; given the value that leaves it off, or one of the values served.
(def %refused
  (list (pair "tunnel" "no") (pair "permitremoteopen" "any") (pair "addressfamily" (list "any" "inet"))))

; An escape character, -e's or EscapeChar's: a character, ^X for its
; control character, or none -- as the character's number, none, or ()
; when it does not read so.
(def ssh-client-escape
  (fn (_ e)
    (match ((str=? e "none") (lit none))
           ((= (Str8 length e) 1) (char->int (str-byte-ref e 0)))
           ((if (= (Str8 length e) 2) (= (str-byte-ref e 0) #\^) #f) (% (char->int (str-byte-ref e 1)) 32))
           (#t ()))))

(def %char-text (fn (_ c) (def s (str-make 1)) (ptr-set! (str->ptr s) 0 c 1) s))

; An escape character as -G prints it: none, a control character as \^X.
(def %escape-text
  (fn (_ c)
    (match ((null? c) "none")
           ((< c 32) (Str8 append "\\^" (%char-text (+ c 64))))
           ((= c 127) "\\^?")
           (#t (%char-text c)))))

; What -Q answers for a query: the names served of its kind, a line
; each, as OpenSSH's -Q names them, a keyword's name too; unsupported
; when it is no query.
(def ssh-client-query
  (fn (_ q)
    (def k (Str8 downcase q))
    (def keys (list "ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "ssh-rsa"))
    (def sigs (list "ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "rsa-sha2-256" "rsa-sha2-512"))
    (match
      ((if (str=? q "cipher") #t (str=? k "ciphers")) ssh-cipher-names)
      ((str=? q "cipher-auth")
        (List filter (fn (_ c) (if (str=? c "chacha20-poly1305@openssh.com") #t (not (null? (Str8 index-of "-gcm@" c))))) ssh-cipher-names))
      ((if (str=? q "mac") #t (str=? k "macs")) ssh-mac-names)
      ((if (str=? q "kex") #t (str=? k "kexalgorithms")) ssh-kex-names)
      ((if (str=? q "key") #t (str=? q "key-plain")) keys)
      ((str=? q "key-cert") (list ""))
      ((if (str=? q "key-sig") #t
         (List any? (fn (_ w) (str=? w k))
           (list "casignaturealgorithms" "pubkeyacceptedkeytypes" "pubkeyacceptedalgorithms" "hostkeyalgorithms"
                 "hostbasedkeytypes" "hostbasedacceptedkeytypes" "hostbasedacceptedalgorithms")))
        (List append keys (list "rsa-sha2-256" "rsa-sha2-512")))
      ((str=? q "sig") sigs)
      ((str=? q "protocol-version") (list "2"))
      ((str=? q "compression") (list "none"))
      ((str=? q "help") (list "cipher" "cipher-auth" "compression" "kex" "key" "key-cert" "key-plain" "key-sig" "mac" "protocol-version" "sig"))
      (#t (lit unsupported)))))

; %-tokens expanded from an alist of (LETTER . TEXT), %% a percent.
(def %expand
  (fn (_ s tokens)
    (def n (Str8 length s))
    ((fn (self i acc)
       (match
         ((>= i n) (Str8 join "" (List reverse acc)))
         ((if (= (str-byte-ref s i) #\%) (< (+ i 1) n) #f)
           (do (def k (Str8 sub (+ i 1) 1 s))
               (def v (if (str=? k "%") "%" (rest (List find (fn (_ p) (str=? (first p) k)) tokens))))
               (self (+ i 2) (pair (if (null? v) (Str8 append "%" k) v) acc))))
         (#t (self (+ i 1) (pair (Str8 sub i 1 s) acc)))))
     0 ())))

; A LocalForward or RemoteForward line as (ADDRESS PORT HOST PORT):
; [bind_address:]port:host:hostport, the command line's -L shape, or the
; file's `[bind_address:]port host:hostport`.  No address is localhost,
; or every interface under GatewayPorts; `*` or an empty one is every
; interface, ().
(def %forward
  (fn (_ l gateway what)
    (def spec (Str8 join ":" (first (rest l))))
    (def parts (Str8 split ":" spec))
    (def n (List length parts))
    (def lport (if (if (= n 3) #t (= n 4)) (ssh-config-int-or-nil (List ref (- n 3) parts)) ()))
    (def rport (if (if (= n 3) #t (= n 4)) (ssh-config-int-or-nil (List ref (- n 1) parts)) ()))
    (def given (if (= n 4) (first parts) #f))
    (if (if (null? lport) #t (null? rport))
      (ssh-config-bad l (Str8 append what " '" spec "'"))
      (list (match ((not given) (if gateway () "localhost")) ((if (str=? given "*") #t (str=? given "")) ()) (#t given))
            lport (List ref (- n 2) parts) rport))))

; A port's digits as a number from 1 to 65535, or ().
(def %port-of
  (fn (_ t)
    ((fn (_ n) (if (null? n) () (if (if (< n 1) #t (> n 65535)) () n))) (ssh-config-int-or-nil t))))

; HOST[:PORT], HOST in brackets when it holds colons, as (HOST PORT):
; PORT the digits given, () for none; () when it does not read so.
(def %host-port
  (fn (_ s)
    (def n (Str8 length s))
    (def after (fn (_ i) (Str8 sub i (- n i) s)))
    (match
      ((= n 0) ())
      ((= (str-byte-ref s 0) #\[)
        (do (def close (Str8 index-of "]" s))
            (match ((if (null? close) #t (< close 2)) ())
                   ((= close (- n 1)) (list (Str8 sub 1 (- close 1) s) ()))
                   ((= (str-byte-ref s (+ close 1)) #\:) (list (Str8 sub 1 (- close 1) s) (after (+ close 2))))
                   (#t ()))))
      (#t (do (def colon (Str8 index-of ":" s))
              (match ((null? colon) (list s ()))
                     ((= colon 0) ())
                     ((not (null? (Str8 index-of ":" (after (+ colon 1))))) (list s ()))
                     (#t (list (Str8 sub 0 colon s) (after (+ colon 1))))))))))

; A DynamicForward, `[bind_address:]port`, as (GIVEN PORT): GIVEN the
; address as written, () for none; () when it does not read so.
(def ssh-client-dynamic
  (fn (_ spec)
    (def hp (if (null? (Str8 index-of ":" spec)) (list () spec) (%host-port spec)))
    (def port (if (null? hp) () (if (null? (List ref 1 hp)) () (%port-of (List ref 1 hp)))))
    (if (null? port) () (list (first hp) port))))

; A ProxyJump's hops, `[user@]host[:port]` or `ssh://[user@]host[:port][/]`
; separated by commas, as (USER HOST PORT) each, USER and PORT () when
; not given, an empty port none; () when one does not read so, as
; OpenSSH reads them -- a URI's host never in brackets.
(def ssh-client-jump
  (fn (_ text)
    (def cut-last (fn (_ s c) (if (if (> (Str8 length s) 0) (= (str-byte-ref s (- (Str8 length s) 1)) c) #f) (Str8 sub 0 (- (Str8 length s) 1) s) s)))
    (def hop
      (fn (_ h)
        (def url (if (> (Str8 length h) 6) (str=? (Str8 sub 0 6 h) "ssh://") #f))
        (def s (if url (cut-last (Str8 sub 6 (- (Str8 length h) 6) h) #\/) h))
        (def at ((fn (self i) (if (< i 0) () (if (= (str-byte-ref s i) #\@) i (self (- i 1))))) (- (Str8 length s) 1)))
        (def user (if (null? at) () (Str8 sub 0 at s)))
        (def where (cut-last (if (null? at) s (Str8 sub (+ at 1) (- (Str8 length s) at 1) s)) #\:))
        (def hp (if (if url (not (null? (Str8 index-of "[" where))) #f) () (%host-port where)))
        (match ((if (null? hp) #t (if (null? user) #f (= (Str8 length user) 0))) ())
               ((null? (List ref 1 hp)) (list user (first hp) ()))
               ((null? (%port-of (List ref 1 hp))) ())
               (#t (list user (first hp) (%port-of (List ref 1 hp)))))))
    (def hops (List map hop (Str8 split "," text)))
    (if (List any? (fn (_ h) (null? h)) hops) () hops)))

; A ProxyJump as -G prints it: the hops before the last as written, the
; last as [user@]host[:port].
(def %jump-text
  (fn (_ text)
    (def hops (Str8 split "," text))
    (def h (first (ssh-client-jump (List last hops))))
    (def host (if (null? (Str8 index-of ":" (List ref 1 h))) (List ref 1 h) (Str8 append "[" (List ref 1 h) "]")))
    (Str8 append (Str8 join "" (List map (fn (_ x) (Str8 append x ",")) (List reverse (rest (List reverse hops)))))
                 (if (null? (first h)) "" (Str8 append (first h) "@")) host
                 (if (null? (List ref 2 h)) "" (Str8 append ":" (%num (List ref 2 h)))))))

; IdentityAgent's socket: none for (), SSH_AUTH_SOCK or $NAME for the
; variable's value, a path otherwise, its tokens and ~ expanded.
(def %agent-socket
  (fn (_ v path)
    (def env (fn (_ name) ((fn (_ p) (if (if (null? p) #t (= (Str8 length p) 0)) () p)) (Sys getenv name))))
    (match ((str=? (Str8 downcase v) "none") ())
           ((str=? v "SSH_AUTH_SOCK") (env v))
           ((if (> (Str8 length v) 1) (= (str-byte-ref v 0) #\$) #f) (env (Str8 sub 1 (- (Str8 length v) 1) v)))
           (#t (path v)))))

; The settings in force, from the lines in order, for host as named on
; the command line: an alist.  Raises a label 'value Err whose message is
; OpenSSH's for a value it would refuse.
(def ssh-client-settings
  (fn (_ lines host local)
    (def home (Sys getenv "HOME"))
    (def hostname (%expand (ssh-config-one lines "hostname" host) (list (pair "h" host))))
    (def port
      ((fn (_ l) (if (null? l) 22
                   ((fn (_ n) (if (if (null? n) #t (if (< n 1) #t (> n 65535))) (ssh-config-bad l "Badly formatted port number.") n))
                    (ssh-config-int-or-nil (ssh-config-arg l)))))
       (ssh-config-line lines "port")))
    (def user (ssh-config-one lines "user" local))
    (def tokens (list (pair "h" hostname) (pair "p" (%num port)) (pair "r" user) (pair "u" local) (pair "d" home) (pair "n" host)))
    (def path (fn (_ p) (%expand (ssh-config-tilde p) tokens)))
    (def ids (List flat-map (fn (_ a) a) (ssh-config-all lines "identityfile")))
    (def files
      (fn (_ kw defaults)
        (def l (if (null? (ssh-config-line lines kw)) defaults (ssh-config-first lines kw)))
        (if (if (= (List length l) 1) (str=? (Str8 downcase (first l)) "none") #f) () (List map path l))))
    (def gateway (ssh-config-yes? lines "gatewayports" #f))
    (def clear (ssh-config-yes? lines "clearallforwardings" #f))
    (def forwards (fn (_ kw what) (if clear () (List map (fn (_ l) (%forward l gateway what)) (List filter (fn (_ l) (str=? (first l) kw)) lines)))))
    (def session (ssh-config-choice lines "sessiontype" (list "default" "none" "subsystem") "default"))
    ; ProxyCommand or ProxyJump, whichever is met first holding, `none`
    ; for neither
    (def proxy-line (List find (fn (_ l) (if (str=? (first l) "proxycommand") #t (str=? (first l) "proxyjump"))) lines))
    (def proxy-value (if (null? proxy-line) () ((fn (_ v) (if (str=? (Str8 downcase v) "none") () v)) (ssh-config-arg proxy-line))))
    (def jump? (if (null? proxy-value) #f (str=? (first proxy-line) "proxyjump")))
    (when (if jump? (null? (ssh-client-jump proxy-value)) #f)
      (ssh-config-bad proxy-line (Str8 append "Invalid ProxyJump \"" proxy-value "\"")))
    ; a last hop that is the destination itself -- its host, its user if
    ; it names one, its port or 22 -- is no jump, as OpenSSH drops it
    (def self-jump?
      (if jump?
        ((fn (_ h) (if (str=? (List ref 1 h) hostname)
                     (if (if (null? (first h)) #t (str=? (first h) user)) (= (if (null? (List ref 2 h)) 22 (List ref 2 h)) port) #f)
                     #f))
         (first (ssh-client-jump (List last (Str8 split "," proxy-value)))))
        #f))
    (def dynamics
      (if clear ()
        (List map (fn (_ l) ((fn (_ d) (if (null? d) (ssh-config-bad l "Bad forwarding specification.") d)) (ssh-client-dynamic (ssh-config-arg l))))
          (List filter (fn (_ l) (str=? (first l) "dynamicforward")) lines))))
    ; EscapeChar: the character's number, () for none
    (def escape
      ((fn (_ l) (if (null? l) 126
                   ((fn (_ e) (match ((null? e) (ssh-config-bad l "Bad escape character.")) ((eq? e (lit none)) ()) (#t e)))
                    (ssh-client-escape (ssh-config-arg l)))))
       (ssh-config-line lines "escapechar")))
    (list (pair (lit host) host)
          (pair (lit family) (ssh-config-choice lines "addressfamily" (list "any" "inet" "inet6") "any"))
          (pair (lit bind) (ssh-config-one lines "bindaddress" ()))
          (pair (lit escape) escape)
          (pair (lit fork) (ssh-config-yes? lines "forkafterauthentication" #f))
          (pair (lit known-command) ((fn (_ c) (if (str=? (Str8 downcase c) "none") () c)) (ssh-config-one lines "knownhostscommand" "none")))
          (pair (lit facility) (ssh-config-choice lines "syslogfacility"
                                 (list "daemon" "user" "auth" "authpriv" "local0" "local1" "local2" "local3" "local4" "local5" "local6" "local7") "user"))
          (pair (lit proxy-command) (if jump? () proxy-value))
          (pair (lit proxy-jump) (if (if jump? (not self-jump?) #f) proxy-value ()))
          (pair (lit dynamics) dynamics)
          (pair (lit tokens) tokens) (pair (lit hostname) hostname) (pair (lit port) port) (pair (lit user) user)
          (pair (lit identities) (if (null? ids) (List map (fn (_ p) (pair (path p) #f)) (list "~/.ssh/id_rsa" "~/.ssh/id_ecdsa" "~/.ssh/id_ed25519")) (List map (fn (_ p) (pair (path p) #t)) ids)))
          (pair (lit known) (files "userknownhostsfile" (list "~/.ssh/known_hosts" "~/.ssh/known_hosts2")))
          (pair (lit global) (files "globalknownhostsfile" (list "/etc/ssh/ssh_known_hosts" "/etc/ssh/ssh_known_hosts2")))
          (pair (lit strict) (ssh-config-choice lines "stricthostkeychecking" (list "yes" "no" "off" "ask" "accept-new") "ask"))
          (pair (lit alias) (ssh-config-one lines "hostkeyalias" ()))
          (pair (lit batch) (ssh-config-yes? lines "batchmode" #f))
          (pair (lit password) (ssh-config-yes? lines "passwordauthentication" #t))
          (pair (lit agent) (%agent-socket (ssh-config-one lines "identityagent" "SSH_AUTH_SOCK") path))
          (pair (lit identities-only) (ssh-config-yes? lines "identitiesonly" #f))
          ; ForwardAgent yes forwards IdentityAgent's socket; a path or $NAME its own
          (pair (lit forward-agent)
                ((fn (_ v) (match ((str=? (Str8 downcase v) "yes") (%agent-socket (ssh-config-one lines "identityagent" "SSH_AUTH_SOCK") path))
                                  ((str=? (Str8 downcase v) "no") ())
                                  (#t (%agent-socket v path))))
                 (ssh-config-one lines "forwardagent" "no")))
          (pair (lit pubkey) (not (str=? (ssh-config-choice lines "pubkeyauthentication" (list "yes" "no" "unbound" "host-bound") "yes") "no")))
          (pair (lit prompts) (ssh-config-count lines "numberofpasswordprompts" 3))
          (pair (lit limits) (list (ssh-config-seconds lines "serveraliveinterval" 0) (ssh-config-count lines "serveralivecountmax" 3) (ssh-config-channel-timeout lines)))
          (pair (lit gateway) gateway)
          (pair (lit forwards) (forwards "localforward" "Bad local forwarding specification"))
          (pair (lit remotes) (forwards "remoteforward" "Bad remote forwarding specification"))
          (pair (lit sendenv) (List flat-map (fn (_ a) a) (ssh-config-all lines "sendenv")))
          (pair (lit setenv) (List flat-map (fn (_ a) a) (ssh-config-all lines "setenv")))
          (pair (lit level) (ssh-config-choice lines "loglevel" (list "quiet" "fatal" "error" "info" "verbose" "debug" "debug1" "debug2" "debug3") "info"))
          (pair (lit session) session)
          (pair (lit command) ((fn (_ c) (if (str=? (Str8 downcase c) "none") () c)) (ssh-config-one lines "remotecommand" "none")))
          (pair (lit stdin-null) (ssh-config-yes? lines "stdinnull" #f))
          (pair (lit tty) (ssh-config-choice lines "requesttty" (list "no" "yes" "force" "auto") "auto"))
          (pair (lit ciphers) (ssh-config-algorithms lines "ciphers" ssh-cipher-names))
          (pair (lit macs) (ssh-config-algorithms lines "macs" ssh-mac-names)))))

; The settings as -G prints them, a keyword and its value a line.
(def %print
  (fn (_ s)
    (def yn (fn (_ b) (if b "yes" "no")))
    (def fwd (fn (_ f) (Str8 append (if (null? (first f)) "*" (first f)) ":" (%num (List ref 1 f)) " "
                                     (List ref 2 f) ":" (%num (List ref 3 f)))))
    (def limits (%get s (lit limits)))
    (Str8 join ""
      (List map (fn (_ l) (Str8 append l "\n"))
        (List append
          (list (Str8 append "host " (%get s (lit host))) (Str8 append "user " (%get s (lit user)))
                (Str8 append "hostname " (%get s (lit hostname))) (Str8 append "port " (%num (%get s (lit port)))))
          (List map (fn (_ i) (Str8 append "identityfile " (first i))) (%get s (lit identities)))
          (list (Str8 append "userknownhostsfile " (Str8 join " " (%get s (lit known))))
                (Str8 append "globalknownhostsfile " (Str8 join " " (%get s (lit global))))
                (Str8 append "stricthostkeychecking " (%get s (lit strict)))
                (Str8 append "batchmode " (yn (%get s (lit batch))))
                (Str8 append "passwordauthentication " (yn (%get s (lit password))))
                (Str8 append "pubkeyauthentication " (yn (%get s (lit pubkey))))
                (Str8 append "numberofpasswordprompts " (%num (%get s (lit prompts))))
                (Str8 append "serveraliveinterval " (%num (first limits)))
                (Str8 append "serveralivecountmax " (%num (List ref 1 limits)))
                (Str8 append "channeltimeout " (if (= (List ref 2 limits) 0) "none" (Str8 append "global=" (%num (List ref 2 limits)))))
                (Str8 append "ciphers " (Str8 join "," (%get s (lit ciphers))))
                (Str8 append "macs " (Str8 join "," (%get s (lit macs))))
                (Str8 append "gatewayports " (yn (%get s (lit gateway)))))
          (List map (fn (_ f) (Str8 append "localforward " (fwd f))) (%get s (lit forwards)))
          (List map (fn (_ f) (Str8 append "remoteforward " (fwd f))) (%get s (lit remotes)))
          (List map (fn (_ d) (Str8 append "dynamicforward " (if (null? (first d)) "" (Str8 append "[" (first d) "]:")) (%num (List ref 1 d))))
            (%get s (lit dynamics)))
          (if (null? (%get s (lit proxy-command))) () (list (Str8 append "proxycommand " (%get s (lit proxy-command)))))
          (if (null? (%get s (lit proxy-jump))) () (list (Str8 append "proxyjump " (%jump-text (%get s (lit proxy-jump))))))
          (List map (fn (_ e) (Str8 append "sendenv " e)) (%get s (lit sendenv)))
          (List map (fn (_ e) (Str8 append "setenv " e)) (%get s (lit setenv)))
          (list (Str8 append "loglevel " (Str8 upcase (%get s (lit level))))
                (Str8 append "sessiontype " (%get s (lit session)))
                (Str8 append "stdinnull " (yn (%get s (lit stdin-null))))
                (Str8 append "requesttty " (%get s (lit tty))))
          (if (null? (%get s (lit command))) () (list (Str8 append "remotecommand " (%get s (lit command)))))
          (if (null? (%get s (lit alias))) () (list (Str8 append "hostkeyalias " (%get s (lit alias)))))
          (list (Str8 append "addressfamily " (%get s (lit family))))
          (if (null? (%get s (lit bind))) () (list (Str8 append "bindaddress " (%get s (lit bind)))))
          (list (Str8 append "escapechar " (%escape-text (%get s (lit escape))))
                (Str8 append "forkafterauthentication " (yn (%get s (lit fork)))))
          (if (null? (%get s (lit known-command))) () (list (Str8 append "knownhostscommand " (%get s (lit known-command)))))
          (list (Str8 append "syslogfacility " (Str8 upcase (%get s (lit facility))))))))))

; --- the terminal ----------------------------------------------------------

; A secret asked for as OpenSSH's client asks, by ssh/ask's
; read_passphrase with the terminal required: () for none, and always
; in batch mode.
(def %ask-secret (fn (_ s text) (if (%get s (lit batch)) () (ssh-ask-secret text #f))))

; --- the host key ----------------------------------------------------------

(def %verification-failed (fn (_) (%log "Host key verification failed.") #f))

; A command line split into its words as OpenSSH's argv_split splits it:
; on spaces and tabs, quotes holding words together, a backslash
; escaping the character after it.
(def %argv
  (fn (_ line)
    (def n (Str8 length line))
    (def at (fn (_ i) (Str8 sub i 1 line)))
    ((fn (self i word quote words)
       (match
         ((>= i n) (List reverse (if (null? word) words (pair (Str8 join "" (List reverse word)) words))))
         ((if (str=? (at i) "\\") (< (+ i 1) n) #f) (self (+ i 2) (pair (at (+ i 1)) (if (null? word) () word)) quote words))
         ((not (null? quote))
           (if (str=? (at i) quote) (self (+ i 1) (if (null? word) (list "") word) () words) (self (+ i 1) (pair (at i) word) quote words)))
         ((if (str=? (at i) "\"") #t (str=? (at i) "'")) (self (+ i 1) (if (null? word) (list "") word) (at i) words))
         ((if (str=? (at i) " ") #t (str=? (at i) "\t"))
           (self (+ i 1) () () (if (null? word) words (pair (Str8 join "" (List reverse word)) words))))
         (#t (self (+ i 1) (pair (at i) word) quote words))))
     0 () () ())))

; KnownHostsCommand's lines for the reason given -- ORDER before the key
; exchange, HOSTNAME once the server's key is in -- as a known_hosts
; file of its own, (LABEL . TEXT); () when there is no command or it
; fails, which is logged.  Its words' tokens are expanded: the
; configuration's, %H the name looked up, %I the reason, and with a key
; %K its base64, %t its type and %f its fingerprint.
(def %known-command
  (fn (_ s name reason key)
    (def command (%get s (lit known-command)))
    (if (null? command) ()
      (do (def tokens
            (List append
              (list (pair "H" name) (pair "I" reason)
                    (pair "k" (if (null? (%get s (lit alias))) (%get s (lit hostname)) (%get s (lit alias)))))
              (if (null? key) ()
                (list (pair "K" (ssh-pubkey-base64 key)) (pair "t" (ssh-pubkey-type key))
                      (pair "f" (ssh-blob-fingerprint (ssh-pubkey-blob key)))))
              (%get s (lit tokens))))
          (def argv (List map (fn (_ w) (%expand w tokens)) (%argv command)))
          (match
            ((if (null? argv) #t (not (str=? (Str8 sub 0 1 (first argv)) "/")))
              (do (%log "KnownHostsCommand path is not absolute") ()))
            (#t
              ((fn (_ r)
                 (if (= (first r) 0) (pair "(KnownHostsCommand)" (rest r))
                   (do (%log (Str8 append "KnownHostsCommand " (first argv) " exited with status " (%num (first r)))) ())))
               (guard (e (pair 255 "")) (ssh-sys-output argv)))))))))

; The host key algorithms offered, as OpenSSH orders them: those of the
; types known_hosts already holds for this host first, so a known host
; is not met by a key of another type; then the rest.  An ssh-rsa key is
; offered as rsa-sha2-512 and rsa-sha2-256.
(def %hostkey-order
  (fn (_ s)
    (def port (%get s (lit port)))
    (def name (ssh-known-name (if (null? (%get s (lit alias))) (%get s (lit hostname)) (%get s (lit alias))) port))
    (def ordered ((fn (_ k) (if (null? k) () (list k))) (%known-command s name "ORDER" ())))
    (def known (List flat-map (fn (_ t) (if (str=? t "ssh-rsa") (list "rsa-sha2-512" "rsa-sha2-256") (list t)))
                 (ssh-known-types (List append (%get s (lit known)) (%get s (lit global)) ordered) name)))
    (def first-known (List filter (fn (_ a) (List any? (fn (_ k) (str=? k a)) known)) ssh-hostkey-names))
    (List append first-known (List filter (fn (_ a) (not (List any? (fn (_ k) (str=? k a)) first-known))) ssh-hostkey-names))))

; The server's key against known_hosts under StrictHostKeyChecking,
; before any credential is sent: #t to go on.  A new host is recorded in
; the first user file when accepted; a changed key is refused whatever
; the policy.
(def %host-key-ok
  (fn (_ c s addr quiet tr)
    (def port (%get s (lit port)))
    (def name (ssh-known-name (if (null? (%get s (lit alias))) (%get s (lit hostname)) (%get s (lit alias))) port))
    (def key (ssh-host-key c))
    (def fp (ssh-blob-fingerprint (ssh-pubkey-blob key)))
    (def label (ssh-pubkey-label key))
    (def known (%get s (lit known)))
    (def given ((fn (_ k) (if (null? k) () (list k))) (%known-command s name "HOSTNAME" key)))
    (def seen (ssh-known-check (List append known (%get s (lit global)) given) name key))
    (def strict (%get s (lit strict)))
    (def record!
      (fn (_)
        (unless (null? known)
          (guard (e (%log (Str8 append "Failed to add the host to the list of known hosts (" (first known) ").")))
            (ssh-known-add! (first known) name key)
            (unless quiet
              (%log (Str8 append "Warning: Permanently added '" name "' (" label ") to the list of known hosts.")))))
        #t))
    (match
      ((eq? (first seen) (lit known)) (do (unless (null? tr) (tr (Str8 append "Host '" name "' is known and matches the " label " host key."))) #t))
      ((eq? (first seen) (lit changed))
        (do (%log (Str8 append
              "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
              "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
              "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
              "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"
              "Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n"
              "It is also possible that a host key has just been changed.\n"
              "The fingerprint for the " label " key sent by the remote host is\n" fp ".\n"
              "Please contact your system administrator.\n"
              "Add correct host key in " (List ref 1 seen) " to get rid of this message.\n"
              "Offending " label " key in " (List ref 1 seen) ":" (%num (List ref 2 seen)) "\n"
              "  remove with:\n"
              "  ssh-keygen -f '" (List ref 1 seen) "' -R '" name "'\n"
              "Host key for " name " has changed and you have requested strict checking."))
            (%verification-failed)))
      ((str=? strict "yes")
        (do (%log (Str8 append "No " label " host key is known for " name " and you have requested strict checking."))
            (%verification-failed)))
      ((not (str=? strict "ask")) (record!))
      ((%get s (lit batch)) (%verification-failed))
      (#t
        ((fn (self text)
           (def a (ssh-ask-tty text #f))
           (match
             ((null? a) (%verification-failed))
             ((if (str=? a "yes") #t (str=? a fp)) (record!))
             ((str=? a "no") (%verification-failed))
             (#t (self "Please type 'yes', 'no' or the fingerprint: "))))
         (Str8 append "The authenticity of host '" name " ("
                      (if (null? addr) "<no hostip for proxy command>" (ssh-known-name addr port)) ")' can't be established.\n"
                      label " key fingerprint is " fp ".\n"
                      "This key is not known by any other names.\n"
                      "Are you sure you want to continue connecting (yes/no/[fingerprint])? "))))))

; --- authentication --------------------------------------------------------

(def %offers? (fn (_ methods m) (if (eq? methods #t) #f (List any? (fn (_ x) (str=? x m)) methods))))

; The identity files that read, as (PATH KEY ID): KEY the public key
; (ssh/pubkey's), of any type served, ID the identity, opened; a file
; named but missing is warned of, the default ones passed over quietly.
; A key sealed under a passphrase is read for its public half alone, its
; ID (), and opened only when the server would take it.
;
; The agent's keys come first, as OpenSSH's pubkey_prepare orders them:
; each in the agent's order, a file's key taking the agent's place with
; the file's path, the agent's others passed over under IdentitiesOnly;
; then the files whose keys the agent lacks.
(def %identities
  (fn (_ s quiet tr)
    (if (not (%get s (lit pubkey))) ()
      (do (def files
            (List flat-map
              (fn (_ i)
                (match
                  ((not (File exists? (first i)))
                    (do (when (if (rest i) (not quiet) #f)
                          (%log (Str8 append "Warning: Identity file " (first i) " not accessible: No such file or directory.")))
                        ()))
                  (#t (guard (e (do (%log (Str8 append "Load key \"" (first i) "\": " (%message e))) ()))
                        (def key (ssh-pubkey-of-key-file (first i)))
                        (def id (if (ssh-key-file-sealed? (first i)) () (ssh-identity-read-file (first i) "")))
                        (list (list (first i) key id))))))
              (%get s (lit identities))))
          (def same? (fn (_ a b) (str=? (ssh-pubkey-base64 a) (ssh-pubkey-base64 b))))
          (def held (%agent-keys s tr))
          (def from-agent
            (List flat-map
              (fn (_ k)
                (def file (List find (fn (_ f) (same? (List ref 1 f) (first k))) files))
                (match
                  ((not (null? file)) (list (list (first file) (first k) (List ref 2 k) #t)))
                  ((%get s (lit identities-only)) ())
                  (#t (list (list (List ref 1 k) (first k) (List ref 2 k) #f)))))
              held))
          (def rest-files (List filter (fn (_ f) (not (List any? (fn (_ k) (same? (List ref 1 f) (first k))) held))) files))
          (unless (null? tr)
            (do (List for-each (fn (_ i) (tr (Str8 append "Will attempt key: " (first i) " " (%key-words (List ref 1 i)) (if (List ref 3 i) " explicit agent" " agent"))))
                  from-agent)
                (List for-each (fn (_ i) (tr (Str8 append "Will attempt key: " (first i) " " (%key-words (List ref 1 i))))) rest-files)))
          (List append (List map (fn (_ i) (List take 3 i)) from-agent) rest-files)))))

; The agent's keys, each (KEY COMMENT ID), ID an identity the agent signs
; for; () when IdentityAgent names none or it does not answer.
(def %agent-keys
  (fn (_ s tr)
    (def path (%get s (lit agent)))
    (if (null? path) ()
      (guard (e (do (unless (null? tr) (tr (Str8 append "get_agent_identities: " (%message e)))) ()))
        (def fd (ssh-agent-connect path))
        (List map (fn (_ k) (list (first k) (List ref 1 k) (ssh-agent-identity fd (first k) (List ref 1 k))))
          (ssh-agent-identities fd))))))

; A key as -v names it: its label and fingerprint.
(def %key-words (fn (_ key) (Str8 append (ssh-pubkey-label key) " " (ssh-blob-fingerprint (ssh-pubkey-blob key)))))

; The algorithm a key signs with: its own, or for RSA the first of
; rsa-sha2-512 and rsa-sha2-256 the server's server-sig-algs names --
; the first when it named none.
(def %alg-for
  (fn (_ c key)
    (def algs (ssh-pubkey-algorithms key))
    (def said (ssh-server-sig-algs c))
    ((fn (_ a) (if (null? a) (first algs) a))
     (if (null? said) () (List find (fn (_ a) (List any? (fn (_ x) (str=? x a)) said)) algs)))))

; A sealed key opened, its passphrase asked for up to
; NumberOfPasswordPrompts times as OpenSSH's load_identity_file asks; ()
; when an answer is empty, there is none, or none opens it.  Batch mode
; asks nothing.  The next try is asked for outside the guard: its
; clause is left with wrong, not run on to the end of the connection.
(def %open-identity
  (fn (_ s path tr)
    (def prompt (Str8 append "Enter passphrase for key '" path "': "))
    (def try
      (fn (_ typed)
        (guard (e (if (str=? (%message e) ssh-key-wrong-passphrase) (lit wrong)
                    (do (%log (Str8 append "Load key \"" path "\": " (%message e))) ())))
          (ssh-identity-read-file path typed))))
    ((fn (self left)
       (if (if (= left 0) #t (%get s (lit batch))) ()
         (do (def typed (ssh-ask-secret prompt #f))
             (if (if (null? typed) #t (= (Str8 length typed) 0))
               (do (unless (null? tr) (tr "no passphrase given, try next key")) ())
               ((fn (_ id)
                  (if (not (eq? id (lit wrong))) id
                    (do (unless (null? tr) (tr "bad passphrase given, try again...")) (self (- left 1)))))
                (try typed))))))
     (%get s (lit prompts)))))

; One identity offered: an open key signed with; a sealed one asked
; about first, then opened and signed with when the server would take
; it.  The answer as ssh-auth-publickey! has it, or the one before when
; the key is passed over.
(def %offer-identity
  (fn (_ c s user id answer tr)
    (def key (List ref 1 id))
    (def alg (%alg-for c key))
    (if (not (null? (List ref 2 id))) (ssh-auth-publickey! c user (List ref 2 id) alg)
      (do (def q (ssh-auth-publickey-query! c user key alg))
          (if (not (eq? q (lit pk-ok))) q
            (do (unless (null? tr) (tr (Str8 append "Server accepts key: " (first id) " " (%key-words key))))
                (def opened (%open-identity s (first id) tr))
                (if (null? opened) answer (ssh-auth-publickey! c user opened alg))))))))

; Authentication as OpenSSH's client tries it: each key while the server
; offers publickey, then, while it offers password, a password asked for
; up to NumberOfPasswordPrompts times.  #t, or the server's remaining
; methods.
(def %authenticate
  (fn (_ c s ids tr)
    (def user (%get s (lit user)))
    (ssh-auth-service! c)
    (def by-key
      ((fn (self ks answer)
         (if (if (null? ks) #t (not (%offers? answer "publickey"))) answer
           (self (rest ks) (%offer-identity c s user (first ks) answer tr))))
       ids (list "publickey" "password")))
    (def prompt (Str8 append user "@" (%get s (lit hostname)) "'s password: "))
    (if (not (%get s (lit password))) by-key
      ((fn (self left answer first-try)
         (if (if (= left 0) #t (not (%offers? answer "password"))) answer
           (do (unless first-try (%log "Permission denied, please try again."))
               (def typed (%ask-secret s prompt))
               (if (null? typed) answer
                 (do (unless (null? tr) (tr "Next authentication method: password"))
                     (self (- left 1) (ssh-auth-password! c user typed) #f))))))
       (%get s (lit prompts)) by-key #t))))

; The variables SendEnv's patterns name and SetEnv's, as (NAME . VALUE).
(def %environment
  (fn (_ s)
    (def split (fn (_ e) (def i (Str8 index-of "=" e)) (if (null? i) () (list (pair (Str8 sub 0 i e) (Str8 sub (+ i 1) (- (Str8 length e) i 1) e))))))
    (def patterns (%get s (lit sendenv)))
    (List append
      (if (null? patterns) ()
        (List filter (fn (_ v) (ssh-config-patterns? patterns (first v))) (List flat-map split (Sys environ))))
      (List flat-map split (%get s (lit setenv))))))

; --- the connection --------------------------------------------------------

(def %debug-levels (list "verbose" "debug" "debug1" "debug2" "debug3"))

; The command the connection is carried over, its tokens expanded, or ()
; to connect directly: ProxyCommand's, or for ProxyJump the one OpenSSH
; makes of it -- this client run to the last hop with -W, the hops
; before it its own -J, -F's file and -v passed on.
(def %proxy-command
  (fn (_ s)
    (def jump (%get s (lit proxy-jump)))
    (def raw
      (if (null? jump) (%get s (lit proxy-command))
        (do (def hops (Str8 split "," jump))
            (def h (first (ssh-client-jump (List last hops))))
            (def extra (List reverse (rest (List reverse hops))))
            (def config (%get s (lit config-file)))
            (Str8 append "ssh"
              (if (null? (first h)) "" (Str8 append " -l " (first h)))
              (if (null? (List ref 2 h)) "" (Str8 append " -p " (%num (List ref 2 h))))
              (if (null? extra) "" (Str8 append " -J " (Str8 join "," extra)))
              (if (null? config) "" (Str8 append " -F " config))
              (if (List any? (fn (_ l) (str=? l (%get s (lit level)))) %debug-levels) " -v" "")
              " -W '[%h]:%p' " (List ref 1 h)))))
    (if (null? raw) () (%expand raw (%get s (lit tokens))))))

; A proxy command's end, as OpenSSH's client ends it: a hangup, then
; waited for.
(def %end-proxy
  (fn (_ pid)
    (def hup ((fn (_ e) (if (null? e) 1 (rest e))) (List find (fn (_ p) (str=? (first p) "HUP")) (Sys signals))))
    (guard (e ()) (Sys kill pid hup))
    (guard (e ()) (Sys wait pid))))

; The connection made and the command run under settings s: its exit
; status, or 255.
(def %run
  (fn (_ s command stdio)
    (def proxy (%proxy-command s))
    (def spawned (if (null? proxy) () (ssh-sys-proxy proxy)))
    (def status (%connected s command stdio proxy spawned))
    (unless (null? spawned) (%end-proxy (first spawned)))
    status))

(def %connected
  (fn (_ s command stdio proxy spawned)
    (def level (%get s (lit level)))
    (def quiet (List any? (fn (_ l) (str=? l level)) (list "quiet" "fatal" "error")))
    (def tr (if (List any? (fn (_ l) (str=? l level)) %debug-levels)
              (fn (_ t) (%log-at (lit debug) (Str8 append "debug1: " (%ms) " ms " t)))
              ()))
    (def host (%get s (lit hostname)))
    (def port (%get s (lit port)))
    (def bind (%get s (lit bind)))
    ; through a proxy command there is no address of the host's own
    (def addr (if (null? proxy) (%address host) ()))
    ; the connection, from BindAddress's address when it names one; a
    ; failure is (failed . WORDS), logged as OpenSSH logs it
    (def fd
      (if (not (null? proxy)) (if (null? spawned) () (rest spawned))
        (guard (e (pair (lit failed) (%message e)))
          (def from
            (if (null? bind) ()
              (guard (e2 (do (%log (Str8 append "getaddrinfo: " bind ": " (ssh-sys-after-op (%message e2))))
                             (Err raise 'value "connect: failure" ())))
                (%address bind))))
          (ssh-sys-connect addr port from))))
    (def failed (if (pair? fd) (eq? (first fd) (lit failed)) #f))
    (match
      (failed
        (do (def words (ssh-sys-after-op (rest fd)))
            (if (str=? (Str8 sub 0 (if (< (Str8 length (rest fd)) 5) 0 5) (rest fd)) "bind:")
              (do (%log (Str8 append "bind " bind ": " words))
                  (%log (Str8 append "ssh: connect to host " host " port " (%num port) ": failure")))
              (%log (Str8 append "ssh: connect to host " host " port " (%num port) ": " words)))
            255))
      ((null? fd) (do (%log "ssh: the proxy command could not be started") 255))
      (#t
      (guard (e (do (%log (match ((str=? (%message e) "keepalive") (Str8 append "Timeout, server " host " not responding."))
                                 ((str=? (%message e) "idle") (Str8 append "Connection to " host " closed: the channels were idle past ChannelTimeout."))
                                 (#t (%message e))))
                    (guard (e2 ()) (Socket close fd))
                    255))
        (unless (null? tr)
          (tr (if (null? proxy) (Str8 append "Connecting to " host " [" addr "] port " (%num port) ".")
                (Str8 append "Executing proxy command: exec " proxy))))
        (def c (ssh-open fd tr))
        (ssh-engines! c)
        ; a proxy that ends before the versions are exchanged is a
        ; connection closed by a peer with no address, in OpenSSH's words
        (if (null? proxy) (ssh-exchange-versions! c)
          (guard (e (Err raise 'value "Connection closed by UNKNOWN port 65535\r" ()))
            (ssh-exchange-versions! c)))
        (ssh-algorithms! c (%get s (lit ciphers)) (%get s (lit macs)))
        (ssh-kex! c (%hostkey-order s))
        (if (not (%host-key-ok c s addr quiet tr))
          (do (Socket close fd) 255)
          (do (def ids (%identities s quiet tr))
              (def ok (%authenticate c s ids tr))
              (if (not (eq? ok #t))
                (do (%log (Str8 append (%get s (lit user)) "@" host ": Permission denied (" (Str8 join "," ok) ")."))
                    (Socket close fd)
                    255)
                (do (unless (null? tr)
                      (tr (Str8 append "Authenticated to " host (if (null? addr) " (via proxy)" (Str8 append " ([" addr "]:" (%num port) ")")) ".")))
                    ; ForkAfterAuthentication: the connection goes on in a
                    ; child of its own session, this process leaving with 0
                    (when (%get s (lit fork))
                      (do (def pid (Sys fork))
                          (unless (= pid 0) (Sys exit 0))
                          (Sys setsid)))
                    ; a terminal as RequestTTY says: force always, yes
                    ; when standard input is one, auto for a shell on one
                    (def local-tty (Sys isatty %stdin))
                    (def want (%get s (lit tty)))
                    (def tty?
                      (match ((str=? want "force") #t)
                             ((str=? want "no") #f)
                             ((not (null? stdio)) #f)
                             ((str=? want "yes") local-tty)
                             (#t (if (eq? command (lit shell)) local-tty #f))))
                    (when (if (str=? want "yes") (if (not local-tty) (not quiet) #f) #f)
                      (%log "Pseudo-terminal will not be allocated because stdin is not a terminal.\r"))
                    (def term ((fn (_ t) (if (null? t) "" t)) (Sys getenv "TERM")))
                    ; the modes as they are before raw mode, for the server's terminal
                    (def modes (if tty? (Term modes %stdin) ()))
                    (def saved (if (if tty? local-tty #f) (Term raw! %stdin) ()))
                    (def outcome
                      (guard (e (pair (lit failed) (%message e)))
                        (pair (lit status)
                          (ssh-session-run! c command
                            (if (if (%get s (lit stdin-null)) #t (if (null? command) (null? stdio) #f)) () %stdin)
                            (fn (_ buf start len) (File write 1 (ssh-copy buf start len) len))
                            (fn (_ buf start len) (File write 2 (ssh-copy buf start len) len))
                            (List map (fn (_ f) (pair (if (null? (first f)) () (%address (first f))) (rest f)))
                              (List append (%get s (lit forwards))
                                ; DynamicForward: a listener whose connections say where they go, by SOCKS
                                (List map (fn (_ d) (list (match ((null? (first d)) (if (%get s (lit gateway)) () "localhost"))
                                                                 ((if (str=? (first d) "*") #t (str=? (first d) "")) ())
                                                                 (#t (first d)))
                                                          (List ref 1 d) #f #f))
                                  (%get s (lit dynamics)))))
                            (%get s (lit remotes))
                            (if (null? stdio) () (pair (%address (first stdio)) (rest stdio)))
                            (%get s (lit limits))
                            (%environment s)
                            (if tty? (list term (fn (_) (Term window %stdin)) modes (%get s (lit escape))) ())
                            (%get s (lit forward-agent))))))
                    (unless (null? saved) (Term restore! %stdin saved))
                    (guard (e2 ()) (ssh-disconnect! c))
                    (Socket close fd)
                    (def closed (Str8 append "Connection to " host " closed.\n"))
                    (match
                      ((eq? (first outcome) (lit status))
                        (do (when (if tty? (not quiet) #f) (%say 2 closed))
                            (def code (if (null? (rest outcome)) 0 (rest outcome)))
                            (unless (null? tr) (tr (Str8 append "Exit status " (%num code))))
                            code))
                      ((str=? (rest outcome) "escape") (do (%say 2 closed) 255))
                      ((str=? (rest outcome) "keepalive") (do (%log (Str8 append "Timeout, server " host " not responding.")) 255))
                      ((str=? (rest outcome) "idle") (do (%log (Str8 append "Connection to " host " closed: the channels were idle past ChannelTimeout.")) 255))
                      (#t (do (%log (rest outcome)) 255))))))))))))

; The client's plan done: (HOST COMMAND OPTIONS CONFIG STDIO PRINT LOG
; SYSLOG).  The log sent where -E and -y say; the configuration settled
; -- the options, the user's file (-F's, or ~/.ssh/config) and the
; system's, which -F leaves out -- and the connection made, or the
; settings printed.  The exit status.
(def ssh-client-main
  (fn (_ plan)
    (def host (first plan))
    (def local (ssh-sys-me))
    (def logfile (List ref 6 plan))
    (def log-fd (if (null? logfile) ()
                  (guard (e (pair (lit failed) (ssh-sys-after-op (%message e))))
                    (File open logfile (list (lit wronly) (lit creat) (lit append)) 384))))
    (if (if (null? log-fd) #f (if (pair? log-fd) #t (< log-fd 0)))
      (do (%say 2 (Str8 append "Couldn't open logfile " logfile (if (pair? log-fd) (Str8 append ": " (rest log-fd)) "") "\r\n")) 255)
      (do (obj-set! %log-to 1 log-fd)
          (obj-set! %log-to 2 (List ref 7 plan))
          (%settled host local plan)))))

(def %settled
  (fn (_ host local plan)
    (guard (e (do (%log (%message e)) 255))
      (def opts (ssh-config-options (List ref 2 plan)))
      (def user (if (null? (ssh-config-first opts "user")) local (first (ssh-config-first opts "user"))))
      (def config (List ref 3 plan))
      (def read
        (fn (_ path dir must)
          (def text (guard (e ()) (File read-all path)))
          (when (if (null? text) must #f) (Err raise 'value (Str8 append "Can't open user config file " path ": No such file or directory") ()))
          (if (null? text) () (ssh-config-read text path host user local dir))))
      (def lines
        (List append opts
          (match
            ((null? config) (List append (read (ssh-config-tilde "~/.ssh/config") (ssh-config-tilde "~/.ssh") #f)
                                         (read "/etc/ssh/ssh_config" "/etc/ssh" #f)))
            ((str=? config "none") ())
            (#t (read config (ssh-config-tilde "~/.ssh") #t)))))
      (def faults (ssh-config-faults lines ssh-config-ssh-keywords %refused (ssh-config-first lines "ignoreunknown")))
      (if (not (null? faults))
        (do (List for-each %log faults)
            (%log (Str8 append "terminating, " (%num (List length faults)) " bad configuration options"))
            255)
        (do (def s (pair (pair (lit config-file) config) (ssh-client-settings lines host local)))
            (obj-set! %log-to 3 (Str8 ->sym (%get s (lit facility))))
            ; -W's host:port, the host in brackets when it holds colons
            (def stdio (if (null? (List ref 4 plan)) ()
                         ((fn (_ hp)
                            (def p (if (null? hp) () (if (null? (List ref 1 hp)) () (ssh-config-int-or-nil (List ref 1 hp)))))
                            (if (null? p) (Err raise 'value "stdio forward specification must be host:port" ())
                              (pair (first hp) p)))
                          (%host-port (List ref 4 plan)))))
            ; the command: none under SessionType none, the one given or
            ; RemoteCommand's -- under SessionType subsystem the name of the
            ; subsystem asked for -- or else the user's shell, unless -W
            ; carries the session's place
            (def command (match ((str=? (%get s (lit session)) "none") ())
                                ((str=? (%get s (lit session)) "subsystem")
                                  ((fn (_ name) (if (null? name) (Err raise 'value "ssh: a subsystem needs its name" ()) (pair (lit subsystem) name)))
                                   (if (null? (List ref 1 plan)) (%get s (lit command)) (List ref 1 plan))))
                                ((not (null? (List ref 1 plan))) (List ref 1 plan))
                                ((not (null? (%get s (lit command)))) (%get s (lit command)))
                                ((null? stdio) (lit shell))
                                (#t ())))
            (when (if (%get s (lit fork)) (eq? command (lit shell)) #f)
              (Err raise 'value "Cannot fork into background without a command to execute.\r" ()))
            (if (List ref 5 plan)
              (do (%say 1 (%print s)) 0)
              (%run s command stdio)))))))

(provide ssh/client ssh-client-main ssh-client-settings ssh-client-jump ssh-client-dynamic ssh-client-escape ssh-client-query)
