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
(import ssh/ask ssh-ask-tty ssh-ask-secret)
(import ssh/bytes ssh-copy)
(import ssh/transport ssh-open ssh-host-key ssh-engines! ssh-exchange-versions! ssh-kex!
  ssh-auth-service! ssh-auth-publickey-query! ssh-auth-publickey! ssh-auth-password! ssh-hostkey-names ssh-server-sig-algs)
(import ssh/session ssh-session-run! ssh-disconnect!)
(import ssh/keys ssh-key-file-sealed? ssh-key-wrong-passphrase ssh-identity-read-file ssh-pubkey-of-key-file)
(import ssh/known ssh-known-name ssh-known-check ssh-known-types ssh-known-add!)
(import ssh/keygen ssh-blob-fingerprint)
(import ssh/pubkey ssh-pubkey-blob ssh-pubkey-label ssh-pubkey-algorithms ssh-pubkey-base64)
(import ssh/agent ssh-agent-connect ssh-agent-identities ssh-agent-identity)
(import ssh/config ssh-config-read ssh-config-options ssh-config-first ssh-config-all ssh-config-faults
  ssh-config-tilde ssh-config-time ssh-config-patterns? ssh-config-ssh-keywords)

(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %cvt (prim-ref (lit convert) (lit to)))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))

(def %say (fn (_ fd text) (File write fd text (%byte-len text))))

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

; The user this client runs as: USER, or the passwd entry of its uid.
(def %me
  (fn (_)
    (def u (Sys getenv "USER"))
    (if (if (null? u) #f (> (Str8 length u) 0)) u
      ((fn (_ e) (if (null? e) "" (first e)))
        (List find (fn (_ fs) (if (> (List length fs) 2) (str=? (List ref 2 fs) (%num (Sys getuid))) #f))
          (List map (fn (_ l) (Str8 split ":" l))
            (Str8 split "\n" (guard (e "") (File read-all "/etc/passwd")))))))))

; --- the settings ----------------------------------------------------------

; What ssh_config may say that this client does not do: refused unless
; given the value that leaves it off.
(def %refused
  (list (pair "proxycommand" "none") (pair "proxyjump" "none") (pair "dynamicforward" "")
        (pair "knownhostscommand" "none") (pair "tunnel" "no") (pair "forkafterauthentication" "no")
        (pair "permitremoteopen" "any")))

(def %line (fn (_ lines kw) (List find (fn (_ l) (str=? (first l) kw)) lines)))
(def %bad (fn (_ l what) (Err raise 'value (Str8 append (List ref 2 l) ": " what) ())))
(def %arg (fn (_ l) (if (null? (first (rest l))) "" (first (first (rest l))))))

; A keyword's first argument, or default.
(def %one (fn (_ lines kw default) (def l (%line lines kw)) (if (null? l) default (%arg l))))

; A keyword's value, one of choices, lowercased, or default.
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

(def %count
  (fn (_ lines kw default)
    (def l (%line lines kw))
    (if (null? l) default ((fn (_ n) (if (null? n) (%bad l "invalid number.") n)) (%int-or-nil (%arg l))))))

(def %seconds
  (fn (_ lines kw default)
    (def l (%line lines kw))
    (if (null? l) default ((fn (_ n) (if (null? n) (%bad l "invalid time value.") n)) (ssh-config-time (%arg l))))))

; ChannelTimeout's global time, in seconds, 0 for none: the one channel
; timeout served is the one over every channel together.
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

; %-tokens expanded from an alist of (LETTER . TEXT), %% a percent.
(def %expand
  (fn (_ s tokens)
    (def n (Str8 length s))
    ((fn (self i acc)
       (match
         ((>= i n) (Str8 join "" (List reverse acc)))
         ((if (= (%byte-ref s i) #\%) (< (+ i 1) n) #f)
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
    (def lport (if (if (= n 3) #t (= n 4)) (%int-or-nil (List ref (- n 3) parts)) ()))
    (def rport (if (if (= n 3) #t (= n 4)) (%int-or-nil (List ref (- n 1) parts)) ()))
    (def given (if (= n 4) (first parts) #f))
    (if (if (null? lport) #t (null? rport))
      (%bad l (Str8 append what " '" spec "'"))
      (list (match ((not given) (if gateway () "localhost")) ((if (str=? given "*") #t (str=? given "")) ()) (#t given))
            lport (List ref (- n 2) parts) rport))))

; IdentityAgent's socket: none for (), SSH_AUTH_SOCK or $NAME for the
; variable's value, a path otherwise, its tokens and ~ expanded.
(def %agent-socket
  (fn (_ v path)
    (def env (fn (_ name) ((fn (_ p) (if (if (null? p) #t (= (Str8 length p) 0)) () p)) (Sys getenv name))))
    (match ((str=? (Str8 downcase v) "none") ())
           ((str=? v "SSH_AUTH_SOCK") (env v))
           ((if (> (Str8 length v) 1) (= (%byte-ref v 0) #\$) #f) (env (Str8 sub 1 (- (Str8 length v) 1) v)))
           (#t (path v)))))

; The settings in force, from the lines in order, for host as named on
; the command line: an alist.  Raises a label 'value Err whose message is
; OpenSSH's for a value it would refuse.
(def ssh-client-settings
  (fn (_ lines host local)
    (def home (Sys getenv "HOME"))
    (def hostname (%expand (%one lines "hostname" host) (list (pair "h" host))))
    (def port
      ((fn (_ l) (if (null? l) 22
                   ((fn (_ n) (if (if (null? n) #t (if (< n 1) #t (> n 65535))) (%bad l "Badly formatted port number.") n))
                    (%int-or-nil (%arg l)))))
       (%line lines "port")))
    (def user (%one lines "user" local))
    (def tokens (list (pair "h" hostname) (pair "p" (%num port)) (pair "r" user) (pair "u" local) (pair "d" home) (pair "n" host)))
    (def path (fn (_ p) (%expand (ssh-config-tilde p) tokens)))
    (def ids (List flat-map (fn (_ a) a) (ssh-config-all lines "identityfile")))
    (def files
      (fn (_ kw defaults)
        (def l (if (null? (%line lines kw)) defaults (ssh-config-first lines kw)))
        (if (if (= (List length l) 1) (str=? (Str8 downcase (first l)) "none") #f) () (List map path l))))
    (def gateway (%yes? lines "gatewayports" #f))
    (def clear (%yes? lines "clearallforwardings" #f))
    (def forwards (fn (_ kw what) (if clear () (List map (fn (_ l) (%forward l gateway what)) (List filter (fn (_ l) (str=? (first l) kw)) lines)))))
    (def session (%choice lines "sessiontype" (list "default" "none" "subsystem") "default"))
    (list (pair (lit host) host) (pair (lit hostname) hostname) (pair (lit port) port) (pair (lit user) user)
          (pair (lit identities) (if (null? ids) (List map (fn (_ p) (pair (path p) #f)) (list "~/.ssh/id_rsa" "~/.ssh/id_ecdsa" "~/.ssh/id_ed25519")) (List map (fn (_ p) (pair (path p) #t)) ids)))
          (pair (lit known) (files "userknownhostsfile" (list "~/.ssh/known_hosts" "~/.ssh/known_hosts2")))
          (pair (lit global) (files "globalknownhostsfile" (list "/etc/ssh/ssh_known_hosts" "/etc/ssh/ssh_known_hosts2")))
          (pair (lit strict) (%choice lines "stricthostkeychecking" (list "yes" "no" "off" "ask" "accept-new") "ask"))
          (pair (lit alias) (%one lines "hostkeyalias" ()))
          (pair (lit batch) (%yes? lines "batchmode" #f))
          (pair (lit password) (%yes? lines "passwordauthentication" #t))
          (pair (lit agent) (%agent-socket (%one lines "identityagent" "SSH_AUTH_SOCK") path))
          (pair (lit identities-only) (%yes? lines "identitiesonly" #f))
          ; ForwardAgent yes forwards IdentityAgent's socket; a path or $NAME its own
          (pair (lit forward-agent)
                ((fn (_ v) (match ((str=? (Str8 downcase v) "yes") (%agent-socket (%one lines "identityagent" "SSH_AUTH_SOCK") path))
                                  ((str=? (Str8 downcase v) "no") ())
                                  (#t (%agent-socket v path))))
                 (%one lines "forwardagent" "no")))
          (pair (lit pubkey) (not (str=? (%choice lines "pubkeyauthentication" (list "yes" "no" "unbound" "host-bound") "yes") "no")))
          (pair (lit prompts) (%count lines "numberofpasswordprompts" 3))
          (pair (lit limits) (list (%seconds lines "serveraliveinterval" 0) (%count lines "serveralivecountmax" 3) (%channel-timeout lines)))
          (pair (lit gateway) gateway)
          (pair (lit forwards) (forwards "localforward" "Bad local forwarding specification"))
          (pair (lit remotes) (forwards "remoteforward" "Bad remote forwarding specification"))
          (pair (lit sendenv) (List flat-map (fn (_ a) a) (ssh-config-all lines "sendenv")))
          (pair (lit setenv) (List flat-map (fn (_ a) a) (ssh-config-all lines "setenv")))
          (pair (lit level) (%choice lines "loglevel" (list "quiet" "fatal" "error" "info" "verbose" "debug" "debug1" "debug2" "debug3") "info"))
          (pair (lit session) session)
          (pair (lit command) ((fn (_ c) (if (str=? (Str8 downcase c) "none") () c)) (%one lines "remotecommand" "none")))
          (pair (lit stdin-null) (%yes? lines "stdinnull" #f))
          (pair (lit tty) (%choice lines "requesttty" (list "no" "yes" "force" "auto") "auto")))))

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
                (Str8 append "gatewayports " (yn (%get s (lit gateway)))))
          (List map (fn (_ f) (Str8 append "localforward " (fwd f))) (%get s (lit forwards)))
          (List map (fn (_ f) (Str8 append "remoteforward " (fwd f))) (%get s (lit remotes)))
          (List map (fn (_ e) (Str8 append "sendenv " e)) (%get s (lit sendenv)))
          (List map (fn (_ e) (Str8 append "setenv " e)) (%get s (lit setenv)))
          (list (Str8 append "loglevel " (Str8 upcase (%get s (lit level))))
                (Str8 append "sessiontype " (%get s (lit session)))
                (Str8 append "stdinnull " (yn (%get s (lit stdin-null))))
                (Str8 append "requesttty " (%get s (lit tty))))
          (if (null? (%get s (lit command))) () (list (Str8 append "remotecommand " (%get s (lit command)))))
          (if (null? (%get s (lit alias))) () (list (Str8 append "hostkeyalias " (%get s (lit alias))))))))))

; --- the terminal ----------------------------------------------------------

; A secret asked for as OpenSSH's client asks, by ssh/ask's
; read_passphrase with the terminal required: () for none, and always
; in batch mode.
(def %ask-secret (fn (_ s text) (if (%get s (lit batch)) () (ssh-ask-secret text #f))))

; --- the host key ----------------------------------------------------------

(def %verification-failed (fn (_) (%say 2 "Host key verification failed.\n") #f))

; The host key algorithms offered, as OpenSSH orders them: those of the
; types known_hosts already holds for this host first, so a known host
; is not met by a key of another type; then the rest.  An ssh-rsa key is
; offered as rsa-sha2-512 and rsa-sha2-256.
(def %hostkey-order
  (fn (_ s)
    (def port (%get s (lit port)))
    (def name (ssh-known-name (if (null? (%get s (lit alias))) (%get s (lit hostname)) (%get s (lit alias))) port))
    (def known (List flat-map (fn (_ t) (if (str=? t "ssh-rsa") (list "rsa-sha2-512" "rsa-sha2-256") (list t)))
                 (ssh-known-types (List append (%get s (lit known)) (%get s (lit global))) name)))
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
    (def seen (ssh-known-check (List append known (%get s (lit global))) name key))
    (def strict (%get s (lit strict)))
    (def record!
      (fn (_)
        (unless (null? known)
          (guard (e (%say 2 (Str8 append "Failed to add the host to the list of known hosts (" (first known) ").\n")))
            (ssh-known-add! (first known) name key)
            (unless quiet
              (%say 2 (Str8 append "Warning: Permanently added '" name "' (" label ") to the list of known hosts.\n")))))
        #t))
    (match
      ((eq? (first seen) (lit known)) (do (unless (null? tr) (tr (Str8 append "Host '" name "' is known and matches the " label " host key."))) #t))
      ((eq? (first seen) (lit changed))
        (do (%say 2 (Str8 append
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
              "Host key for " name " has changed and you have requested strict checking.\n"))
            (%verification-failed)))
      ((str=? strict "yes")
        (do (%say 2 (Str8 append "No " label " host key is known for " name " and you have requested strict checking.\n"))
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
         (Str8 append "The authenticity of host '" name " (" (ssh-known-name addr port) ")' can't be established.\n"
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
                          (%say 2 (Str8 append "Warning: Identity file " (first i) " not accessible: No such file or directory.\n")))
                        ()))
                  (#t (guard (e (do (%say 2 (Str8 append "Load key \"" (first i) "\": " (%message e) "\n")) ()))
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
; asks nothing.
(def %open-identity
  (fn (_ s path tr)
    (def prompt (Str8 append "Enter passphrase for key '" path "': "))
    ((fn (self left)
       (if (if (= left 0) #t (%get s (lit batch))) ()
         (do (def typed (ssh-ask-secret prompt #f))
             (if (if (null? typed) #t (= (Str8 length typed) 0))
               (do (unless (null? tr) (tr "no passphrase given, try next key")) ())
               (guard (e (if (str=? (%message e) ssh-key-wrong-passphrase)
                           (do (unless (null? tr) (tr "bad passphrase given, try again...")) (self (- left 1)))
                           (do (%say 2 (Str8 append "Load key \"" path "\": " (%message e) "\n")) ())))
                 (ssh-identity-read-file path typed))))))
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
           (do (unless first-try (%say 2 "Permission denied, please try again.\n"))
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

; The connection made and the command run under settings s: its exit
; status, or 255.
(def %run
  (fn (_ s command stdio)
    (def level (%get s (lit level)))
    (def quiet (List any? (fn (_ l) (str=? l level)) (list "quiet" "fatal" "error")))
    (def tr (if (List any? (fn (_ l) (str=? l level)) (list "verbose" "debug" "debug1" "debug2" "debug3"))
              (fn (_ t) (%say 2 (Str8 append "debug1: " (%ms) " ms " t "\n")))
              ()))
    (def host (%get s (lit hostname)))
    (def port (%get s (lit port)))
    (def addr (%address host))
    (def fd (guard (e ()) (Socket tcp-connect addr port)))
    (if (null? fd)
      (do (%say 2 (Str8 append "ssh: connect to host " host " port " (%num port) ": Connection refused\n")) 255)
      (guard (e (do (%say 2 (match ((str=? (%message e) "keepalive") (Str8 append "Timeout, server " host " not responding.\n"))
                                    ((str=? (%message e) "idle") (Str8 append "Connection to " host " closed: the channels were idle past ChannelTimeout.\n"))
                                    (#t (Str8 append (%message e) "\n"))))
                    (guard (e2 ()) (Socket close fd))
                    255))
        (unless (null? tr) (tr (Str8 append "Connecting to " host " [" addr "] port " (%num port) ".")))
        (def c (ssh-open fd tr))
        (ssh-engines! c)
        (ssh-exchange-versions! c)
        (ssh-kex! c (%hostkey-order s))
        (if (not (%host-key-ok c s addr quiet tr))
          (do (Socket close fd) 255)
          (do (def ids (%identities s quiet tr))
              (def ok (%authenticate c s ids tr))
              (if (not (eq? ok #t))
                (do (%say 2 (Str8 append (%get s (lit user)) "@" host ": Permission denied (" (Str8 join "," ok) ").\n"))
                    (Socket close fd)
                    255)
                (do (unless (null? tr) (tr (Str8 append "Authenticated to " host " ([" addr "]:" (%num port) ").")))
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
                      (%say 2 "Pseudo-terminal will not be allocated because stdin is not a terminal.\r\n"))
                    (def term ((fn (_ t) (if (null? t) "" t)) (Sys getenv "TERM")))
                    (def saved (if (if tty? local-tty #f) (Term raw! %stdin) ()))
                    (def outcome
                      (guard (e (pair (lit failed) (%message e)))
                        (pair (lit status)
                          (ssh-session-run! c command
                            (if (if (%get s (lit stdin-null)) #t (if (null? command) (null? stdio) #f)) () %stdin)
                            (fn (_ buf start len) (File write 1 (ssh-copy buf start len) len))
                            (fn (_ buf start len) (File write 2 (ssh-copy buf start len) len))
                            (List map (fn (_ f) (pair (if (null? (first f)) () (%address (first f))) (rest f))) (%get s (lit forwards)))
                            (%get s (lit remotes))
                            (if (null? stdio) () (pair (%address (first stdio)) (rest stdio)))
                            (%get s (lit limits))
                            (%environment s)
                            (if tty? (list term (fn (_) (Term window %stdin))) ())
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
                      ((str=? (rest outcome) "keepalive") (do (%say 2 (Str8 append "Timeout, server " host " not responding.\n")) 255))
                      ((str=? (rest outcome) "idle") (do (%say 2 (Str8 append "Connection to " host " closed: the channels were idle past ChannelTimeout.\n")) 255))
                      (#t (do (%say 2 (Str8 append (rest outcome) "\n")) 255)))))))))))

; The client's plan done: (HOST COMMAND OPTIONS CONFIG STDIO PRINT).
; The configuration settled -- the options, the user's file (-F's, or
; ~/.ssh/config) and the system's, which -F leaves out -- and the
; connection made, or the settings printed.  The exit status.
(def ssh-client-main
  (fn (_ plan)
    (def host (first plan))
    (def local (%me))
    (guard (e (do (%say 2 (Str8 append (%message e) "\n")) 255))
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
        (do (List for-each (fn (_ f) (%say 2 (Str8 append f "\n"))) faults)
            (%say 2 (Str8 append "terminating, " (%num (List length faults)) " bad configuration options\n"))
            255)
        (do (def s (ssh-client-settings lines host local))
            (def stdio (if (null? (List ref 4 plan)) ()
                         ((fn (_ w) (def i (Str8 index-of ":" w))
                            (def p (if (null? i) () (%int-or-nil (Str8 sub (+ i 1) (- (Str8 length w) i 1) w))))
                            (if (if (null? i) #t (null? p)) (Err raise 'value "stdio forward specification must be host:port" ())
                              (pair (Str8 sub 0 i w) p)))
                          (List ref 4 plan))))
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
            (if (List ref 5 plan)
              (do (%say 1 (%print s)) 0)
              (%run s command stdio)))))))

(provide ssh/client ssh-client-main ssh-client-settings)
