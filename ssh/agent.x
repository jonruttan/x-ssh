; # x-ssh -- SSH on x-lang
;
; ## ssh/agent.x -- the authentication agent: ssh-agent, ssh-add, and its
; ## protocol from the client's end
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; OpenSSH's agent protocol (draft-miller-ssh-agent) on a unix-domain
; socket: each message a uint32 length, then a type byte and its fields.
; The agent keeps identities in memory and signs with them; ssh-add and
; the client ask it.  Served:
;
;   11 REQUEST_IDENTITIES     answered 12: uint32 n, then each key's
;                             string blob and string comment
;   13 SIGN_REQUEST           string blob, string data, uint32 flags;
;                             answered 14: string signature
;   17 ADD_IDENTITY           string type, the key's private fields,
;                             string comment
;   25 ADD_ID_CONSTRAINED     the same, then constraints: 1 and a uint32,
;                             the seconds it lives
;   18 REMOVE_IDENTITY        string blob
;   19 REMOVE_ALL_IDENTITIES
;   22 LOCK, 23 UNLOCK        string passphrase
;
; each answered 6 SUCCESS, or 5 FAILURE where it has no answer of its
; own -- an extension, a confirm constraint, a type not served among
; them.  A locked agent lists no keys, and signs and adds none.  Flags 2
; and 4 ask an RSA key for rsa-sha2-256 and rsa-sha2-512; neither, the
; SHA-1 ssh-rsa, is refused, as the client's signatures refuse it.
;
; The private fields are those of an OpenSSH key file's private section:
; Ed25519's public key and its 64-byte secret (seed, then public key);
; RSA's mpint n, e, d, iqmp, p, q; ECDSA's curve, point and mpint d.

(module ssh/agent)

(import x/sys/file)
(import x/sys/posix)
(import x/sys/socket)
(import x/sys/gc)
(import x/codec/base64)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-put-bytes ssh-put-string ssh-put-text ssh-put-mpint ssh-out-run
  ssh-in ssh-in-left ssh-in-buf ssh-get-byte ssh-get-uint32 ssh-get-string ssh-get-text ssh-copy)
(import ssh/pubkey ssh-pubkey-of ssh-pubkey-of-line ssh-pubkey-blob ssh-pubkey-type ssh-pubkey-label ssh-pubkey-bits
  ssh-pubkey-base64 ssh-identity-sign ssh-ecdsa-curve)
(import ssh/transport ssh-random)
(import ssh/sftp ssh-sftp-reader ssh-sftp-take! ssh-sftp-write-all)
(import ssh/keygen ssh-blob-fingerprint)
(import ssh/keys ssh-identity-read-file ssh-key-file-sealed? ssh-key-wrong-passphrase ssh-pubkey-of-key-file
  ssh-key-comment-of-file)
(import ssh/ask ssh-ask-secret)
(import ssh/sys ssh-sys-after-op)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %cvt (prim-ref (lit convert) (lit to)))
(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %ref (fn (_ v i) (%oref v (+ i 1))))
(def %set (fn (_ v i x) (%oset! v (+ i 1) x)))
(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))
(def %say (fn (_ fd t) (File write fd t (%byte-len t))))

(def %FAILURE 5) (def %SUCCESS 6)
(def %REQUEST-IDENTITIES 11) (def %IDENTITIES-ANSWER 12)
(def %SIGN-REQUEST 13) (def %SIGN-RESPONSE 14)
(def %ADD-IDENTITY 17) (def %REMOVE-IDENTITY 18) (def %REMOVE-ALL 19)
(def %LOCK 22) (def %UNLOCK 23) (def %ADD-CONSTRAINED 25)
(def %LIFETIME 1)
(def %RSA-SHA2-256 2) (def %RSA-SHA2-512 4)

; The longest message taken, OpenSSH's AGENT_MAX_LEN.
(def %max-message 262144)

; --- messages --------------------------------------------------------------------

; A message from a reader: (BUF . LEN), BUF its own bytes from the type
; byte on, or () when the peer is gone or sends past the limit.
(def %read-message
  (fn (_ r)
    (def h (ssh-sftp-take! r 4))
    (if (null? h) ()
      (do (def n (ssh-get-uint32 (ssh-in h 0 4)))
          (if (if (< n 1) #t (> n %max-message)) ()
            ((fn (_ body) (if (null? body) () (pair body n))) (ssh-sftp-take! r n)))))))

; Whether a reader holds bytes it has not handed out.
(def %buffered? (fn (_ r) (< (%ref r 2) (%ref r 3))))

; A message's body sent with its length before it.
(def %send!
  (fn (_ fd body)
    (def r (ssh-out-run body))
    (def out (ssh-out))
    (ssh-put-uint32 out (rest r))
    (ssh-put-bytes out (first r) 0 (rest r))
    (def m (ssh-out-run out))
    (ssh-sftp-write-all fd (first m) 0 (rest m))))

(def %code (fn (_ type) (def o (ssh-out)) (ssh-put-byte o type) o))

(def %put-region (fn (_ out r) (ssh-put-string out (first r) (List ref 1 r) (List ref 2 r))))

; Whether two regions hold the same bytes.
(def %same?
  (fn (_ a b)
    (if (not (= (List ref 2 a) (List ref 2 b))) #f
      ((fn (self i)
         (if (= i (List ref 2 a)) #t
           (if (= (%byte (first a) (+ (List ref 1 a) i)) (%byte (first b) (+ (List ref 1 b) i))) (self (+ i 1)) #f)))
       0))))

(def %same-key? (fn (_ k1 k2) (%same? (ssh-pubkey-blob k1) (ssh-pubkey-blob k2))))

; --- identities on the wire ----------------------------------------------------

(def %ecdsa-type? (fn (_ t) (List any? (fn (_ c) (str=? t (Str8 append "ecdsa-sha2-" c))) (list "nistp256" "nistp384" "nistp521"))))

; A key's private fields, as ADD_IDENTITY carries them from its type on,
; read from in over buf as an identity (KEY SECRET COMMENT): its public
; blob built from them, its secret ssh/pubkey's, regions of buf.
(def ssh-agent-read-identity
  (fn (_ in buf)
    (def type (ssh-get-text in))
    (def reg (fn (_ r) (list buf (first r) (rest r))))
    (def blob (ssh-out))
    (ssh-put-text blob type)
    (def secret
      (match
        ((str=? type "ssh-ed25519")
          (do (def pub (ssh-get-string in))
              (def sk (ssh-get-string in))
              (unless (if (= (rest pub) 32) (= (rest sk) 64) #f) (Err raise 'value "an Ed25519 key of the wrong size" ()))
              (ssh-put-string blob buf (first pub) 32)
              (ssh-copy buf (first sk) 32)))
        ((str=? type "ssh-rsa")
          (do (def n (ssh-get-string in)) (def e (ssh-get-string in)) (def d (ssh-get-string in))
              (def iqmp (ssh-get-string in)) (def p (ssh-get-string in)) (def q (ssh-get-string in))
              (ssh-put-string blob buf (first e) (rest e))
              (ssh-put-string blob buf (first n) (rest n))
              (list (reg n) (reg d) (reg e) (reg iqmp) (reg p) (reg q))))
        ((%ecdsa-type? type)
          (do (def curve (ssh-get-text in)) (def q (ssh-get-string in)) (def d (ssh-get-string in))
              (ssh-put-text blob curve)
              (ssh-put-string blob buf (first q) (rest q))
              (list (ssh-ecdsa-curve curve) (reg d))))
        (#t (Err raise 'value (Str8 append "a key of a type not served: " type) ()))))
    (def br (ssh-out-run blob))
    (list (ssh-pubkey-of (first br) 0 (rest br)) secret (ssh-get-text in))))

; An identity's private fields put as ADD_IDENTITY carries them, comment
; after.
(def %put-identity
  (fn (_ out id comment)
    (def key (first id))
    (def secret (List ref 1 id))
    (def mp (fn (_ r) (ssh-put-mpint out (first r) (List ref 1 r) (List ref 2 r))))
    (ssh-put-text out (ssh-pubkey-type key))
    (match
      ((eq? (first key) (lit ed25519))
        (do (def pub (List ref 2 key))
            (ssh-put-string out pub 0 32)
            (ssh-put-uint32 out 64)
            (ssh-put-bytes out secret 0 32)
            (ssh-put-bytes out pub 0 32)))
      ; (N D E IQMP P Q) as the wire orders them, n e d iqmp p q
      ((eq? (first key) (lit rsa))
        (List for-each (fn (_ i) (mp (List ref i secret))) (list 0 2 1 3 4 5)))
      (#t
        (do (ssh-put-text out (List ref 2 key))
            (%put-region out (List ref 3 key))
            (mp (List ref 1 secret)))))
    (ssh-put-text out comment)))

; --- the agent -------------------------------------------------------------------
;
; (KEYS LOCK DEBUG LIFE): KEYS a list of (IDENTITY . EXPIRY), EXPIRY the
; second the key lapses or (), the newest last; LOCK the passphrase it is
; locked under, or (); DEBUG whether -d traces; LIFE the seconds a key
; added without a lifetime lives, or ().

(def %agent
  (fn (_ debug life)
    (def a (Vector make 4 ()))
    (%set a 2 debug)
    (%set a 3 life)
    a))

(def %trace (fn (_ a t) (when (%ref a 2) (%say 2 (Str8 append t "\n")))))

; Keys past their lifetime dropped.
(def %expire!
  (fn (_ a)
    (def now (Sys now))
    (%set a 0 (List filter (fn (_ k) (if (null? (rest k)) #t (> (rest k) now))) (%ref a 0)))))

(def %find (fn (_ a blob) (List find (fn (_ k) (%same? (ssh-pubkey-blob (first (first k))) blob)) (%ref a 0))))
(def %without (fn (_ a blob) (List filter (fn (_ k) (not (%same? (ssh-pubkey-blob (first (first k))) blob))) (%ref a 0))))

; The algorithm a sign request's flags ask of a key, or () for one refused.
(def %sign-alg
  (fn (_ key flags)
    (match
      ((not (eq? (first key) (lit rsa))) (ssh-pubkey-type key))
      ((= (& flags %RSA-SHA2-512) %RSA-SHA2-512) "rsa-sha2-512")
      ((= (& flags %RSA-SHA2-256) %RSA-SHA2-256) "rsa-sha2-256")
      (#t ()))))

; A constrained add's constraints: the lifetime asked, () for none, or
; refused for one not served.
(def %constraints
  (fn (self in life)
    (if (= (ssh-in-left in) 0) life
      (if (= (ssh-get-byte in) %LIFETIME) (self in (ssh-get-uint32 in)) (lit refused)))))

; One request answered: the reply's body.
(def %answer
  (fn (_ a buf n)
    (def in (ssh-in buf 1 (- n 1)))
    (def type (%byte buf 0))
    (def locked (not (null? (%ref a 1))))
    (%expire! a)
    (%trace a (Str8 append "process_message: socket type " (%num type)))
    (match
      ((= type %REQUEST-IDENTITIES)
        (do (def keys (if locked () (%ref a 0)))
            (def out (%code %IDENTITIES-ANSWER))
            (ssh-put-uint32 out (List length keys))
            (List for-each
              (fn (_ k) (%put-region out (ssh-pubkey-blob (first (first k)))) (ssh-put-text out (List ref 2 (first k))))
              keys)
            out))
      ((= type %SIGN-REQUEST)
        (do (def kb (ssh-get-string in))
            (def data (ssh-get-string in))
            (def flags (ssh-get-uint32 in))
            (def k (if locked () (%find a (list buf (first kb) (rest kb)))))
            (def alg (if (null? k) () (%sign-alg (first (first k)) flags)))
            (if (null? alg) (%code %FAILURE)
              (do (def out (%code %SIGN-RESPONSE))
                  (%put-region out (ssh-identity-sign (first k) (list buf (first data) (rest data)) alg))
                  out))))
      ((if (= type %ADD-IDENTITY) #t (= type %ADD-CONSTRAINED))
        (if locked (%code %FAILURE)
          (do (def id (ssh-agent-read-identity in buf))
              (def life (%constraints in (%ref a 3)))
              (if (eq? life (lit refused)) (%code %FAILURE)
                (do (%set a 0 (List append (%without a (ssh-pubkey-blob (first id)))
                                (list (pair id (if (null? life) () (+ (Sys now) life))))))
                    (%code %SUCCESS))))))
      ((= type %REMOVE-IDENTITY)
        (do (def kb (ssh-get-string in))
            (def blob (list buf (first kb) (rest kb)))
            (if (if locked #t (null? (%find a blob))) (%code %FAILURE)
              (do (%set a 0 (%without a blob)) (%code %SUCCESS)))))
      ((= type %REMOVE-ALL)
        (if locked (%code %FAILURE) (do (%set a 0 ()) (%code %SUCCESS))))
      ((= type %LOCK)
        (do (def pass (ssh-get-text in))
            (if locked (%code %FAILURE) (do (%set a 1 pass) (%code %SUCCESS)))))
      ((= type %UNLOCK)
        (do (def pass (ssh-get-text in))
            (if (if locked (str=? pass (%ref a 1)) #f) (do (%set a 1 ()) (%code %SUCCESS)) (%code %FAILURE))))
      (#t (%code %FAILURE)))))

(def %signal (fn (_ name) ((fn (_ p) (if (null? p) () (rest p))) (List find (fn (_ s) (str=? (first s) name)) (Sys signals)))))

; The agent's loop on a listening socket: each client's requests answered
; in turn, a client gone or garbled closed.  Ends when TERM, HUP or INT
; arrives, or when parent -- a pid, or () -- is gone, looked for each ten
; seconds; answers the signal's number, or 0.
(def %serve
  (fn (_ a lfd parent)
    (def sigs (List filter (fn (_ s) (not (null? s))) (List map %signal (list "TERM" "HUP" "INT"))))
    (List for-each (fn (_ s) (Sys catch-signal s)) sigs)
    (unless (null? (%signal "PIPE")) (Sys signal (%signal "PIPE") (Sys sig-ign)))
    ; clients: (FD . READER)
    (def clients (Vector make 1 ()))
    (def drop! (fn (_ fd) (guard (e ()) (Socket close fd)) (%set clients 0 (List filter (fn (_ c) (not (= (first c) fd))) (%ref clients 0)))))
    ; each message the reader holds answered, the first read from the socket
    (def serve-one!
      (fn (self c)
        (def m (guard (e ()) (%read-message (rest c))))
        (if (null? m) (drop! (first c))
          (when (guard (e (do (%trace a (Str8 append "process_message: " (guard (x "a bad message") (e msg)))) (drop! (first c)) #f))
                  (%send! (first c) (%answer a (first m) (rest m)))
                  #t)
            (when (%buffered? (rest c)) (self c))))))
    ((fn (self served)
       (def got (List find (fn (_ s) (Sys take-signal s)) sigs))
       (match
         ((not (null? got)) got)
         ((if (null? parent) #f (< (Sys kill parent 0) 0)) 0)
         (#t
           (do (def ready (Sys poll (pair (pair lfd (list (lit in))) (List map (fn (_ c) (pair (first c) (list (lit in)))) (%ref clients 0)))
                                    (if (null? parent) -1 10000)))
               (List for-each
                 (fn (_ r)
                   (if (= (first r) lfd)
                     (do (def fd (guard (e ()) (Socket accept lfd)))
                         (unless (null? fd)
                           (do (%trace a (Str8 append "new_socket: type = CONNECTION, fd " (%num fd)))
                               (%set clients 0 (pair (pair fd (ssh-sftp-reader fd)) (%ref clients 0))))))
                     ((fn (_ c) (unless (null? c) (serve-one! c))) (List find (fn (_ c) (= (first c) (first r))) (%ref clients 0)))))
                 (if (null? ready) () ready))
               (when (> served 31) (Heap collect))
               (self (if (> served 31) 0 (+ served 1)))))))
     0)))

; --- the client's end ----------------------------------------------------------

(def %unset? (fn (_ v) (if (null? v) #t (= (Str8 length v) 0))))

; A connection to the agent at path, or at SSH_AUTH_SOCK's when path is
; (): its fd, or a raise in OpenSSH's words -- none when neither names
; one, its data (none . #t).
(def ssh-agent-connect
  (fn (_ path)
    (def p (if (null? path) (Sys getenv "SSH_AUTH_SOCK") path))
    (if (%unset? p)
      (Err raise 'agent "Could not open a connection to your authentication agent." (list (pair (lit none) #t)))
      (guard (e (Err raise 'agent (Str8 append "Error connecting to agent: " (ssh-sys-after-op (guard (x "Connection refused") (e msg)))) ()))
        (Socket unix-connect p)))))

; A request sent and its reply: (TYPE . IN), IN a reader over its fields.
(def %ask
  (fn (_ fd body)
    (%send! fd body)
    (def m (%read-message (ssh-sftp-reader fd)))
    (when (null? m) (Err raise 'agent "agent: the connection closed" ()))
    (pair (%byte (first m) 0) (ssh-in (first m) 1 (- (rest m) 1)))))

; The agent's keys: each (KEY COMMENT), a type not served passed over.
(def ssh-agent-identities
  (fn (_ fd)
    (def r (%ask fd (%code %REQUEST-IDENTITIES)))
    (unless (= (first r) %IDENTITIES-ANSWER) (Err raise 'agent "agent refused operation" ()))
    (def in (rest r))
    ((fn (self k acc)
       (if (= k 0) (List reverse acc)
         (do (def b (ssh-get-string in))
             (def key (guard (e ()) (ssh-pubkey-of (ssh-copy (ssh-in-buf in) (first b) (rest b)) 0 (rest b))))
             (def comment (ssh-get-text in))
             (self (- k 1) (if (null? key) acc (pair (list key comment) acc))))))
     (ssh-get-uint32 in) ())))

; A signature by the agent's key over data's region, with alg: the
; signature blob's region, or a raise.
(def ssh-agent-sign
  (fn (_ fd key data alg)
    (def out (%code %SIGN-REQUEST))
    (%put-region out (ssh-pubkey-blob key))
    (%put-region out data)
    (ssh-put-uint32 out (match ((str=? alg "rsa-sha2-512") %RSA-SHA2-512) ((str=? alg "rsa-sha2-256") %RSA-SHA2-256) (#t 0)))
    (def r (%ask fd out))
    (unless (= (first r) %SIGN-RESPONSE) (Err raise 'agent "agent refused operation" ()))
    (def s (ssh-get-string (rest r)))
    (list (ssh-in-buf (rest r)) (first s) (rest s))))

; An agent's key as an identity ssh-identity-sign signs with: its secret
; (agent . SIGNER), the agent asked.
(def ssh-agent-identity
  (fn (_ fd key comment)
    (list key (pair (lit agent) (fn (_ data alg) (ssh-agent-sign fd key data alg))) comment)))

; A request answered SUCCESS or FAILURE: whether it succeeded.
(def %ok? (fn (_ fd body) (= (first (%ask fd body)) %SUCCESS)))

(def ssh-agent-add?
  (fn (_ fd id comment life)
    (def out (%code (if (null? life) %ADD-IDENTITY %ADD-CONSTRAINED)))
    (%put-identity out id comment)
    (unless (null? life) (do (ssh-put-byte out %LIFETIME) (ssh-put-uint32 out life)))
    (%ok? fd out)))

(def ssh-agent-remove?
  (fn (_ fd key)
    (def out (%code %REMOVE-IDENTITY))
    (%put-region out (ssh-pubkey-blob key))
    (%ok? fd out)))

(def ssh-agent-remove-all? (fn (_ fd) (%ok? fd (%code %REMOVE-ALL))))

(def ssh-agent-lock?
  (fn (_ fd lock pass)
    (def out (%code (if lock %LOCK %UNLOCK)))
    (ssh-put-text out pass)
    (%ok? fd out)))

; --- times -----------------------------------------------------------------------

; A time as OpenSSH's convtime reads it -- numbers, each with an optional
; unit s, m, h, d or w, 90 or 1h30m -- in seconds, or () for one that
; does not read.
(def %units (list (pair 115 1) (pair 109 60) (pair 104 3600) (pair 100 86400) (pair 119 604800)))
(def ssh-agent-seconds
  (fn (_ t)
    (def n (%byte-len t))
    (if (= n 0) ()
      ((fn (self i num had total)
         (if (= i n) (+ total num)
           (do (def c (%byte t i))
               (def u (List find (fn (_ p) (= (first p) (| c 32))) %units))
               (match
                 ((if (>= c 48) (<= c 57) #f) (self (+ i 1) (+ (* num 10) (- c 48)) #t total))
                 ((if had (not (null? u)) #f) (self (+ i 1) 0 #f (+ total (* num (rest u)))))
                 (#t ())))))
       0 0 #f 0))))

(def %two (fn (_ n) (if (< n 10) (Str8 append "0" (%num n)) (%num n))))

; Seconds as OpenSSH's fmt_timeframe writes them: 00:00:01 within a day,
; 1d02h03m within a week, 01w2d03h past it.
(def %timeframe
  (fn (_ s)
    (def m (/ s 60)) (def h (/ s 3600)) (def d (/ s 86400)) (def w (/ s 604800))
    (match
      ((< s 86400) (Str8 append (%two h) ":" (%two (% m 60)) ":" (%two (% s 60))))
      ((< s 604800) (Str8 append (%num d) "d" (%two (% h 24)) "h" (%two (% m 60)) "m"))
      (#t (Str8 append (%two w) "w" (%num (% d 7)) "d" (%two (% h 24)) "h")))))

; --- ssh-agent -------------------------------------------------------------------

(def %letters "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
(def %random-name
  (fn (_ n)
    (def r (ssh-random n))
    ((fn (self i acc) (if (= i n) acc (self (+ i 1) (Str8 append acc (Str8 sub (% (%byte r i) 62) 1 %letters))))) 0 "")))

; The socket OpenSSH makes when -a names none: ~/.ssh/agent/s.R.agent.R,
; the directory made, private, when it is missing.
(def %default-socket
  (fn (_)
    (def ssh (Str8 append (Sys getenv "HOME") "/.ssh"))
    (def dir (Str8 append ssh "/agent"))
    (unless (eq? (File type ssh) (lit dir)) (File mkdir ssh 448))
    (unless (eq? (File type dir) (lit dir)) (File mkdir dir 448))
    (Str8 append dir "/s." (%random-name 10) ".agent." (%random-name 10))))

; The lines that set the agent's variables, in sh's or csh's words; pid
; the agent's, () for no SSH_AGENT_PID, only its echo.
(def %env-lines
  (fn (_ csh path pid shown)
    (def set (fn (_ name v) (if csh (Str8 append "setenv " name " " v ";\n") (Str8 append name "=" v "; export " name ";\n"))))
    (Str8 append (set "SSH_AUTH_SOCK" path)
                 (if (null? pid) "" (set "SSH_AGENT_PID" (%num pid)))
                 "echo Agent pid " (%num shown) ";\n")))

; -k: the agent SSH_AGENT_PID names ended, and the lines that unset its
; variables.
(def %kill-agent
  (fn (_ csh)
    (def v (Sys getenv "SSH_AGENT_PID"))
    (def pid (if (%unset? v) () (guard (e ()) (%cvt v (Type named INTEGER) 10))))
    (match
      ((%unset? v) (do (%say 2 "SSH_AGENT_PID not set, cannot kill agent\n") 1))
      ((if (null? pid) #t (< pid 1)) (do (%say 2 (Str8 append "SSH_AGENT_PID=\"" v "\", which is not a good PID: invalid\n")) 1))
      ((< (Sys kill pid (%signal "TERM")) 0) (do (%say 2 "kill: No such process\n") 1))
      (#t (do (%say 1 (Str8 append (if csh "unsetenv SSH_AUTH_SOCK;\nunsetenv SSH_AGENT_PID;\n" "unset SSH_AUTH_SOCK;\nunset SSH_AGENT_PID;\n")
                                  "echo Agent pid " (%num pid) " killed;\n"))
              0)))))

(def %setsid! (fn (_) ((prim-ref (lit ptr) (lit call)) ((prim-ref (lit ffi) (lit dlsym)) ((prim-ref (lit ffi) (lit dlopen)) () 1) "setsid"))))

; The standard descriptors on /dev/null, as a daemon's are.
(def %quiet!
  (fn (_)
    (def null (File open "/dev/null" (lit rdwr)))
    (unless (< null 0)
      (do (Sys dup2 null 0) (Sys dup2 null 1) (Sys dup2 null 2)
          (when (> null 2) (File close null))))))

; The agent served until its end, its socket then removed; the status.
(def %run-agent
  (fn (_ a lfd path parent loud)
    (def sig (%serve a lfd parent))
    (guard (e ()) (Socket close lfd))
    (File unlink path)
    (when (if loud (> sig 0) #f) (%say 2 (Str8 append "exiting on signal " (%num sig) "\n")))
    0))

; ssh-agent's line done: (MODE CSH SOCKET LIFE COMMAND), MODE kill,
; daemon, foreground (-D), debug (-d) or command; LIFE seconds or ().
(def ssh-agent-main
  (fn (_ what)
    (def mode (List ref 0 what))
    (def csh (List ref 1 what))
    (def given (List ref 2 what))
    (def life (List ref 3 what))
    (def command (List ref 4 what))
    (if (eq? mode (lit kill)) (%kill-agent csh)
      (do (def path (if (null? given) (%default-socket) given))
          (def full (if (= (%byte path 0) 47) path (Str8 append (Sys getcwd) "/" path)))
          (def lfd
            (if (> (%byte-len path) 103)
              (do (%say 2 (Str8 append "unix_listener: path \"" path "\" too long for Unix domain socket\r\n")) ())
              (guard (e (do (%say 2 (Str8 append "unix_listener: cannot bind to path " path ": " (ssh-sys-after-op (guard (x "failed") (e msg))) "\r\n")) ()))
                (Socket unix-listen path 128))))
          (if (null? lfd) 1
            (do (File chmod path 384)
                (def a (%agent (eq? mode (lit debug)) life))
                (Heap collect)
                (match
                  ((if (eq? mode (lit foreground)) #t (eq? mode (lit debug)))
                    (do (%say 1 (%env-lines csh path () (Sys getpid)))
                        (%run-agent a lfd full () #t)))
                  ((eq? mode (lit command))
                    (do (def parent (Sys getpid))
                        (def pid (Sys fork))
                        (if (= pid 0)
                          (do (%setsid!) (Sys chdir "/") (%quiet!)
                              (Sys exit (%run-agent a lfd full parent #f)))
                          (do (Socket close lfd)
                              (Sys setenv "SSH_AUTH_SOCK" path)
                              (Sys setenv "SSH_AGENT_PID" (%num pid))
                              (Sys exec (first command) (rest command))
                              (%say 2 (Str8 append (first command) ": No such file or directory\n"))
                              1))))
                  (#t
                    (do (def pid (Sys fork))
                        (if (= pid 0)
                          (do (%setsid!) (Sys chdir "/") (%quiet!)
                              (Sys exit (%run-agent a lfd full () #f)))
                          (do (%say 1 (%env-lines csh path pid pid)) 0)))))))))))

; --- ssh-add ---------------------------------------------------------------------

(def %default-keys (list "id_rsa" "id_ecdsa" "id_ecdsa_sk" "id_ed25519" "id_ed25519_sk"))

; A key file opened as ssh-add opens it: with no passphrase, then asking
; for one until it opens or the answer is empty.  The identity, or ().
(def %open-file
  (fn (_ path)
    (def try (fn (_ pass) (guard (e (if (str=? (guard (x "") (e msg)) ssh-key-wrong-passphrase) (lit wrong) (error e)))
                            (ssh-identity-read-file path pass))))
    (if (not (ssh-key-file-sealed? path)) (try "")
      ((fn (self prompt)
         (def typed (ssh-ask-secret prompt #t))
         (if (%unset? typed) ()
           ((fn (_ id) (if (eq? id (lit wrong)) (self (Str8 append "Bad passphrase, try again for " path ": ")) id)) (try typed))))
       (Str8 append "Enter passphrase for " path ": ")))))

; One key file added; whether it was.
(def %add-file
  (fn (_ fd path life quiet)
    (if (not (File exists? path))
      (do (%say 2 (Str8 append path ": No such file or directory\n")) #f)
      (do (def id (guard (e (do (%say 2 (Str8 append "Error loading key \"" path "\": invalid format\n")) (lit bad)))
                    (%open-file path)))
          (match
            ((eq? id (lit bad)) #f)
            ((null? id) #f)
            (#t
              (do (def comment (if (%unset? (List ref 2 id)) path (List ref 2 id)))
                  (if (ssh-agent-add? fd id comment life)
                    (do (unless quiet
                          (do (%say 2 (Str8 append "Identity added: " path " (" comment ")\n"))
                              (unless (null? life) (%say 2 (Str8 append "Lifetime set to " (%timeframe life) "\n")))))
                        #t)
                    (do (%say 2 (Str8 append "Could not add identity \"" path "\": agent refused operation\n")) #f)))))))))

; A key file's public key and comment, as ssh-add -d reads it: from
; PATH.pub when there is one, else from the key file.
(def %public-of
  (fn (_ path)
    (def pub (Str8 append path ".pub"))
    (if (File exists? pub)
      (do (def fd (File open pub (lit rdonly)))
          (def buf ((prim-ref (lit str) (lit make)) 16384))
          (def n (File read fd buf 16384))
          (File close fd)
          (def line (first (Str8 split "\n" (Str8 sub 0 n buf))))
          (def ws (List filter (fn (_ w) (> (Str8 length w) 0)) (Str8 split " " line)))
          (pair (ssh-pubkey-of-line (first ws) (List ref 1 ws)) (Str8 join " " (List drop 2 ws))))
      (pair (ssh-pubkey-of-key-file path)
            (if (ssh-key-file-sealed? path) "" (guard (e "") (ssh-key-comment-of-file path)))))))

(def %remove-file
  (fn (_ fd path quiet)
    (def p (guard (e ()) (%public-of path)))
    (match
      ((if (null? p) #t (null? (first p)))
        (do (%say 2 (Str8 append "Bad key file " path "\n")) #f))
      ((ssh-agent-remove? fd (first p))
        (do (unless quiet (%say 2 (Str8 append "Identity removed: " path " " (ssh-pubkey-label (first p)) " (" (rest p) ")\n"))) #t))
      (#t (do (%say 2 (Str8 append "Could not remove identity \"" path "\": agent refused operation\n")) #f)))))

; -l and -L: each key's fingerprint line or public line.
(def %list
  (fn (_ fd public)
    (def keys (ssh-agent-identities fd))
    (if (null? keys) (do (%say 1 "The agent has no identities.\n") 1)
      (do (List for-each
            (fn (_ k)
              (def key (first k))
              (def comment (if (%unset? (List ref 1 k)) "no comment" (List ref 1 k)))
              (%say 1 (if public
                        (Str8 append (ssh-pubkey-type key) " " (ssh-pubkey-base64 key) " " (List ref 1 k) "\n")
                        (Str8 append (%num (ssh-pubkey-bits key)) " " (ssh-blob-fingerprint (ssh-pubkey-blob key)) " " comment
                                     " (" (ssh-pubkey-label key) ")\n"))))
            keys)
          0))))

; -x and -X: the agent locked or unlocked under a password asked for.
(def %lock
  (fn (_ fd lock)
    (def p1 (ssh-ask-secret "Enter lock password: " #t))
    (def p2 (if (if lock (not (null? p1)) #f) (ssh-ask-secret "Again: " #t) p1))
    (match
      ((null? p1) 1)
      ((not (str=? p1 (if (null? p2) "" p2))) (do (%say 2 "Passwords do not match.\n") 1))
      ((ssh-agent-lock? fd lock p1) (do (%say 2 (if lock "Agent locked.\n" "Agent unlocked.\n")) 0))
      (#t (do (%say 2 (if lock "Failed to lock agent.\n" "Failed to unlock agent.\n")) 1)))))

; ssh-add's line done: (ACTION FILES LIFE QUIET), ACTION add, delete,
; delete-all, list, public, lock or unlock.
(def ssh-add-main
  (fn (_ what)
    (def action (List ref 0 what))
    (def files (List ref 1 what))
    (def life (List ref 2 what))
    (def quiet (List ref 3 what))
    (def fd (guard (e (do (%say 2 (Str8 append (guard (x "agent") (e msg)) "\n")) ())) (ssh-agent-connect ())))
    (if (null? fd) 2
      (match
        ((eq? action (lit list)) (%list fd #f))
        ((eq? action (lit public)) (%list fd #t))
        ((eq? action (lit lock)) (%lock fd #t))
        ((eq? action (lit unlock)) (%lock fd #f))
        ((eq? action (lit delete-all))
          (if (ssh-agent-remove-all? fd)
            (do (unless quiet (%say 2 "All identities removed.\n")) 0)
            (do (%say 2 "Failed to remove all identities.\n") 1)))
        (#t
          (do (def home (Str8 append (Sys getenv "HOME") "/.ssh/"))
              (def paths (if (null? files) (List filter File exists? (List map (fn (_ f) (Str8 append home f)) %default-keys)) files))
              (def one (if (eq? action (lit delete)) (fn (_ p) (%remove-file fd p quiet)) (fn (_ p) (%add-file fd p life quiet))))
              (def ok (List map one paths))
              (if (if (null? ok) #f (List all? (fn (_ x) x) ok)) 0 1)))))))

(provide ssh/agent ssh-agent-read-identity ssh-agent-connect ssh-agent-identities ssh-agent-sign ssh-agent-identity
  ssh-agent-add? ssh-agent-remove? ssh-agent-remove-all? ssh-agent-lock? ssh-agent-seconds ssh-agent-main ssh-add-main)
