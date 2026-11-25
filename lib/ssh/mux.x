; # x-ssh -- SSH on x-lang
;
; ## lib/ssh/mux.x -- connection sharing: OpenSSH's multiplexing protocol
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; OpenSSH's PROTOCOL.mux, version 4, as its ControlMaster speaks it on a
; Unix socket: each message a uint32 length, then a uint32 type and its
; fields in the SSH wire form.  Each end sends HELLO first.  A request
; names an id its reply names again.  A session's standard input,
; output and error, and -W's input and output, go to the master after
; the request, each a descriptor in a message of its own (SCM_RIGHTS).
;
; Here are the messages, their reading and writing, and the client's
; requests: an alive check, a terminate, a stop of the listener, a
; forward opened or closed, a session or -W stdio forward the
; master carries, its exit status the client's, proxy mode, after
; which the socket carries the connection protocol itself (see
; ssh-open-mux in ssh/transport), and OpenSSH's "info" extension, the
; master's words on the connection or its channels.  The master's half
; is the session loop's (ssh/session).

(module ssh/mux)

(import x/sys/file)
(import x/sys/socket)
(import ssh/sys ssh-sys-send-fd ssh-sys-recv-fd)
(import ssh/bytes ssh-out ssh-put-uint32 ssh-put-text ssh-put-string ssh-out-run
  ssh-in ssh-in-left ssh-get-uint32 ssh-get-text ssh-copy)
(import x/core/doors str-make str-byte-len)

(def ssh-mux-version 4)

(def ssh-mux-hello 1)
(def ssh-mux-new-session 268435458)       ; 0x10000002
(def ssh-mux-alive-check 268435460)       ; 0x10000004
(def ssh-mux-terminate 268435461)         ; 0x10000005
(def ssh-mux-open-fwd 268435462)          ; 0x10000006
(def ssh-mux-close-fwd 268435463)         ; 0x10000007
(def ssh-mux-new-stdio-fwd 268435464)     ; 0x10000008
(def ssh-mux-stop-listening 268435465)    ; 0x10000009
(def ssh-mux-proxy 268435471)             ; 0x1000000f
(def ssh-mux-ok 2147483649)               ; 0x80000001
(def ssh-mux-permission-denied 2147483650) ; 0x80000002
(def ssh-mux-failure 2147483651)          ; 0x80000003
(def ssh-mux-exit-message 2147483652)     ; 0x80000004
(def ssh-mux-alive 2147483653)            ; 0x80000005
(def ssh-mux-session-opened 2147483654)   ; 0x80000006
(def ssh-mux-remote-port 2147483655)      ; 0x80000007
(def ssh-mux-tty-alloc-fail 2147483656)   ; 0x80000008
(def ssh-mux-s-proxy 2147483663)          ; 0x8000000f
(def ssh-mux-ext-info 536870913)          ; 0x20000001
(def ssh-mux-s-ext-info 2415919105)       ; 0x90000001

; --- messages --------------------------------------------------------------

; A message of type t, its fields put by the caller after.
(def ssh-mux-message
  (fn (_ t)
    (def out (ssh-out))
    (ssh-put-uint32 out t)
    out))

; A message written to fd whole, its length first: #t, or #f when the
; other end has gone.
(def ssh-mux-send!
  (fn (_ fd out)
    (def r (ssh-out-run out))
    (def framed (ssh-out))
    (ssh-put-string framed (first r) 0 (rest r))
    (def f (ssh-out-run framed))
    (guard (e #f)
      ((fn (self at)
         (if (= at (rest f)) #t
           (do (def n (File write fd (ssh-copy (first f) at (- (rest f) at)) (- (rest f) at)))
               (if (< n 1) #f (self (+ at n))))))
       0))))

; The next message read from fd: (TYPE . READER), the reader at the
; field after the type, or () when the other end has gone.
(def ssh-mux-receive
  (fn (_ fd)
    (def head (%read fd 4))
    (if (null? head) ()
      (do (def n (ssh-get-uint32 (ssh-in head 0 4)))
          (def body (if (< n 4) () (%read fd n)))
          (if (null? body) ()
            (do (def in (ssh-in body 0 n))
                (pair (ssh-get-uint32 in) in)))))))

; n bytes read from fd into one buffer: it, or () when fd ends first.
(def %read
  (fn (_ fd n)
    ((fn (self acc have)
       (if (= have n) (ssh-join-texts (List reverse acc))
         (do (def buf (str-make (- n have)))
             (def got (guard (e 0) (File read fd buf (- n have))))
             (if (< got 1) ()
               (self (pair (if (= got (- n have)) buf (Str8 sub 0 got buf)) acc) (+ have got))))))
     () 0)))

(def ssh-join-texts (fn (_ ts) (Str8 join "" ts)))

; HELLO, version 4: the client's with no extensions, as OpenSSH's
; client sends it; the master's with "info", its value "0", as
; OpenSSH's master sends it.
(def ssh-mux-hello-message
  (fn (_)
    (def m (ssh-mux-message ssh-mux-hello))
    (ssh-put-uint32 m ssh-mux-version)
    m))

(def ssh-mux-master-hello
  (fn (_)
    (def m (ssh-mux-hello-message))
    (ssh-put-text m "info")
    (ssh-put-text m "0")
    m))

; EXT_INFO's reply: (STATUS . TEXT), STATUS 1 for words given and 0 for
; a name not served.
(def ssh-mux-reply-info
  (fn (_ rid status text)
    (def m (ssh-mux-message ssh-mux-s-ext-info))
    (ssh-put-uint32 m rid)
    (ssh-put-uint32 m status)
    (ssh-put-text m text)
    m))

; A reply naming rid: OK, or a refusal of type t with its reason.
(def ssh-mux-reply-ok
  (fn (_ rid)
    (def m (ssh-mux-message ssh-mux-ok))
    (ssh-put-uint32 m rid)
    m))

(def ssh-mux-reply-error
  (fn (_ t rid reason)
    (def m (ssh-mux-message t))
    (ssh-put-uint32 m rid)
    (ssh-put-text m reason)
    m))

; Two uint32 fields after the type: ALIVE (rid pid), SESSION_OPENED (rid
; sid), EXIT_MESSAGE (sid status).
(def ssh-mux-reply-two
  (fn (_ t a b)
    (def m (ssh-mux-message t))
    (ssh-put-uint32 m a)
    (ssh-put-uint32 m b)
    m))

; A NEW_SESSION request read past its id: (TTY? AGENT? SUBSYSTEM? ESCAPE
; TERM COMMAND ENV), ESCAPE () for none, ENV its NAME=VALUE strings.
(def ssh-mux-session-request
  (fn (_ in)
    (ssh-get-text in)
    (def tty (not (= (ssh-get-uint32 in) 0)))
    (ssh-get-uint32 in)
    (def agent (not (= (ssh-get-uint32 in) 0)))
    (def sub (not (= (ssh-get-uint32 in) 0)))
    (def esc (ssh-get-uint32 in))
    (def term (ssh-get-text in))
    (def command (ssh-get-text in))
    (def env ((fn (self acc) (if (= (ssh-in-left in) 0) (List reverse acc) (self (pair (ssh-get-text in) acc)))) ()))
    (list tty agent sub (if (= esc 4294967295) () esc) term command env)))

; --- the client's end --------------------------------------------------------

; The master's socket at path, connected: the descriptor, or (failed .
; WORDS), the system's words for why not.
(def ssh-mux-connect
  (fn (_ path)
    (guard (e (pair (lit failed) (e msg)))
      (Socket unix-connect path))))

; HELLO each way: (hello . NAMES), NAMES the extensions the master's
; names, or the words of a refusal.
(def ssh-mux-greet!
  (fn (_ fd)
    (if (not (ssh-mux-send! fd (ssh-mux-hello-message))) "master hello exchange failed"
      (do (def m (ssh-mux-receive fd))
          (match
            ((null? m) "master hello exchange failed")
            ((not (= (first m) ssh-mux-hello)) "master hello exchange failed")
            (#t (do (def in (rest m))
                    (def v (ssh-get-uint32 in))
                    (if (= v ssh-mux-version)
                      (pair (lit hello)
                            ((fn (self acc)
                               (if (= (ssh-in-left in) 0) (List reverse acc)
                                 (do (def name (ssh-get-text in)) (ssh-get-text in) (self (pair name acc)))))
                             ()))
                      (Str8 append "Unsupported multiplexing protocol version " (%num v)
                                   " (expected " (%num ssh-mux-version) ")")))))))))

(def %num (fn (_ n) ((prim-ref (lit convert) (lit to)) n (Type named STRING) 10)))

; A request of type t with id rid and nothing more, its reply read:
; (TYPE . READER) past the id, or () when the master has gone.
(def %ask
  (fn (_ fd t rid)
    (def m (ssh-mux-message t))
    (ssh-put-uint32 m rid)
    (if (not (ssh-mux-send! fd m)) ()
      (do (def r (ssh-mux-receive fd))
          (if (null? r) () (do (ssh-get-uint32 (rest r)) r))))))

; ALIVE_CHECK: the master's pid, or ().
(def ssh-mux-alive?
  (fn (_ fd rid)
    (def r (%ask fd ssh-mux-alive-check rid))
    (if (if (null? r) #f (= (first r) ssh-mux-alive)) (ssh-get-uint32 (rest r)) ())))

; TERMINATE or STOP_LISTENING: #t for OK, (denied . REASON), (failed .
; REASON), or () when the master has gone.
(def ssh-mux-command
  (fn (_ fd t rid)
    (def r (%ask fd t rid))
    (match
      ((null? r) ())
      ((= (first r) ssh-mux-ok) #t)
      ((= (first r) ssh-mux-permission-denied) (pair (lit denied) (ssh-get-text (rest r))))
      ((= (first r) ssh-mux-failure) (pair (lit failed) (ssh-get-text (rest r))))
      (#t ()))))

; PROXY: #t when the master answers PROXY, the socket in proxy mode from
; then on; otherwise as a command's.
(def ssh-mux-proxy!
  (fn (_ fd rid)
    (def r (%ask fd ssh-mux-proxy rid))
    (match
      ((null? r) ())
      ((= (first r) ssh-mux-s-proxy) #t)
      ((= (first r) ssh-mux-permission-denied) (pair (lit denied) (ssh-get-text (rest r))))
      ((= (first r) ssh-mux-failure) (pair (lit failed) (ssh-get-text (rest r))))
      (#t ()))))

; EXT_INFO for name, "connection" or "channels": the master's words, or
; (error . REASON) when it answers another way, or () when it has gone.
; Its status is not looked at, as OpenSSH's client does not look.
(def ssh-mux-info
  (fn (_ fd rid name)
    (def m (ssh-mux-message ssh-mux-ext-info))
    (ssh-put-uint32 m rid)
    (ssh-put-text m name)
    (if (not (ssh-mux-send! fd m)) ()
      (do (def r (ssh-mux-receive fd))
          (match
            ((null? r) ())
            ((not (= (first r) ssh-mux-s-ext-info))
              (do (ssh-get-uint32 (rest r))
                  (pair (lit error) (if (= (ssh-in-left (rest r)) 0) "" (ssh-get-text (rest r))))))
            (#t (do (ssh-get-uint32 (rest r)) (ssh-get-uint32 (rest r)) (ssh-get-text (rest r)))))))))

; A session asked of the master: NEW_SESSION with tty?, agent?, sub?,
; the escape character (() for none), term, the command and env's
; NAME=VALUE strings; then the three descriptors.  The reply: (opened .
; SID), (denied . REASON), (failed . REASON), or () when the master has
; gone.
(def ssh-mux-open-session
  (fn (_ fd rid tty agent sub esc term command env in out err)
    (def m (ssh-mux-message ssh-mux-new-session))
    (ssh-put-uint32 m rid)
    (ssh-put-text m "")
    (ssh-put-uint32 m (if tty 1 0))
    (ssh-put-uint32 m 0)
    (ssh-put-uint32 m (if agent 1 0))
    (ssh-put-uint32 m (if sub 1 0))
    (ssh-put-uint32 m (if (null? esc) 4294967295 esc))
    (ssh-put-text m term)
    (ssh-put-text m command)
    (List for-each (fn (_ e) (ssh-put-text m e)) env)
    (%opened fd rid m (list in out err))))

; -W asked of the master: NEW_STDIO_FWD to host and port -- the port a
; uint32, as OpenSSH sends it, not the string PROTOCOL.mux says -- then in and
; out; the reply as a session's.
(def ssh-mux-open-stdio
  (fn (_ fd rid host port in out)
    (def m (ssh-mux-message ssh-mux-new-stdio-fwd))
    (ssh-put-uint32 m rid)
    (ssh-put-text m "")
    (ssh-put-text m host)
    (ssh-put-uint32 m port)
    (%opened fd rid m (list in out))))

(def %opened
  (fn (_ fd rid m fds)
    (if (if (ssh-mux-send! fd m) (List all? (fn (_ d) (ssh-sys-send-fd fd d)) fds) #f)
      (do (def r (ssh-mux-receive fd))
          (match
            ((null? r) ())
            (#t (do (ssh-get-uint32 (rest r))
                    (match
                      ((= (first r) ssh-mux-session-opened) (pair (lit opened) (ssh-get-uint32 (rest r))))
                      ((= (first r) ssh-mux-permission-denied) (pair (lit denied) (ssh-get-text (rest r))))
                      ((= (first r) ssh-mux-failure) (pair (lit failed) (ssh-get-text (rest r))))
                      (#t ()))))))
      ())))

; The session's end waited for: its exit status, or () when the master
; closed without one; on-tty-fail called on TTY_ALLOC_FAIL.
(def ssh-mux-wait
  (fn (_ fd sid on-tty-fail)
    ((fn (self status)
       (def r (ssh-mux-receive fd))
       (match
         ((null? r) status)
         ((= (first r) ssh-mux-exit-message)
           (do (ssh-get-uint32 (rest r)) (self (ssh-get-uint32 (rest r)))))
         ((= (first r) ssh-mux-tty-alloc-fail) (do (on-tty-fail) (self status)))
         (#t (self status))))
     ())))

; --- forwards ------------------------------------------------------------------
;
; A forward on the wire is (TYPE LHOST LPORT CHOST CPORT), as OpenSSH's
; mux_client_forward sends it: LHOST "" for no address given, "*" for
; every interface, or the address; a socket's path in place of a host
; with its port ssh-mux-streamlocal; a dynamic forward's CHOST "" and
; CPORT 0.  The same forward asked twice is the same list.

(def ssh-mux-fwd-local 1)
(def ssh-mux-fwd-remote 2)
(def ssh-mux-fwd-dynamic 3)
(def ssh-mux-streamlocal 4294967294)       ; (u_int) -2

; The wire form of a forward of type t as the client's settings hold
; one, (ADDRESS PORT HOST PORT GIVEN LPATH CPATH), HOST #f or () for a
; dynamic one's.
(def ssh-mux-forward-key
  (fn (_ t f)
    (def given (List ref 4 f))
    (def lpath (List ref 5 f))
    (def cpath (List ref 6 f))
    (def chost (List ref 2 f))
    (def cport (List ref 3 f))
    (list t
          (match ((not (null? lpath)) lpath) ((null? given) "") ((str=? given "") "*") (#t given))
          (if (null? lpath) (List ref 1 f) ssh-mux-streamlocal)
          (match ((not (null? cpath)) cpath) ((if (null? chost) #t (not chost)) "") (#t chost))
          (match ((not (null? cpath)) ssh-mux-streamlocal) ((if (null? cport) #t (not cport)) 0) (#t cport)))))

; A forward as OpenSSH's format_forward says it, gateway GatewayPorts.
(def ssh-mux-forward-text
  (fn (_ key gateway)
    (def t (first key))
    (def lhost (List ref 1 key)) (def lport (List ref 2 key))
    (def chost (List ref 3 key)) (def cport (List ref 4 key))
    (def port (fn (_ p) (if (= p ssh-mux-streamlocal) "-2" (%num p))))
    (def listen (if (str=? lhost "") (if (if gateway (not (= t ssh-mux-fwd-remote)) #f) "*" "LOCALHOST") lhost))
    (match
      ((= t ssh-mux-fwd-dynamic) (Str8 append "dynamic forward " listen ":" (port lport) " -> *"))
      (#t (Str8 append (if (= t ssh-mux-fwd-local) "local" "remote") " forward " listen ":" (port lport)
                       " -> " chost ":" (port cport))))))

; OPEN_FWD read past its id: the forward, or () when it is malformed, a
; port past 65535 that is no socket's.
(def ssh-mux-forward-read
  (fn (_ in)
    (def t (ssh-get-uint32 in))
    (def lhost (ssh-get-text in)) (def lport (ssh-get-uint32 in))
    (def chost (ssh-get-text in)) (def cport (ssh-get-uint32 in))
    (def bad (fn (_ p) (if (= p ssh-mux-streamlocal) #f (> p 65535))))
    (if (if (bad lport) #t (bad cport)) () (list t lhost lport chost cport))))

; OPEN_FWD, or CLOSE_FWD when cancel?, of the forward key, its reply
; read: #t for OK, (port . PORT) for REMOTE_PORT, (denied . REASON),
; (failed . REASON), or () when the master has gone.
(def ssh-mux-forward!
  (fn (_ fd cancel? rid key)
    (def m (ssh-mux-message (if cancel? ssh-mux-close-fwd ssh-mux-open-fwd)))
    (ssh-put-uint32 m rid)
    (ssh-put-uint32 m (first key))
    (ssh-put-text m (List ref 1 key)) (ssh-put-uint32 m (List ref 2 key))
    (ssh-put-text m (List ref 3 key)) (ssh-put-uint32 m (List ref 4 key))
    (if (not (ssh-mux-send! fd m)) ()
      (do (def r (ssh-mux-receive fd))
          (if (null? r) ()
            (do (ssh-get-uint32 (rest r))
                (match
                  ((= (first r) ssh-mux-ok) #t)
                  ((= (first r) ssh-mux-remote-port) (pair (lit port) (ssh-get-uint32 (rest r))))
                  ((= (first r) ssh-mux-permission-denied) (pair (lit denied) (ssh-get-text (rest r))))
                  ((= (first r) ssh-mux-failure) (pair (lit failed) (ssh-get-text (rest r))))
                  (#t ()))))))))

; --- the master's end --------------------------------------------------------

; A descriptor the client sends after its request: it, or ().
(def ssh-mux-take-fd (fn (_ fd) (ssh-sys-recv-fd fd)))

(provide ssh/mux ssh-mux-version ssh-mux-hello ssh-mux-new-session ssh-mux-alive-check ssh-mux-terminate
  ssh-mux-open-fwd ssh-mux-close-fwd ssh-mux-new-stdio-fwd ssh-mux-stop-listening ssh-mux-proxy
  ssh-mux-ok ssh-mux-permission-denied ssh-mux-failure ssh-mux-exit-message ssh-mux-alive
  ssh-mux-session-opened ssh-mux-remote-port ssh-mux-tty-alloc-fail ssh-mux-s-proxy ssh-mux-proxy!
  ssh-mux-fwd-local ssh-mux-fwd-remote ssh-mux-fwd-dynamic ssh-mux-streamlocal
  ssh-mux-forward-key ssh-mux-forward-text ssh-mux-forward-read ssh-mux-forward!
  ssh-mux-message ssh-mux-send! ssh-mux-receive ssh-mux-hello-message ssh-mux-reply-ok ssh-mux-reply-error
  ssh-mux-reply-two ssh-mux-session-request ssh-mux-connect ssh-mux-greet! ssh-mux-alive? ssh-mux-command
  ssh-mux-open-session ssh-mux-open-stdio ssh-mux-wait ssh-mux-take-fd
  ssh-mux-ext-info ssh-mux-s-ext-info ssh-mux-master-hello ssh-mux-reply-info ssh-mux-info)
