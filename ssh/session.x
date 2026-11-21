; # x-ssh -- SSH on x-lang
;
; ## ssh/session.x -- the connection protocol: the client's channels
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; RFC 4254 from the client's end.  One session channel carries the
; command: opened, asked to exec, its output and extended output handed
; to the caller as they arrive, our input pumped to it as the server's
; window allows, its exit status taken from the request that carries it.
; Beside it, each connection accepted on a -L listener is a direct-tcpip
; channel to the host and port the forward names -- on a -D listener, to
; the host and port its SOCKS request names -- and each -R forward is
; asked of the server by a tcpip-forward global request, the connections
; it then opens as forwarded-tcpip channels connected here to the host
; and port the forward names, or, for one given only a port, to the host
; and port each one's SOCKS request names.  Either end may be a Unix
; socket instead, by OpenSSH's streamlocal channels and request.  A
; forward's bytes are pumped each way until
; both ends close.  The channels are a table keyed by our channel
; number, which every message from the server names first; one loop
; waits on the socket, the listeners, and each channel's input while
; that channel's window has room.  Under ControlMaster the run serves
; other clients' sessions too, as OpenSSH's master serves them (see
; connection sharing below).

(module ssh/session)

(import x/sys/posix)
(import x/sys/file)
(import x/sys/socket)
(import x/sys/gc)
(import ssh/tty ssh-tty-modes-encode)
(import ssh/sys ssh-sys-umask)
(import ssh/ask ssh-askpass)
(import ssh/mux ssh-mux-hello ssh-mux-new-session ssh-mux-alive-check ssh-mux-terminate ssh-mux-new-stdio-fwd
  ssh-mux-stop-listening ssh-mux-permission-denied ssh-mux-failure ssh-mux-exit-message ssh-mux-alive
  ssh-mux-session-opened ssh-mux-send! ssh-mux-receive ssh-mux-hello-message ssh-mux-reply-ok ssh-mux-reply-error
  ssh-mux-reply-two ssh-mux-session-request ssh-mux-take-fd)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-text ssh-put-string ssh-out-run
  ssh-in ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-text ssh-in-buf ssh-copy)
(import ssh/transport ssh-fd ssh-pending? ssh-send-packet! ssh-take-packet! ssh-msg-disconnect
  ssh-msg-global-request ssh-msg-request-success ssh-msg-request-failure
  ssh-clock-sent ssh-clock-recv ssh-clock-data ssh-clock-mark! ssh-clocks-start! ssh-wait-ms ssh-clocks!)

(import x/core/doors str-byte-ref char->int str-byte-len obj-ref obj-set! str-make str->ptr ptr-set!)
(def %byte (fn (_ s i) (char->int (str-byte-ref s i))))
(def %num (fn (_ n) ((prim-ref (lit convert) (lit to)) n (Type named STRING) 10)))

(def %msg-channel-open 90) (def %msg-channel-open-confirmation 91)
(def %msg-channel-open-failure 92) (def %msg-channel-window-adjust 93)
(def %msg-channel-data 94) (def %msg-channel-extended-data 95)
(def %msg-channel-eof 96) (def %msg-channel-close 97)
(def %msg-channel-request 98) (def %msg-channel-success 99) (def %msg-channel-failure 100)

(def %window 2097152)
(def %max-packet 32768)

(def %say (fn (_ text) (File write 2 text (str-byte-len text))))

(def %send
  (fn (_ c out)
    (def r (ssh-out-run out))
    (ssh-send-packet! c (first r) (rest r))
    (ssh-clock-mark! ssh-clock-sent)))

(def %packet-of
  (fn (_ type)
    (def out (ssh-out))
    (ssh-put-byte out type)
    out))


; A channel's state, in a vector: 1 our channel number, 2 the server's,
; 3 how many bytes it will take from us (its window), 4 the most a packet
; may carry, 5 the descriptor our input is read from, () once it has
; ended, 6 the exit status, 7 whether the server has closed the channel,
; 8 what takes its data, 9 what takes its extended data or (), 10 its
; kind, session or forward, 11 a forward's connection, 12 the session's
; command, 13 the bytes taken from the server not yet given back, 14
; whether we have closed it first; a session's 15 terminal asked for, as
; (TERM WINDOW MODES ESCAPE), WINDOW a function answering (COLUMNS .
; ROWS), MODES the local terminal's as Term modes answers them, ESCAPE
; the escape character's number or () for none; or (), 16 the window
; last sent, 17 where the escape character stands: 1 at a line's start,
; 2 just after the escape character there, 0 elsewhere, 18 the
; environment sent, 19 the agent's socket forwarded, or (); and 20, for
; a channel a sharing client asked for, its control connection as
; (FD RID FDS), FDS the descriptors it passed, or ().
(def %OURS 1) (def %SERVER 2) (def %WINDOW 3) (def %MAX 4) (def %INPUT 5) (def %STATUS 6)
(def %CLOSED 7) (def %OUT 8) (def %ERR 9) (def %KIND 10) (def %FD 11) (def %COMMAND 12)
(def %OWED 13) (def %SHUT 14) (def %TTY 15) (def %SIZE 16) (def %ESC 17) (def %ENV 18)
(def %AGENT 19) (def %CTL 20)
(def %ch (fn (_ ch i) (obj-ref ch i)))
(def %ch! (fn (_ ch i v) (obj-set! ch i v)))

; The run's state: 1 the channels, 2 the next channel number, 3 the
; bytes moved since the last collect, 4 the listeners as (FD HOST PORT CPATH),
; 5 the session channel or (), 6 the remote forwards as forwards are,
; 7 those whose request the server has yet to answer, in
; the order asked, 8 the agent's socket, or (), 9 the connections on
; dynamic listeners yet to say where they go, as (FD BYTES GREETED), 10
; where a remote forward's SOCKS requests may go: () anywhere, none
; nowhere, or (HOST PORT) each, HOST "*" any host and PORT () any port;
; 11 the control socket listened on for sharing clients, as (FD PATH
; ASK HOST), or (); 12 its connections as (FD GREETED); 13 whether a
; sharing client has asked the run to end.
(def %CHANNELS 1) (def %NEXT 2) (def %MOVED 3) (def %LISTENERS 4) (def %SESSION 5)
(def %REMOTES 6) (def %UNANSWERED 7) (def %RUN-AGENT 8) (def %SOCKS 9) (def %OPEN 10)
(def %CONTROL 11) (def %CONTROLS 12) (def %ENDED 13)
(def %rn (fn (_ run i) (obj-ref run i)))
(def %rn! (fn (_ run i v) (obj-set! run i v)))

; The most a read of an input takes at once.
(def %chunk 16384)

(def %min (fn (_ a b) (if (< a b) a b)))

; Bytes moved between collects.  x collects only when asked, and every
; byte through the cipher and the authenticator leaves garbage behind, so
; a long transfer is swept as it goes, every input chunk's worth.
(def %collect-every 16384)

(def %moved! (fn (_ run n) (%rn! run %MOVED (+ (%rn run %MOVED) n))))

; A dotted address for a name: what the resolver says, or the name when
; it already is one.
(def %address
  (fn (_ host)
    (def r (Socket resolve host))
    (if (null? r) host (if (pair? r) (first r) r))))

; A channel added to the table, numbered next.
(def %channel!
  (fn (_ run kind input out err fd command)
    (def ch (Vector make 20 ()))
    (%ch! ch %OURS (%rn run %NEXT))
    (%rn! run %NEXT (+ (%rn run %NEXT) 1))
    (%ch! ch %WINDOW 0) (%ch! ch %MAX 32768) (%ch! ch %INPUT input) (%ch! ch %CLOSED #f) (%ch! ch %OWED 0) (%ch! ch %SHUT #f)
    (%ch! ch %OUT out) (%ch! ch %ERR err) (%ch! ch %KIND kind) (%ch! ch %FD fd) (%ch! ch %COMMAND command)
    (%rn! run %CHANNELS (List append (%rn run %CHANNELS) (list ch)))
    ch))

; A forward channel over a connection: the connection its input, and
; what its data is written to.
(def %forward-channel!
  (fn (_ run fd)
    (%channel! run (lit forward) fd
      (fn (_ buf start len) (Socket send-run fd (ssh-copy buf start len) len))
      () fd ())))

(def %find
  (fn (_ run ours)
    (List find (fn (_ ch) (= (%ch ch %OURS) ours)) (%rn run %CHANNELS))))

(def %drop!
  (fn (_ run ch)
    (%rn! run %CHANNELS (List filter (fn (_ x) (not (= (%ch x %OURS) (%ch ch %OURS)))) (%rn run %CHANNELS)))))

; The open of a channel, its kind's fields put by the caller after.
(def %open-packet
  (fn (_ ch type)
    (def open (%packet-of %msg-channel-open))
    (ssh-put-text open type)
    (ssh-put-uint32 open (%ch ch %OURS))
    (ssh-put-uint32 open %window)
    (ssh-put-uint32 open %max-packet)
    open))

; A session channel opened for a command, its input the descriptor read
; for it, () for none, with its terminal (or ()), environment and agent.
(def %session-channel!
  (fn (_ c run command input on-out on-err tty env agent)
    (def ch (%channel! run (lit session) input on-out on-err () command))
    (%ch! ch %TTY tty) (%ch! ch %SIZE (if (null? tty) () ((List ref 1 tty)))) (%ch! ch %ESC 1)
    (%ch! ch %ENV env) (%ch! ch %AGENT agent)
    (%send c (%open-packet ch "session"))
    ch))

; The run's own session.
(def %open-session!
  (fn (_ c run command input on-out on-err tty env agent)
    (%rn! run %SESSION (%session-channel! c run command input on-out on-err tty env agent))))

; A connection accepted on a listener opened as a direct-tcpip channel
; to the forward's host and port, the connection its input and output.
; One on a Unix socket has no address (the system says port 0): it says
; 127.0.0.1 port 65535, as OpenSSH says it for servers that check.
(def %open-forward!
  (fn (_ c run fd host port)
    (def peer ((fn (_ p) (if (= (rest p) 0) (pair "127.0.0.1" 65535) p)) (Socket peer fd)))
    (def ch (%forward-channel! run fd))
    (def open (%open-packet ch "direct-tcpip"))
    (ssh-put-text open host)
    (ssh-put-uint32 open port)
    (ssh-put-text open (first peer))
    (ssh-put-uint32 open (rest peer))
    (%send c open)))

; --- Unix sockets: OpenSSH's streamlocal forwarding ------------------------
;
; Either end of a forward may be a Unix socket.  A connection accepted
; for a forward to a socket is a direct-streamlocal@openssh.com channel
; to its path; a listener on a socket is made under StreamLocalBindMask,
; an old file in its place removed first under StreamLocalBindUnlink,
; and one that cannot be made is said as OpenSSH says it and left out.

(def %open-streamlocal!
  (fn (_ c run fd path)
    (def ch (%forward-channel! run fd))
    (def open (%open-packet ch "direct-streamlocal@openssh.com"))
    (ssh-put-text open path)
    (ssh-put-text open "")
    (ssh-put-uint32 open 0)
    (%send c open)))

; An Err's words past its call's name: "bind: Address already in use" is
; "Address already in use".
(def %reason
  (fn (_ e)
    (def m (e msg))
    (def i (Str8 index-of ": " m))
    (if (null? i) m (Str8 sub (+ i 2) (- (Str8 length m) i 2) m))))

; A forward's listener, (FD HOST PORT CPATH), or () for a socket's that
; cannot be made; sl is (MASK . UNLINK).
(def %listen
  (fn (_ f sl)
    (def lpath (List ref 5 f))
    (if (null? lpath)
      (list (if (null? (first f)) (Socket tcp-listen (List ref 1 f)) (Socket tcp-listen-on (first f) (List ref 1 f)))
            (List ref 2 f) (List ref 3 f) (List ref 6 f))
      (do (when (rest sl) (guard (e ()) (File unlink lpath)))
          (def old (ssh-sys-umask (first sl)))
          (def fd (guard (e (do (%say (Str8 append "unix_listener: cannot bind to path " lpath ": " (%reason e)
                                                    "\nCould not request local forwarding.\n"))
                                ()))
                    (Socket unix-listen lpath)))
          (ssh-sys-umask old)
          (if (null? fd) () (list fd (List ref 2 f) (List ref 3 f) (List ref 6 f)))))))

; --- DynamicForward: SOCKS (RFC 1928, and SOCKS 4 and 4a) -------------------
;
; A connection accepted on a dynamic listener says where it goes before
; it is a channel: SOCKS 4 or 4a, or SOCKS 5 without authentication,
; CONNECT only, as OpenSSH's client serves them.  What it has sent is
; kept, a byte at a time as a list, until the request is whole; then the
; reply is sent at once, as OpenSSH sends it, and the connection is a
; direct-tcpip channel's like any -L forward's.  Each read takes no more
; than the request still lacks, so nothing meant for the channel is read
; here.

; The most a request may hold, SOCKS 4's user and host names with it.
(def %socks-max 1024)

(def %bytes-text
  (fn (_ bs)
    (def out (ssh-out))
    (List for-each (fn (_ b) (ssh-put-byte out b)) bs)
    ((fn (_ r) (ssh-copy (first r) 0 (rest r))) (ssh-out-run out))))

(def %slice (fn (_ bs from n) (List take n (List drop from bs))))

; The index of the first zero byte at or past from, or ().
(def %nul-from
  (fn (_ bs from)
    ((fn (self xs i) (match ((null? xs) ()) ((= (first xs) 0) i) (#t (self (rest xs) (+ i 1)))))
     (List drop from bs) from)))

(def %hex (fn (_ n) ((prim-ref (lit convert) (lit to)) n (Type named STRING) 16)))

; What a request so far calls for: (more N) bytes, (greet) for SOCKS 5's
; greeting answered, (done HOST PORT REPLY USED) with the reply's bytes
; and how many of bs the greeting and request took, or (bad) to close
; the connection.
(def %socks
  (fn (_ bs greeted)
    (def n (List length bs))
    (def at (fn (_ i) (List ref i bs)))
    (def port-at (fn (_ i) (+ (* (at i) 256) (at (+ i 1)))))
    (match
      ((= n 0) (list (lit more) 1))
      ((> n %socks-max) (list (lit bad)))
      ((= (at 0) 4)
        (match
          ((< n 8) (list (lit more) (- 8 n)))
          ((not (= (at 1) 1)) (list (lit bad)))
          (#t
            (do (def user-end (%nul-from bs 8))
                (def ip (%slice bs 4 4))
                ; 4a: an address 0.0.0.x, x not 0, is a name after the user's
                (def named (if (= (first ip) 0) (if (= (at 5) 0) (if (= (at 6) 0) (not (= (at 7) 0)) #f) #f) #f))
                (def host-end (if (if named (not (null? user-end)) #f) (%nul-from bs (+ user-end 1)) ()))
                (def reply (list 0 90 0 0 0 0 0 0))
                (match
                  ((null? user-end) (list (lit more) 1))
                  ((not named) (list (lit done) (Str8 join "." (List map %num ip)) (port-at 2) reply (+ user-end 1)))
                  ((null? host-end) (list (lit more) 1))
                  (#t (list (lit done) (%bytes-text (%slice bs (+ user-end 1) (- host-end user-end 1))) (port-at 2) reply (+ host-end 1))))))))
      ((= (at 0) 5)
        (if (< n 2) (list (lit more) (- 2 n))
          (do (def hdr (+ 2 (at 1)))
              (match
                ((< n hdr) (list (lit more) (- hdr n)))
                ((not greeted) (if (List any? (fn (_ m) (= m 0)) (%slice bs 2 (at 1))) (list (lit greet)) (list (lit bad))))
                ((< n (+ hdr 5)) (list (lit more) (- (+ hdr 5) n)))
                ((not (if (= (at hdr) 5) (= (at (+ hdr 1)) 1) #f)) (list (lit bad)))
                (#t
                  (do (def atyp (at (+ hdr 3)))
                      (def a (+ hdr 4))
                      (def size (match ((= atyp 1) 4) ((= atyp 3) (+ 1 (at a))) ((= atyp 4) 16) (#t ())))
                      (def reply (list 5 0 0 1 0 0 0 0 0 0))
                      (match
                        ((null? size) (list (lit bad)))
                        ((< n (+ a size 2)) (list (lit more) (- (+ a size 2) n)))
                        ((= atyp 1) (list (lit done) (Str8 join "." (List map %num (%slice bs a 4))) (port-at (+ a 4)) reply (+ a size 2)))
                        ((= atyp 3) (list (lit done) (%bytes-text (%slice bs (+ a 1) (at a))) (port-at (+ a size)) reply (+ a size 2)))
                        (#t (list (lit done)
                                  (Str8 join ":" ((fn (self xs) (if (null? xs) () (pair (%hex (+ (* (first xs) 256) (first (rest xs)))) (self (rest (rest xs))))))
                                                  (%slice bs a 16)))
                                  (port-at (+ a 16)) reply (+ a size 2))))))))))
      (#t (list (lit bad))))))

; A connection on a dynamic listener, waiting to say where it goes: (FD
; BYTES GREETED), BYTES what it has sent.
(def %socks-wait!
  (fn (_ run fd) (%rn! run %SOCKS (List append (%rn run %SOCKS) (list (list fd () #f))))))

(def %socks-drop!
  (fn (_ run fd) (%rn! run %SOCKS (List filter (fn (_ w) (not (= (first w) fd))) (%rn run %SOCKS)))))

(def %send-bytes
  (fn (_ fd bs) (def t (%bytes-text bs)) (guard (e ()) (Socket send-run fd t (List length bs)))))

; A waiting connection's bytes read, as many as its request still
; lacks, and what they call for done: the greeting answered, the
; connection opened as a channel, or closed.
(def %socks-read!
  (fn (_ c run w)
    (def fd (first w))
    (def bs (List ref 1 w))
    (def greeted (List ref 2 w))
    (def want (%socks bs greeted))
    (def got (if (eq? (first want) (lit more)) (guard (e ()) (Socket recv-run fd (List ref 1 want))) ()))
    (def close! (fn (_) (do (%socks-drop! run fd) (guard (e ()) (Socket close fd)))))
    (if (if (null? got) #t (= (rest got) 0))
      (close!)
      (do (def now (List append bs ((fn (self i) (if (= i (rest got)) () (pair (%byte (first got) i) (self (+ i 1))))) 0)))
          (def next (%socks now greeted))
          (%rn! run %SOCKS (List map (fn (_ x) (if (= (first x) fd) (list fd now greeted) x)) (%rn run %SOCKS)))
          (match
            ((eq? (first next) (lit more)) ())
            ((eq? (first next) (lit bad)) (close!))
            ((eq? (first next) (lit greet))
              (do (%send-bytes fd (list 5 0))
                  (%rn! run %SOCKS (List map (fn (_ x) (if (= (first x) fd) (list fd now #t) x)) (%rn run %SOCKS)))))
            (#t (do (%socks-drop! run fd)
                    (%send-bytes fd (List ref 3 next))
                    (%open-forward! c run fd (List ref 1 next) (List ref 2 next)))))))))

; -W: a direct-tcpip channel to a host and port whose two
; ways are this process's own input and output, the loop's to end as a
; session's is.
(def %open-netcat!
  (fn (_ c run host port input on-out)
    (def ch (%channel! run (lit netcat) input on-out () () ()))
    (%rn! run %SESSION ch)
    (def open (%open-packet ch "direct-tcpip"))
    (ssh-put-text open host)
    (ssh-put-uint32 open port)
    (ssh-put-text open "127.0.0.1")
    (ssh-put-uint32 open 0)
    (%send c open)))

; A remote forward asked of the server: tcpip-forward for its address
; and port, the address "" for every interface, as OpenSSH asks; or
; streamlocal-forward@openssh.com for a socket at the server's end.
(def %ask-remote!
  (fn (_ c run remote)
    (def req (%packet-of ssh-msg-global-request))
    (def path (List ref 5 remote))
    (if (null? path)
      (do (ssh-put-text req "tcpip-forward")
          (ssh-put-bool req #t)
          (ssh-put-text req (if (null? (first remote)) "" (first remote)))
          (ssh-put-uint32 req (List ref 1 remote)))
      (do (ssh-put-text req "streamlocal-forward@openssh.com")
          (ssh-put-bool req #t)
          (ssh-put-text req path)))
    (%send c req)
    (%rn! run %UNANSWERED (List append (%rn run %UNANSWERED) (list remote)))))

; --- RemoteForward without a destination: SOCKS at the server's end --------
;
; A remote forward given only a port is OpenSSH's remote dynamic
; forward: each connection the server opens for it says where it goes by
; SOCKS, as a -D listener's do, its request read from the channel's data.
; Where PermitRemoteOpen allows it, the place is connected, the reply sent
; and the channel a forward's like any; where it does not, or the
; connect fails, the channel is closed with no reply, as OpenSSH closes
; it.

; Whether a SOCKS request for host and port may be connected.
(def %open-allowed?
  (fn (_ open host port)
    (match ((null? open) #t)
           ((eq? open (lit none)) #f)
           (#t (List any? (fn (_ p) (if (if (str=? (first p) "*") #t (str=? (first p) host))
                                       (if (null? (List ref 1 p)) #t (= (List ref 1 p) port))
                                       #f))
                 open)))))

; Bytes, a list, sent as a channel's data.
(def %channel-data!
  (fn (_ c ch bs)
    (def data (%packet-of %msg-channel-data))
    (ssh-put-uint32 data (%ch ch %SERVER))
    (ssh-put-string data (%bytes-text bs) 0 (List length bs))
    (%send c data)
    (%ch! ch %WINDOW (- (%ch ch %WINDOW) (List length bs)))))

; Our close of a channel before the server's: sent once.
(def %shut!
  (fn (_ c ch)
    (unless (%ch ch %SHUT)
      (do (def cl (%packet-of %msg-channel-close))
          (ssh-put-uint32 cl (%ch ch %SERVER))
          (%send c cl)
          (%ch! ch %SHUT #t)))))

; A forward channel with no connection yet: its data is kept, the
; request's bytes and whether SOCKS 5's greeting is answered, until the
; request is whole; then it is connected or closed.  Bytes past the
; request go to the connection.
(def %socks-channel!
  (fn (_ c run)
    (def ch (%channel! run (lit forward) () () () () ()))
    (def state (Vector make 2 ()))
    (obj-set! state 2 #f)
    (%ch! ch %OUT
      (fn (_ buf start len)
        (unless (%ch ch %SHUT)
          (do (obj-set! state 1 (List append (obj-ref state 1)
                                  ((fn (self i) (if (= i len) () (pair (%byte buf (+ start i)) (self (+ i 1))))) 0)))
              ((fn (self)
                 (def next (%socks (obj-ref state 1) (obj-ref state 2)))
                 (match
                   ((eq? (first next) (lit more)) ())
                   ((eq? (first next) (lit bad)) (%shut! c ch))
                   ((eq? (first next) (lit greet))
                     (do (%channel-data! c ch (list 5 0)) (obj-set! state 2 #t) (self)))
                   (#t
                     (do (def host (List ref 1 next))
                         (def port (List ref 2 next))
                         (def fd (if (%open-allowed? (%rn run %OPEN) host port)
                                   (guard (e ()) (Socket tcp-connect (%address host) port))
                                   ()))
                         (if (null? fd)
                           (%shut! c ch)
                           (do (def after (List drop (List ref 4 next) (obj-ref state 1)))
                               (%channel-data! c ch (List ref 3 next))
                               (%ch! ch %FD fd)
                               (%ch! ch %INPUT fd)
                               (%ch! ch %OUT (fn (_ b s n) (Socket send-run fd (ssh-copy b s n) n)))
                               (unless (null? after)
                                 (Socket send-run fd (%bytes-text after) (List length after))))))))))))))
    ch))

; The server's answer to the oldest request still open: a refusal said
; as OpenSSH says it.
(def %answered!
  (fn (_ run ok)
    (def asked (%rn run %UNANSWERED))
    (unless (null? asked)
      (do (def r (first asked))
          (%rn! run %UNANSWERED (rest asked))
          (unless ok
            (%say (if (null? (List ref 5 r))
                    (Str8 append "Warning: remote port forwarding failed for listen port " (%num (List ref 1 r)) "\n")
                    (Str8 append "Warning: remote port forwarding failed for listen path " (List ref 5 r) "\n"))))))))

; A channel the server opens: a forwarded-tcpip for a remote forward's
; port, or a forwarded-streamlocal@openssh.com for its socket's path,
; connected here to the forward's host and port or socket, or, for a
; forward without one, confirmed to say where it goes by SOCKS; or an
; auth-agent@openssh.com, connected to the agent forwarded, and
; confirmed; any other, or a connect that fails, refused.
(def %opened!
  (fn (_ c run in)
    (def type (ssh-get-text in))
    (def sender (ssh-get-uint32 in))
    (def window (ssh-get-uint32 in))
    (def max (ssh-get-uint32 in))
    (def agent? (if (str=? type "auth-agent@openssh.com") (not (null? (%rn run %RUN-AGENT))) #f))
    (def port (if (str=? type "forwarded-tcpip") (do (ssh-get-text in) (ssh-get-uint32 in)) ()))
    ; a socket's: its path, then a reserved string
    (def path (if (str=? type "forwarded-streamlocal@openssh.com") (do (def p (ssh-get-text in)) (ssh-get-text in) p) ()))
    (def remote
      (match
        ((not (null? port)) (List find (fn (_ r) (if (null? (List ref 5 r)) (= (List ref 1 r) port) #f)) (%rn run %REMOTES)))
        ((not (null? path)) (List find (fn (_ r) (if (null? (List ref 5 r)) #f (str=? (List ref 5 r) path))) (%rn run %REMOTES)))
        (#t ())))
    (def socks? (if (null? remote) #f (if (null? (List ref 2 remote)) (null? (List ref 6 remote)) #f)))
    (def fd (match
              (agent? (guard (e ()) (Socket unix-connect (%rn run %RUN-AGENT))))
              ((null? remote) ())
              (socks? ())
              ((not (null? (List ref 6 remote))) (guard (e ()) (Socket unix-connect (List ref 6 remote))))
              (#t (guard (e ()) (Socket tcp-connect (%address (List ref 2 remote)) (List ref 3 remote))))))
    (def asked (if agent? #t (not (null? remote))))
    (if (if (null? fd) (not socks?) #f)
      (do (def no (%packet-of %msg-channel-open-failure))
          (ssh-put-uint32 no sender)
          (ssh-put-uint32 no (if asked 2 1))
          (ssh-put-text no (if asked "connect failed" (Str8 append "unrequested channel: " type)))
          (ssh-put-text no "")
          (%send c no))
      (do (def ch (if socks? (%socks-channel! c run) (%forward-channel! run fd)))
          (%ch! ch %SERVER sender) (%ch! ch %WINDOW window) (%ch! ch %MAX max)
          (def ok (%packet-of %msg-channel-open-confirmation))
          (ssh-put-uint32 ok sender)
          (ssh-put-uint32 ok (%ch ch %OURS))
          (ssh-put-uint32 ok %window)
          (ssh-put-uint32 ok %max-packet)
          (%send c ok)))))

; A channel's input's end: EOF to the server, and no more reads.
(def %input-done!
  (fn (_ c ch)
    (def eof (%packet-of %msg-channel-eof))
    (ssh-put-uint32 eof (%ch ch %SERVER))
    (%send c eof)
    (%ch! ch %INPUT ())))

; One read of a channel's input sent as its data: as much as is there,
; the window and the packet size allow; a read of nothing is its end.
; Typed bytes through OpenSSH's escapes, the escape character esc (~ by
; default) at a line's start: esc . ends the connection, esc esc is one
; esc, an esc before anything else is itself.  Answers (BUF . N), or
; raises "escape" for esc . .
(def %escape
  (fn (_ ch buf got esc)
    (def out (str-make (+ (* got 2) 1)))
    (def p (str->ptr out))
    (def byte (fn (_ i) ((prim-ref (lit char) (lit ->int)) ((prim-ref (lit str) (lit byte-ref)) buf i))))
    (def n
      ((fn (self i n state)
         (if (= i got) (do (%ch! ch %ESC state) n)
           (do (def b (byte i))
               (def line? (if (= b 13) #t (= b 10)))
               (match
                 ((= state 2)
                   (match
                     ((= b 46) (Err raise 'io "escape" ()))
                     ((= b esc) (do (ptr-set! p n esc 1) (self (+ i 1) (+ n 1) 0)))
                     (#t (do (ptr-set! p n esc 1) (ptr-set! p (+ n 1) b 1) (self (+ i 1) (+ n 2) (if line? 1 0))))))
                 ((if (= state 1) (= b esc) #f) (self (+ i 1) n 2))
                 (#t (do (ptr-set! p n b 1) (self (+ i 1) (+ n 1) (if line? 1 0))))))))
       0 0 (%ch ch %ESC)))
    (pair out n)))

; The sessions on a terminal.
(def %on-terminals
  (fn (_ run) (List filter (fn (_ ch) (if (%ch ch %CLOSED) #f (not (null? (%ch ch %TTY))))) (%rn run %CHANNELS))))

; How long the poll may wait: the clocks' limit, and with a session on a
; terminal half a second at most, so a resized window is seen -- a
; closure cannot be a SIGWINCH handler.
(def %poll-ms
  (fn (_ run limits)
    (def w (ssh-wait-ms limits))
    (if (null? (%on-terminals run)) w (if (if (< w 0) #t (< 500 w)) 500 w))))

; Each terminal's window as it is now, sent as window-change when it
; moved.
(def %resized!
  (fn (_ c run)
    (List for-each
      (fn (_ session)
        (unless (null? (%ch session %SERVER))
          (do (def now (guard (e (%ch session %SIZE)) ((List ref 1 (%ch session %TTY)))))
              (unless (if (= (first now) (first (%ch session %SIZE))) (= (rest now) (rest (%ch session %SIZE))) #f)
                (do (def p (%packet-of %msg-channel-request))
                    (ssh-put-uint32 p (%ch session %SERVER))
                    (ssh-put-text p "window-change")
                    (ssh-put-bool p #f)
                    (ssh-put-uint32 p (first now))
                    (ssh-put-uint32 p (rest now))
                    (ssh-put-uint32 p 0)
                    (ssh-put-uint32 p 0)
                    (%send c p)
                    (%ch! session %SIZE now))))))
      (%on-terminals run))))

; A sharing client's session ended at its escape: the channel closed,
; the client hearing no exit status.
(def %escape-closed!
  (fn (_ c ch)
    (unless (%ch ch %SHUT)
      (do (def cl (%packet-of %msg-channel-close))
          (ssh-put-uint32 cl (%ch ch %SERVER))
          (%send c cl)
          (%ch! ch %SHUT #t)))
    (%ch! ch %INPUT ())
    (pair "" 0)))

(def %pump!
  (fn (_ c run ch)
    (def n (%min %chunk (%min (%ch ch %WINDOW) (- (%ch ch %MAX) 64))))
    (def tty (%ch ch %TTY))
    ; a held escape character comes out with the next byte, so a terminal reads one short
    (def raw (str-make n))
    (def read (File read (%ch ch %INPUT) raw (if (null? tty) n (- n 1))))
    ; esc . ends the connection, or a sharing client's session alone
    (def typed (if (if (< read 1) #f (if (null? tty) #f (not (null? (List ref 3 tty)))))
                 (if (null? (%ch ch %CTL)) (%escape ch raw read (List ref 3 tty))
                   (guard (e (%escape-closed! c ch)) (%escape ch raw read (List ref 3 tty))))
                 (pair raw read)))
    (def buf (first typed))
    (def got (rest typed))
    (if (< read 1)
      (%input-done! c ch)
      (do (def data (%packet-of %msg-channel-data))
          (ssh-put-uint32 data (%ch ch %SERVER))
          (ssh-put-string data buf 0 got)
          (%send c data)
          (ssh-clock-mark! ssh-clock-data)
          (%ch! ch %WINDOW (- (%ch ch %WINDOW) got))
          (%moved! run got)))))

; Our close of a channel, after the server's: its connection closed and
; the channel dropped, a session marked closed for the loop's end; a
; sharing client's descriptors and control connection closed with it.
(def %close!
  (fn (_ c run ch)
    (unless (%ch ch %SHUT)
      (do (def cl (%packet-of %msg-channel-close))
          (ssh-put-uint32 cl (%ch ch %SERVER))
          (%send c cl)))
    (%ch! ch %CLOSED #t) (%ch! ch %INPUT ())
    (when (eq? (%ch ch %KIND) (lit forward))
      (do (guard (e ()) (Socket close (%ch ch %FD)))
          (%drop! run ch)))
    (unless (null? (%ch ch %CTL)) (%mux-done! run ch))))

; --- connection sharing: the master's end (ssh/mux) -------------------------
;
; With ControlMaster, the run listens on ControlPath for other clients
; to share its connection, as OpenSSH's master serves them.  Each
; control connection is greeted with HELLO and answered request by
; request: ALIVE_CHECK with this process's id, TERMINATE by ending the
; run, STOP_LISTENING by closing the socket, and NEW_SESSION or
; NEW_STDIO_FWD by a channel whose input, output and error are the
; descriptors the client passes, its control connection told when it is
; open and the session's exit status, and closed when the channel is.
; ControlMaster ask and autoask ask SSH_ASKPASS to confirm each, as
; OpenSSH's ask_permission does.  A forward asked of the master is not
; served yet: "unsupported request".

; A message to a sharing channel's client.
(def %mux-tell (fn (_ ch m) (ssh-mux-send! (first (%ch ch %CTL)) m)))

; A sharing channel ended: the descriptors its client passed and its
; control connection closed, the channel dropped.
(def %mux-done!
  (fn (_ run ch)
    (def ctl (%ch ch %CTL))
    (List for-each (fn (_ fd) (guard (e ()) (File close fd))) (List ref 2 ctl))
    (guard (e ()) (Socket close (first ctl)))
    (%rn! run %CONTROLS (List filter (fn (_ k) (not (= (first k) (first ctl)))) (%rn run %CONTROLS)))
    (%ch! ch %INPUT ())
    (%drop! run ch)))

; The sharing channels: those a client of the control socket asked for.
(def %shared (fn (_ run) (List filter (fn (_ ch) (not (null? (%ch ch %CTL)))) (%rn run %CHANNELS))))

; ControlMaster ask's question, put to SSH_ASKPASS as OpenSSH's
; ask_permission puts it: an empty answer or yes allows.
(def %allowed?
  (fn (_ run text)
    (if (not (List ref 2 (%rn run %CONTROL))) #t
      (do (Sys setenv "SSH_ASKPASS_PROMPT" "confirm")
          (def a (if (if (%set? "DISPLAY") #t (if (%set? "WAYLAND_DISPLAY") #t
                       ((fn (_ r) (if (null? r) #f (str=? (Str8 downcase r) "force"))) (Sys getenv "SSH_ASKPASS_REQUIRE"))))
                   (ssh-askpass text) ()))
          (Sys unsetenv "SSH_ASKPASS_PROMPT")
          (if (null? a) #f (if (= (Str8 length a) 0) #t (str=? (Str8 downcase a) "yes")))))))

(def %set? (fn (_ name) ((fn (_ v) (if (null? v) #f (> (Str8 length v) 0))) (Sys getenv name))))

; The control socket made at path, as OpenSSH's muxserver_listen makes
; it: under umask 0177 at a name of its own, then linked into place, so
; no client finds it before it listens.  The descriptor, or () when path
; is taken, said as OpenSSH says it.
(def %control-listen
  (fn (_ path)
    (def temp (Str8 append path "." (%num (Sys getpid)) "." (%num (Sys now))))
    (def old (ssh-sys-umask 127))
    (def fd (guard (e ()) (Socket unix-listen temp)))
    (ssh-sys-umask old)
    (def placed (if (null? fd) #f (guard (e #f) (do (File link temp path) #t))))
    (guard (e ()) (File unlink temp))
    (if placed fd
      (do (unless (null? fd) (Socket close fd))
          (%say (Str8 append "ControlSocket " path " already exists, disabling multiplexing\n"))
          ()))))

; A control connection ended: closed, or, when it asked for a channel,
; that channel closed, the connection closed with it once the server
; has closed it.
(def %control-drop!
  (fn (_ c run k)
    (def fd (first k))
    (def owner (List find (fn (_ ch) (= (first (%ch ch %CTL)) fd)) (%shared run)))
    (%rn! run %CONTROLS (List filter (fn (_ x) (not (= (first x) fd))) (%rn run %CONTROLS)))
    (if (null? owner) (guard (e ()) (Socket close fd))
      (do (unless (null? (%ch owner %SERVER)) (%shut! c owner))
          (%ch! owner %INPUT ())))))

; A control connection's next request read and answered.
(def %control-read!
  (fn (_ c run k)
    (def fd (first k))
    (def m (ssh-mux-receive fd))
    (match
      ((null? m) (%control-drop! c run k))
      ((not (List ref 1 k))
        (if (= (first m) ssh-mux-hello)
          (%rn! run %CONTROLS (List map (fn (_ x) (if (= (first x) fd) (list fd #t) x)) (%rn run %CONTROLS)))
          (%control-drop! c run k)))
      (#t (do (def rid (ssh-get-uint32 (rest m)))
              (def host (List ref 3 (%rn run %CONTROL)))
              (def deny (fn (_) (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-permission-denied rid "Permission denied"))))
              (match
                ((= (first m) ssh-mux-alive-check)
                  (ssh-mux-send! fd (ssh-mux-reply-two ssh-mux-alive rid (Sys getpid))))
                ((= (first m) ssh-mux-terminate)
                  (if (%allowed? run (Str8 append "Terminate shared connection to " host "? "))
                    (do (ssh-mux-send! fd (ssh-mux-reply-ok rid)) (%rn! run %ENDED #t))
                    (deny)))
                ((= (first m) ssh-mux-stop-listening)
                  (if (%allowed? run (Str8 append "Disable further multiplexing on shared connection to " host "? "))
                    (do (%control-close! run) (ssh-mux-send! fd (ssh-mux-reply-ok rid)))
                    (deny)))
                ((= (first m) ssh-mux-new-session) (%mux-session! c run fd rid (rest m)))
                ((= (first m) ssh-mux-new-stdio-fwd) (%mux-stdio! c run fd rid (rest m)))
                (#t (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-failure rid "unsupported request")))))))))

; n descriptors a client passes after its request: them, or () when any
; fails to come, those that came closed.
(def %take-fds
  (fn (_ fd n)
    ((fn (self i acc)
       (if (= i n) (List reverse acc)
         ((fn (_ got) (if (null? got) (do (List for-each (fn (_ d) (guard (e ()) (File close d))) acc) ())
                        (self (+ i 1) (pair got acc))))
          (ssh-mux-take-fd fd))))
     0 ())))

(def %writer (fn (_ fd) (fn (_ buf start len) (guard (e ()) (File write fd (ssh-copy buf start len) len)))))

; NEW_SESSION: the client's three descriptors, then, allowed, a session
; channel over them with the client's terminal, its modes read from the
; descriptor before the client makes it raw, and its environment.
(def %mux-session!
  (fn (_ c run fd rid in)
    (def req (ssh-mux-session-request in))
    (def fds (%take-fds fd 3))
    (match
      ((null? fds) (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-failure rid "did not receive file descriptors")))
      ((not (null? (List find (fn (_ ch) (= (first (%ch ch %CTL)) fd)) (%shared run))))
        (do (List for-each (fn (_ d) (guard (e ()) (File close d))) fds)
            (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-failure rid "Multiple sessions not supported"))))
      ((not (%allowed? run (Str8 append "Allow shared connection to " (List ref 3 (%rn run %CONTROL)) "? ")))
        (do (List for-each (fn (_ d) (guard (e ()) (File close d))) fds)
            (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-permission-denied rid "Permission denied"))))
      (#t
        (do (def tty? (first req))
            (def input (first fds))
            (def tty (if tty? (list (List ref 4 req) (fn (_) (Term window input)) (guard (e ()) (Term modes input)) (List ref 3 req)) ()))
            (def command (match ((List ref 2 req) (pair (lit subsystem) (List ref 5 req)))
                                ((= (Str8 length (List ref 5 req)) 0) (lit shell))
                                (#t (List ref 5 req))))
            (def env (List flat-map (fn (_ e) (def i (Str8 index-of "=" e))
                                         (if (null? i) () (list (pair (Str8 sub 0 i e) (Str8 sub (+ i 1) (- (Str8 length e) i 1) e)))))
                       (List ref 6 req)))
            (def ch (%session-channel! c run command input (%writer (List ref 1 fds)) (%writer (List ref 2 fds))
                      tty env (if (List ref 1 req) (%rn run %RUN-AGENT) ())))
            (%ch! ch %CTL (list fd rid fds)))))))

; NEW_STDIO_FWD: the client's input and output, then, allowed, a
; direct-tcpip channel over them to the host and port it names.
(def %mux-stdio!
  (fn (_ c run fd rid in)
    (ssh-get-text in)
    (def host (ssh-get-text in))
    (def port (ssh-get-uint32 in))
    (def fds (%take-fds fd 2))
    (match
      ((null? fds) (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-failure rid "did not receive file descriptors")))
      ((not (%allowed? run (Str8 append "Allow forward to " host ":" (%num port) "? ")))
        (do (List for-each (fn (_ d) (guard (e ()) (File close d))) fds)
            (ssh-mux-send! fd (ssh-mux-reply-error ssh-mux-permission-denied rid "Permission denied"))))
      (#t
        (do (def ch (%channel! run (lit stdio) (first fds) (%writer (List ref 1 fds)) () () ()))
            (%ch! ch %CTL (list fd rid fds))
            (def open (%open-packet ch "direct-tcpip"))
            (ssh-put-text open host)
            (ssh-put-uint32 open port)
            (ssh-put-text open "127.0.0.1")
            (ssh-put-uint32 open 65535)
            (%send c open))))))

; The control socket closed and its path removed: no client more, those
; connected still heard.
(def %control-close!
  (fn (_ run)
    (def ctl (%rn run %CONTROL))
    (unless (if (null? ctl) #t (null? (first ctl)))
      (do (guard (e ()) (Socket close (first ctl)))
          (guard (e ()) (File unlink (List ref 1 ctl)))
          (%rn! run %CONTROL (pair () (rest ctl)))))))

; A global request from the server: none is served; answered when it
; wants an answer.
(def %global!
  (fn (_ c in)
    (ssh-get-text in)
    (when (ssh-get-bool in) (%send c (%packet-of ssh-msg-request-failure)))))

; One packet from the server handled: a channel message is for the
; channel it names, ours; one the transport keeps (EXT_INFO, IGNORE)
; is only a packet received.
(def %handle!
  (fn (_ c run)
    (def p (ssh-take-packet! c))
    (ssh-clock-mark! ssh-clock-recv)
    (unless (null? p) (%packet! c run p))))

(def %packet!
  (fn (_ c run p)
    (def t (%byte (first p) 0))
    (when (if (= t %msg-channel-data) #t (= t %msg-channel-extended-data)) (ssh-clock-mark! ssh-clock-data))
    (def in (ssh-in (first p) 1 (- (rest p) 1)))
    (def ch (if (if (>= t %msg-channel-open-confirmation) (<= t %msg-channel-failure) #f)
              (%find run (ssh-get-uint32 in))
              ()))
    (match
      ((= t ssh-msg-global-request) (%global! c in))
      ((= t ssh-msg-request-success) (%answered! run #t))
      ((= t ssh-msg-request-failure) (%answered! run #f))
      ((= t %msg-channel-open) (%opened! c run in))
      ((null? ch) ())
      ((= t %msg-channel-open-confirmation)
        (do (%ch! ch %SERVER (ssh-get-uint32 in))
            (%ch! ch %WINDOW (ssh-get-uint32 in))
            (%ch! ch %MAX (ssh-get-uint32 in))
            ; a sharing client hears its session or stdio forward is open
            (unless (null? (%ch ch %CTL))
              (%mux-tell ch (ssh-mux-reply-two ssh-mux-session-opened (List ref 1 (%ch ch %CTL)) (%ch ch %OURS))))
            (when (eq? (%ch ch %KIND) (lit session))
              (do ; the agent forwarded first, as OpenSSH asks, wanting no answer
                  (unless (null? (%ch ch %AGENT))
                    (do (def a (%packet-of %msg-channel-request))
                        (ssh-put-uint32 a (%ch ch %SERVER))
                        (ssh-put-text a "auth-agent-req@openssh.com")
                        (ssh-put-bool a #f)
                        (%send c a)))
                  ; then the environment, each variable a request
                  ; wanting no answer: a server may refuse any of them
                  (List for-each
                    (fn (_ v)
                      (def e (%packet-of %msg-channel-request))
                      (ssh-put-uint32 e (%ch ch %SERVER))
                      (ssh-put-text e "env")
                      (ssh-put-bool e #f)
                      (ssh-put-text e (first v))
                      (ssh-put-text e (rest v))
                      (%send c e))
                    (%ch ch %ENV))
                  ; a terminal (RFC 4254 6.2), wanting no answer, as
                  ; OpenSSH's -t: TERM, the window in characters and
                  ; pixels, and the local terminal's modes
                  (unless (null? (%ch ch %TTY))
                    (do (def p (%packet-of %msg-channel-request))
                        (def size (%ch ch %SIZE))
                        (def modes (ssh-tty-modes-encode (List ref 2 (%ch ch %TTY))))
                        (ssh-put-uint32 p (%ch ch %SERVER))
                        (ssh-put-text p "pty-req")
                        (ssh-put-bool p #f)
                        (ssh-put-text p (first (%ch ch %TTY)))
                        (ssh-put-uint32 p (first size))
                        (ssh-put-uint32 p (rest size))
                        (ssh-put-uint32 p 0)
                        (ssh-put-uint32 p 0)
                        (ssh-put-string p (first modes) 0 (rest modes))
                        (%send c p)))
                  (def req (%packet-of %msg-channel-request))
                  ; a shell, a command, or a subsystem by its name (RFC
                  ; 4254 6.5), the command then (subsystem . NAME)
                  (def command (%ch ch %COMMAND))
                  (def shell? (eq? command (lit shell)))
                  (def sub? (pair? command))
                  (ssh-put-uint32 req (%ch ch %SERVER))
                  (ssh-put-text req (match (shell? "shell") (sub? "subsystem") (#t "exec")))
                  (ssh-put-bool req #t)
                  (unless shell? (ssh-put-text req (if sub? (rest command) command)))
                  (%send c req)
                  (when (null? (%ch ch %INPUT)) (%input-done! c ch))))))
      ((= t %msg-channel-open-failure)
        (do (ssh-get-uint32 in)
            (def why (ssh-get-text in))
            (match
              ; a sharing client's: refused to it, the master going on
              ((not (null? (%ch ch %CTL)))
                (do (%mux-tell ch (ssh-mux-reply-error ssh-mux-failure (List ref 1 (%ch ch %CTL)) "Session open refused by peer"))
                    (%mux-done! run ch)))
              ((not (eq? (%ch ch %KIND) (lit forward)))
                (Err raise 'io (Str8 append "ssh: the server refused the channel: " why) ()))
              (#t (do (%say (Str8 append "x-ssh: the server refused the forward: " why "\n"))
                      (guard (e ()) (Socket close (%ch ch %FD)))
                      (%drop! run ch))))))
      ((= t %msg-channel-failure)
        (when (eq? (%ch ch %KIND) (lit session))
          (if (null? (%ch ch %CTL))
            (Err raise 'io (if (pair? (%ch ch %COMMAND)) "subsystem request failed on channel 0" "ssh: the server refused the command") ())
            ; a sharing client's command refused: its channel closed
            (%shut! c ch))))
      ((= t %msg-channel-window-adjust)
        (%ch! ch %WINDOW (+ (%ch ch %WINDOW) (ssh-get-uint32 in))))
      ((= t %msg-channel-data)
        (do (def r (ssh-get-string in))
            ((%ch ch %OUT) (ssh-in-buf in) (first r) (rest r))
            (%refill c ch (rest r))
            (%moved! run (rest r))))
      ((= t %msg-channel-extended-data)
        (do (ssh-get-uint32 in)
            (def r (ssh-get-string in))
            (unless (null? (%ch ch %ERR)) ((%ch ch %ERR) (ssh-in-buf in) (first r) (rest r)))
            (%refill c ch (rest r))
            (%moved! run (rest r))))
      ((= t %msg-channel-request)
        (do (def name (ssh-get-text in))
            (def want-reply (ssh-get-bool in))
            (when (str=? name "exit-status")
              (do (%ch! ch %STATUS (ssh-get-uint32 in))
                  ; a sharing client hears it as its own
                  (unless (null? (%ch ch %CTL))
                    (%mux-tell ch (ssh-mux-reply-two ssh-mux-exit-message (%ch ch %OURS) (%ch ch %STATUS))))))
            (when want-reply
              (do (def no (%packet-of %msg-channel-failure))
                  (ssh-put-uint32 no (%ch ch %SERVER))
                  (%send c no)))))
      ((= t %msg-channel-eof)
        ; a forward's far end has no more: its connection hears so, as
        ; does a sharing client's -W output
        (match
          ((eq? (%ch ch %KIND) (lit forward)) (guard (e ()) (Socket shutdown (%ch ch %FD) (lit write))))
          ((eq? (%ch ch %KIND) (lit stdio))
            (do (def ctl (%ch ch %CTL))
                (def fds (List ref 2 ctl))
                (when (= (List length fds) 2)
                  (do (guard (e ()) (File close (List ref 1 fds)))
                      (%ch! ch %OUT (fn (_ b s n) ()))
                      (%ch! ch %CTL (list (first ctl) (List ref 1 ctl) (list (first fds))))))))
          (#t ())))
      ((= t %msg-channel-close) (%close! c run ch))
      ; success needs nothing
      (#t ()))))

(def %ready?
  (fn (_ ready fd)
    (List any? (fn (_ r) (if (= (first r) fd) (not (null? (rest r))) #f)) ready)))

; The channels whose input is waited on: open, not ended, with room.
(def %readable
  (fn (_ run)
    (List filter (fn (_ ch) (if (null? (%ch ch %INPUT)) #f
                              (if (null? (%ch ch %SERVER)) #f (> (%ch ch %WINDOW) 0))))
      (%rn run %CHANNELS))))

; The command run on the server, () for none, with input the descriptor
; its standard input is read from (() for none: EOF at once), on-out and
; on-err called with each (BUF START LEN) of its output as it arrives;
; each forward (ADDRESS PORT HOST PORT GIVEN LPATH CPATH) listened on,
; ADDRESS () for every one, or on the socket LPATH, its connections
; carried to HOST:PORT, or the socket CPATH, through the server; and each
; remote of the same shape asked of the server, ADDRESS () for
; every one, the connections it opens carried to HOST:PORT, or CPATH, from here,
; HOST () for SOCKS, where open allows (see %OPEN);
; and netcat (HOST . PORT) or (), -W's: a direct-tcpip channel to
; HOST:PORT whose two ways are input and on-out, in a session's place;
; env, the session's environment as (NAME . VALUE)s; tty, its terminal
; as a channel's (see %TTY), or (); agent, the agent socket forwarded
; to the session, or (); and open, where a remote forward's SOCKS
; requests may go; streamlocal, (MASK . UNLINK), StreamLocalBindMask
; and StreamLocalBindUnlink; and control, (PATH ASK HOST), the control
; socket sharing clients find the connection at, ASK whether each is
; confirmed and HOST the name they are asked about, or () for none.
; Runs until the session channel closes and every sharing client's
; channel with it, or, with no command, until the connection ends, or
; until a sharing client asks the run to end.  Answers the exit status,
; or () when the server gave none.
(def ssh-session-run!
  (fn (_ c command input on-out on-err forwards remotes netcat limits env tty agent open streamlocal control)
    (def run (Vector make 13 ()))
    (ssh-clocks-start!)
    (%rn! run %CHANNELS ()) (%rn! run %NEXT 0) (%rn! run %MOVED 0)
    (%rn! run %REMOTES remotes) (%rn! run %UNANSWERED ()) (%rn! run %RUN-AGENT agent)
    (%rn! run %SOCKS ()) (%rn! run %OPEN open) (%rn! run %CONTROLS ()) (%rn! run %ENDED #f)
    (%rn! run %CONTROL
      (if (null? control) ()
        ((fn (_ fd) (if (null? fd) () (pair fd control))) (%control-listen (first control)))))
    (%rn! run %LISTENERS
      (List filter (fn (_ l) (not (null? l))) (List map (fn (_ f) (%listen f streamlocal)) forwards)))
    (List for-each (fn (_ r) (%ask-remote! c run r)) remotes)
    (unless (null? command) (%open-session! c run command input on-out on-err tty env agent))
    (unless (null? netcat) (%open-netcat! c run (first netcat) (rest netcat) input on-out))
    (def sock (ssh-fd c))
    (def failed
      (guard (e (guard (e2 "an internal error") (e msg)))
        ((fn (self)
           (unless (if (%rn run %ENDED) #t
                     (if (null? (%rn run %SESSION)) #f
                       (if (%ch (%rn run %SESSION) %CLOSED) (null? (%shared run)) #f)))
             (do (if (ssh-pending? c)
                   (%handle! c run)
                   (do (def inputs (%readable run))
                       (def listener (if (null? (%rn run %CONTROL)) () (if (null? (first (%rn run %CONTROL))) () (list (first (%rn run %CONTROL))))))
                       (def ready
                         (Sys poll (List append (list (pair sock (list (lit in))))
                                                (List map (fn (_ l) (pair (first l) (list (lit in)))) (%rn run %LISTENERS))
                                                (List map (fn (_ ch) (pair (%ch ch %INPUT) (list (lit in)))) inputs)
                                                (List map (fn (_ w) (pair (first w) (list (lit in)))) (%rn run %SOCKS))
                                                (List map (fn (_ fd) (pair fd (list (lit in)))) listener)
                                                (List map (fn (_ k) (pair (first k) (list (lit in)))) (%rn run %CONTROLS)))
                                   (%poll-ms run limits)))
                       (List for-each
                         (fn (_ l) (when (%ready? ready (first l))
                                     ; to a socket, to a host and port, or, on a dynamic
                                     ; listener, where its connection says first
                                     ((fn (_ fd) (match ((not (null? (List ref 3 l))) (%open-streamlocal! c run fd (List ref 3 l)))
                                                        ((List ref 1 l) (%open-forward! c run fd (List ref 1 l) (List ref 2 l)))
                                                        (#t (%socks-wait! run fd))))
                                      (Socket accept (first l)))))
                         (%rn run %LISTENERS))
                       (List for-each
                         (fn (_ ch) (when (%ready? ready (%ch ch %INPUT)) (%pump! c run ch)))
                         inputs)
                       (List for-each (fn (_ w) (when (%ready? ready (first w)) (%socks-read! c run w))) (%rn run %SOCKS))
                       ; a sharing client: greeted, then heard request by request
                       (List for-each
                         (fn (_ fd) (when (%ready? ready fd)
                                      ((fn (_ k) (unless (null? k)
                                                   (if (ssh-mux-send! k (ssh-mux-hello-message))
                                                     (%rn! run %CONTROLS (List append (%rn run %CONTROLS) (list (list k #f))))
                                                     (guard (e ()) (Socket close k)))))
                                       (guard (e ()) (Socket accept fd)))))
                         listener)
                       ; a request malformed drops its client alone
                       (List for-each (fn (_ k) (when (%ready? ready (first k))
                                                  (guard (e (%control-drop! c run k)) (%control-read! c run k))))
                         (%rn run %CONTROLS))
                       (when (%ready? ready sock) (%handle! c run))
                       (ssh-clocks! c limits)
                       (%resized! c run)))
                 (when (> (%rn run %MOVED) %collect-every)
                   (do (Heap collect) (%rn! run %MOVED 0)))
                 (self)))))
        ()))
    ; the control socket gone with the run, its clients' connections too
    (%control-close! run)
    (List for-each (fn (_ ch) (%mux-done! run ch)) (%shared run))
    (List for-each (fn (_ k) (guard (e ()) (Socket close (first k)))) (%rn run %CONTROLS))
    (unless (null? failed) (Err raise 'io failed ()))
    (if (null? (%rn run %SESSION)) () (%ch (%rn run %SESSION) %STATUS))))

; The window given back once half of it is used, as OpenSSH gives it: the
; server keeps sending, and a run of small packets costs no adjust each.
(def %refill
  (fn (_ c ch n)
    (def owed (+ (%ch ch %OWED) n))
    (if (< owed (>> %window 1))
      (%ch! ch %OWED owed)
      (do (def adj (%packet-of %msg-channel-window-adjust))
          (ssh-put-uint32 adj (%ch ch %SERVER))
          (ssh-put-uint32 adj owed)
          (%send c adj)
          (%ch! ch %OWED 0)))))

; A courteous end: DISCONNECT by application, before the socket closes.
(def ssh-disconnect!
  (fn (_ c)
    (def d (%packet-of ssh-msg-disconnect))
    (ssh-put-uint32 d 11)
    (ssh-put-text d "by application")
    (ssh-put-text d "")
    (%send c d)))

(provide ssh/session ssh-session-run! ssh-disconnect!)
