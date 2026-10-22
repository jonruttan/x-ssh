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
; channel to the host and port the forward names, and each -R forward is
; asked of the server by a tcpip-forward global request, the connections
; it then opens as forwarded-tcpip channels connected here to the host
; and port the forward names; a forward's bytes are pumped each way until
; both ends close.  The channels are a table keyed by our channel
; number, which every message from the server names first; one loop
; waits on the socket, the listeners, and each channel's input while
; that channel's window has room.

(module ssh/session)

(import x/sys/posix)
(import x/sys/file)
(import x/sys/socket)
(import x/sys/gc)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-text ssh-put-string ssh-out-run
  ssh-in ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-text ssh-in-buf ssh-copy)
(import ssh/transport ssh-fd ssh-pending? ssh-send-packet! ssh-next-packet! ssh-msg-disconnect
  ssh-msg-global-request ssh-msg-request-success ssh-msg-request-failure)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))
(def %num (fn (_ n) ((prim-ref (lit convert) (lit to)) n (Type named STRING) 10)))

(def %msg-channel-open 90) (def %msg-channel-open-confirmation 91)
(def %msg-channel-open-failure 92) (def %msg-channel-window-adjust 93)
(def %msg-channel-data 94) (def %msg-channel-extended-data 95)
(def %msg-channel-eof 96) (def %msg-channel-close 97)
(def %msg-channel-request 98) (def %msg-channel-success 99) (def %msg-channel-failure 100)

(def %window 2097152)
(def %max-packet 32768)

(def %say (fn (_ text) (File write 2 text (%byte-len text))))

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

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset1 (prim-ref (lit ptr) (lit set!)))

; The clocks ServerAliveInterval and ChannelTimeout read, seconds since
; the epoch: 1 the last packet sent, 2 the last received, 3 the last
; carrying data either way, 4 the last keepalive asked.  A keepalive is
; asked after the interval without sending or receiving; the connection
; is given up after ServerAliveCountMax intervals without receiving
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

; A channel's state, in a vector: 1 our channel number, 2 the server's,
; 3 how many bytes it will take from us (its window), 4 the most a packet
; may carry, 5 the descriptor our input is read from, () once it has
; ended, 6 the exit status, 7 whether the server has closed the channel,
; 8 what takes its data, 9 what takes its extended data or (), 10 its
; kind, session or forward, 11 a forward's connection, 12 the session's
; command, 13 the bytes taken from the server not yet given back.
(def %OURS 1) (def %SERVER 2) (def %WINDOW 3) (def %MAX 4) (def %INPUT 5) (def %STATUS 6)
(def %CLOSED 7) (def %OUT 8) (def %ERR 9) (def %KIND 10) (def %FD 11) (def %COMMAND 12)
(def %OWED 13)
(def %ch (fn (_ ch i) (%oref ch i)))
(def %ch! (fn (_ ch i v) (%oset! ch i v)))

; The run's state: 1 the channels, 2 the next channel number, 3 the
; bytes moved since the last collect, 4 the listeners as (FD HOST PORT),
; 5 the session channel or (), 6 the remote forwards as (ADDRESS PORT
; HOST PORT), 7 those whose request the server has yet to answer, in
; the order asked, 8 the environment sent, 9 the terminal asked for, as
; (TERM WINDOW), WINDOW a function answering (COLUMNS . ROWS), or (), 10
; the window last sent, 11 where the escape character stands: 1 at a
; line's start, 2 just after a tilde there, 0 elsewhere.
(def %CHANNELS 1) (def %NEXT 2) (def %MOVED 3) (def %LISTENERS 4) (def %SESSION 5)
(def %REMOTES 6) (def %UNANSWERED 7) (def %ENV 8) (def %TTY 9) (def %SIZE 10) (def %ESC 11)
(def %rn (fn (_ run i) (%oref run i)))
(def %rn! (fn (_ run i v) (%oset! run i v)))

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
    (def ch (Vector make 13 ()))
    (%ch! ch %OURS (%rn run %NEXT))
    (%rn! run %NEXT (+ (%rn run %NEXT) 1))
    (%ch! ch %WINDOW 0) (%ch! ch %MAX 32768) (%ch! ch %INPUT input) (%ch! ch %CLOSED #f) (%ch! ch %OWED 0)
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

; The session channel opened for a command, its input the descriptor
; read for it, () for none.
(def %open-session!
  (fn (_ c run command input on-out on-err)
    (def ch (%channel! run (lit session) input on-out on-err () command))
    (%rn! run %SESSION ch)
    (%send c (%open-packet ch "session"))))

; A connection accepted on a listener opened as a direct-tcpip channel
; to the forward's host and port, the connection its input and output.
(def %open-forward!
  (fn (_ c run fd host port)
    (def peer (Socket peer fd))
    (def ch (%forward-channel! run fd))
    (def open (%open-packet ch "direct-tcpip"))
    (ssh-put-text open host)
    (ssh-put-uint32 open port)
    (ssh-put-text open (first peer))
    (ssh-put-uint32 open (rest peer))
    (%send c open)))

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
; and port, the address "" for every interface, as OpenSSH asks.
(def %ask-remote!
  (fn (_ c run remote)
    (def req (%packet-of ssh-msg-global-request))
    (ssh-put-text req "tcpip-forward")
    (ssh-put-bool req #t)
    (ssh-put-text req (if (null? (first remote)) "" (first remote)))
    (ssh-put-uint32 req (List ref 1 remote))
    (%send c req)
    (%rn! run %UNANSWERED (List append (%rn run %UNANSWERED) (list remote)))))

; The server's answer to the oldest request still open: a refusal said
; as OpenSSH says it.
(def %answered!
  (fn (_ run ok)
    (def asked (%rn run %UNANSWERED))
    (unless (null? asked)
      (do (def r (first asked))
          (%rn! run %UNANSWERED (rest asked))
          (unless ok
            (%say (Str8 append "x-ssh: Remote TCP forward request failed (port " (%num (List ref 1 r))
                              " -> " (List ref 2 r) ":" (%num (List ref 3 r)) ")\n")))))))

; A channel the server opens: a forwarded-tcpip for a remote forward's
; port, connected here to the forward's host and port and confirmed; any
; other, or a connect that fails, refused.
(def %opened!
  (fn (_ c run in)
    (def type (ssh-get-text in))
    (def sender (ssh-get-uint32 in))
    (def window (ssh-get-uint32 in))
    (def max (ssh-get-uint32 in))
    (def port (if (str=? type "forwarded-tcpip") (do (ssh-get-text in) (ssh-get-uint32 in)) ()))
    (def remote (if (null? port) () (List find (fn (_ r) (= (List ref 1 r) port)) (%rn run %REMOTES))))
    (def fd (if (null? remote) ()
              (guard (e ()) (Socket tcp-connect (%address (List ref 2 remote)) (List ref 3 remote)))))
    (if (null? fd)
      (do (def no (%packet-of %msg-channel-open-failure))
          (ssh-put-uint32 no sender)
          (ssh-put-uint32 no (if (null? remote) 1 2))
          (ssh-put-text no (if (null? remote) (Str8 append "unrequested channel: " type) "connect failed"))
          (ssh-put-text no "")
          (%send c no))
      (do (def ch (%forward-channel! run fd))
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
; Typed bytes through OpenSSH's escapes, at a line's start: ~. ends the
; connection, ~~ is one tilde, a tilde before anything else is itself.
; Answers (BUF . N), or raises "escape" for ~.
(def %escape
  (fn (_ run buf got)
    (def out (%make-str (+ (* got 2) 1)))
    (def p (%str->ptr out))
    (def byte (fn (_ i) ((prim-ref (lit char) (lit ->int)) ((prim-ref (lit str) (lit byte-ref)) buf i))))
    (def n
      ((fn (self i n state)
         (if (= i got) (do (%rn! run %ESC state) n)
           (do (def b (byte i))
               (def line? (if (= b 13) #t (= b 10)))
               (match
                 ((= state 2)
                   (match
                     ((= b 46) (Err raise 'io "escape" ()))
                     ((= b 126) (do (%pset1 p n 126 1) (self (+ i 1) (+ n 1) 0)))
                     (#t (do (%pset1 p n 126 1) (%pset1 p (+ n 1) b 1) (self (+ i 1) (+ n 2) (if line? 1 0))))))
                 ((if (= state 1) (= b 126) #f) (self (+ i 1) n 2))
                 (#t (do (%pset1 p n b 1) (self (+ i 1) (+ n 1) (if line? 1 0))))))))
       0 0 (%rn run %ESC)))
    (pair out n)))

; How long the poll may wait: the clocks' limit, and on a terminal half a
; second at most, so a resized window is seen -- a closure cannot be a
; SIGWINCH handler.
(def %poll-ms
  (fn (_ run limits)
    (def w (%wait-ms limits))
    (if (null? (%rn run %TTY)) w (if (if (< w 0) #t (< 500 w)) 500 w))))

; A terminal's window as it is now, sent as window-change when it moved.
(def %resized!
  (fn (_ c run)
    (def session (%rn run %SESSION))
    (unless (if (null? (%rn run %TTY)) #t (if (null? session) #t (null? (%ch session %SERVER))))
      (do (def now ((List ref 1 (%rn run %TTY))))
          (unless (if (= (first now) (first (%rn run %SIZE))) (= (rest now) (rest (%rn run %SIZE))) #f)
            (do (def p (%packet-of %msg-channel-request))
                (ssh-put-uint32 p (%ch session %SERVER))
                (ssh-put-text p "window-change")
                (ssh-put-bool p #f)
                (ssh-put-uint32 p (first now))
                (ssh-put-uint32 p (rest now))
                (ssh-put-uint32 p 0)
                (ssh-put-uint32 p 0)
                (%send c p)
                (%rn! run %SIZE now)))))))

(def %pump!
  (fn (_ c run ch)
    (def n (%min %chunk (%min (%ch ch %WINDOW) (- (%ch ch %MAX) 64))))
    ; a held tilde comes out with the next byte, so a terminal reads one short
    (def raw (%make-str n))
    (def read (File read (%ch ch %INPUT) raw (if (null? (%rn run %TTY)) n (- n 1))))
    (def typed (if (if (< read 1) #f (if (null? (%rn run %TTY)) #f (eq? (%ch ch %KIND) (lit session))))
                 (%escape run raw read)
                 (pair raw read)))
    (def buf (first typed))
    (def got (rest typed))
    (if (< read 1)
      (%input-done! c ch)
      (do (def data (%packet-of %msg-channel-data))
          (ssh-put-uint32 data (%ch ch %SERVER))
          (ssh-put-string data buf 0 got)
          (%send c data)
          (%oset! %clock %DATA (Sys now))
          (%ch! ch %WINDOW (- (%ch ch %WINDOW) got))
          (%moved! run got)))))

; Our close of a channel, after the server's: its connection closed and
; the channel dropped, a session marked closed for the loop's end.
(def %close!
  (fn (_ c run ch)
    (def cl (%packet-of %msg-channel-close))
    (ssh-put-uint32 cl (%ch ch %SERVER))
    (%send c cl)
    (%ch! ch %CLOSED #t)
    (when (eq? (%ch ch %KIND) (lit forward))
      (do (guard (e ()) (Socket close (%ch ch %FD)))
          (%drop! run ch)))))

; A global request from the server: none is served; answered when it
; wants an answer.
(def %global!
  (fn (_ c in)
    (ssh-get-text in)
    (when (ssh-get-bool in) (%send c (%packet-of ssh-msg-request-failure)))))

; One packet from the server handled: a channel message is for the
; channel it names, ours.
(def %handle!
  (fn (_ c run)
    (def p (ssh-next-packet! c))
    (%oset! %clock %RECV (Sys now))
    (def t (%byte (first p) 0))
    (when (if (= t %msg-channel-data) #t (= t %msg-channel-extended-data)) (%oset! %clock %DATA (Sys now)))
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
            (when (eq? (%ch ch %KIND) (lit session))
              (do ; the environment first, each variable a request
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
                    (%rn run %ENV))
                  ; a terminal (RFC 4254 6.2), wanting no answer, as
                  ; OpenSSH's -t: TERM, the window in characters and
                  ; pixels, and the modes, none but the end marker
                  (unless (null? (%rn run %TTY))
                    (do (def p (%packet-of %msg-channel-request))
                        (def size (%rn run %SIZE))
                        (ssh-put-uint32 p (%ch ch %SERVER))
                        (ssh-put-text p "pty-req")
                        (ssh-put-bool p #f)
                        (ssh-put-text p (first (%rn run %TTY)))
                        (ssh-put-uint32 p (first size))
                        (ssh-put-uint32 p (rest size))
                        (ssh-put-uint32 p 0)
                        (ssh-put-uint32 p 0)
                        (ssh-put-uint32 p 1)
                        (ssh-put-byte p 0)
                        (%send c p)))
                  (def req (%packet-of %msg-channel-request))
                  (def shell? (eq? (%ch ch %COMMAND) (lit shell)))
                  (ssh-put-uint32 req (%ch ch %SERVER))
                  (ssh-put-text req (if shell? "shell" "exec"))
                  (ssh-put-bool req #t)
                  (unless shell? (ssh-put-text req (%ch ch %COMMAND)))
                  (%send c req)
                  (when (null? (%ch ch %INPUT)) (%input-done! c ch))))))
      ((= t %msg-channel-open-failure)
        (do (ssh-get-uint32 in)
            (def why (ssh-get-text in))
            (if (not (eq? (%ch ch %KIND) (lit forward)))
              (Err raise 'io (Str8 append "ssh: the server refused the channel: " why) ())
              (do (%say (Str8 append "x-ssh: the server refused the forward: " why "\n"))
                  (guard (e ()) (Socket close (%ch ch %FD)))
                  (%drop! run ch)))))
      ((= t %msg-channel-failure)
        (when (eq? (%ch ch %KIND) (lit session))
          (Err raise 'io "ssh: the server refused the command" ())))
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
            (when (str=? name "exit-status") (%ch! ch %STATUS (ssh-get-uint32 in)))
            (when want-reply
              (do (def no (%packet-of %msg-channel-failure))
                  (ssh-put-uint32 no (%ch ch %SERVER))
                  (%send c no)))))
      ((= t %msg-channel-eof)
        ; a forward's far end has no more: its connection hears so
        (when (eq? (%ch ch %KIND) (lit forward))
          (guard (e ()) (Socket shutdown (%ch ch %FD) (lit write)))))
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
; each forward (ADDRESS PORT HOST PORT) listened on, ADDRESS () for every
; one, its connections carried to HOST:PORT through the server; and each
; remote (ADDRESS PORT HOST PORT) asked of the server, ADDRESS () for
; every one, the connections it opens carried to HOST:PORT from here;
; and netcat (HOST . PORT) or (), -W's: a direct-tcpip channel to
; HOST:PORT whose two ways are input and on-out, in a session's place.
; Runs until the session channel closes, or, with no command, until the
; connection ends.  Answers the exit status, or () when the server gave
; none.
(def ssh-session-run!
  (fn (_ c command input on-out on-err forwards remotes netcat limits env tty)
    (def run (Vector make 11 ()))
    (%clocks-start!)
    (%rn! run %CHANNELS ()) (%rn! run %NEXT 0) (%rn! run %MOVED 0)
    (%rn! run %REMOTES remotes) (%rn! run %UNANSWERED ()) (%rn! run %ENV env)
    (%rn! run %TTY tty) (%rn! run %SIZE (if (null? tty) () ((List ref 1 tty)))) (%rn! run %ESC 1)
    (%rn! run %LISTENERS
      (List map (fn (_ f) (list (if (null? (first f)) (Socket tcp-listen (List ref 1 f))
                                  (Socket tcp-listen-on (first f) (List ref 1 f)))
                                (List ref 2 f) (List ref 3 f)))
        forwards))
    (List for-each (fn (_ r) (%ask-remote! c run r)) remotes)
    (unless (null? command) (%open-session! c run command input on-out on-err))
    (unless (null? netcat) (%open-netcat! c run (first netcat) (rest netcat) input on-out))
    (def sock (ssh-fd c))
    ((fn (self)
       (unless (if (null? (%rn run %SESSION)) #f (%ch (%rn run %SESSION) %CLOSED))
         (do (if (ssh-pending? c)
               (%handle! c run)
               (do (def inputs (%readable run))
                   (def ready
                     (Sys poll (List append (list (pair sock (list (lit in))))
                                            (List map (fn (_ l) (pair (first l) (list (lit in)))) (%rn run %LISTENERS))
                                            (List map (fn (_ ch) (pair (%ch ch %INPUT) (list (lit in)))) inputs))
                               (%poll-ms run limits)))
                   (List for-each
                     (fn (_ l) (when (%ready? ready (first l))
                                 (%open-forward! c run (Socket accept (first l)) (List ref 1 l) (List ref 2 l))))
                     (%rn run %LISTENERS))
                   (List for-each
                     (fn (_ ch) (when (%ready? ready (%ch ch %INPUT)) (%pump! c run ch)))
                     inputs)
                   (when (%ready? ready sock) (%handle! c run))
                   (%clocks! c limits)
                   (%resized! c run)))
             (when (> (%rn run %MOVED) %collect-every)
               (do (Heap collect) (%rn! run %MOVED 0)))
             (self)))))
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
