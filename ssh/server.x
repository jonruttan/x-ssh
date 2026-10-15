; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/server.x -- the server: commands run for authenticated keys
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What dropbear does as a user's own server: listen, take each connection
; in a process of its own, exchange keys under the host key, let in the
; user it runs as by an ssh-ed25519 key in authorized_keys, and run the
; command an "exec" asks for in the user's shell, its standard input the
; channel's data and its output the channel's, its exit status sent back.
; One suite, the client's: curve25519-sha256, ssh-ed25519,
; chacha20-poly1305@openssh.com.  Not served yet: passwords, other users
; (that is a root server's business), terminals and shells, forwarding.
; Like Dropbear's, the log is on standard error, a line an event.

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
  ssh-msg-userauth-request ssh-msg-userauth-failure ssh-msg-userauth-success
  ssh-msg-global-request ssh-msg-request-success ssh-msg-request-failure)
(import ssh/keys ssh-key-of-file)
(import x/codec/ed25519)
(import ssh/keygen ssh-keygen-make ssh-key-fingerprint)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %cvt (prim-ref (lit convert) (lit to)))

(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))

(def %log
  (fn (_ text)
    (def line (Str8 append "[" (%num (Sys getpid)) "] " text "\n"))
    (File write 2 line (%byte-len line))))

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

; --- authorized_keys --------------------------------------------------------

; The base64 key of every ssh-ed25519 line in the file, options or not.
(def %authorized
  (fn (_ dir)
    (def path (Str8 append dir "/authorized_keys"))
    (if (not (File exists? path)) ()
      ((fn (self lines acc)
         (if (null? lines) acc
           (do (def ws (List filter (fn (_ w) (> (Str8 length w) 0))
                         (Str8 split " " (Str8 join " " (Str8 split "\t" (first lines))))))
               ; the key follows its type, wherever options put the type
               (def at ((fn (self ws) (if (null? ws) () (if (str=? (first ws) "ssh-ed25519") ws (self (rest ws))))) ws))
               (self (rest lines)
                 (if (if (null? at) #t (null? (rest at))) acc (pair (first (rest at)) acc))))))
       (Str8 split "\n" (File read-all path)) ()))))

; --- authentication (RFC 4252), publickey with ssh-ed25519 ---------------

(def %failure
  (fn (_ c)
    (def f (%packet-of ssh-msg-userauth-failure))
    (ssh-put-names f (list "publickey"))
    (ssh-put-bool f #f)
    (%send c f)))

; Requests answered until one succeeds: the user this server runs as, by
; a key in authorized_keys whose signature over the session id and the
; request checks.  A request with no signature asks whether the key
; would do, and is answered PK_OK when it would.  Answers the user.
(def %authenticate
  (fn (_ c dir peer)
    (def sr (ssh-expect! c ssh-msg-service-request "SERVICE_REQUEST"))
    (def sin (ssh-in (first sr) 1 (- (rest sr) 1)))
    (unless (str=? (ssh-get-text sin) "ssh-userauth")
      (Err raise 'value "ssh: a service other than ssh-userauth asked for" ()))
    (def sa (%packet-of ssh-msg-service-accept))
    (ssh-put-text sa "ssh-userauth")
    (%send c sa)
    (def me (Sys getenv "USER"))
    (def keys (%authorized dir))
    ((fn (self)
       (def p (ssh-expect! c ssh-msg-userauth-request "USERAUTH_REQUEST"))
       (def in (ssh-in (first p) 1 (- (rest p) 1)))
       (def user (ssh-get-text in))
       (def service (ssh-get-text in))
       (def method (ssh-get-text in))
       (if (if (str=? method "publickey") (str=? user me) #f)
         (do (def signed? (ssh-get-bool in))
             (def alg (ssh-get-text in))
             (def blob (ssh-get-string in))
             (def b64 (Base64 encode-bytes (%bytes (ssh-in-buf in) (first blob) (rest blob))))
             (def kin (ssh-in (ssh-in-buf in) (first blob) (rest blob)))
             (def known (if (str=? alg "ssh-ed25519") (List any? (fn (_ k) (str=? k b64)) keys) #f))
             (match
               ((not known) (do (%failure c) (self)))
               ((not signed?)
                 (do (def ok (%packet-of %msg-userauth-pk-ok))
                     (ssh-put-text ok alg)
                     (ssh-put-string ok (ssh-in-buf in) (first blob) (rest blob))
                     (%send c ok)
                     (self)))
               (#t
                 (do (ssh-get-text kin)
                     (def pub (ssh-get-bytes kin))
                     (def sig (ssh-get-string in))
                     (def sin2 (ssh-in (ssh-in-buf in) (first sig) (rest sig)))
                     (ssh-get-text sin2)
                     (def sig64 (ssh-get-bytes sin2))
                     ; what was signed: the session id as a string, then the
                     ; request up to the signature's own length field
                     (def data (ssh-out))
                     (ssh-put-string data (ssh-session-id c) 0 32)
                     (ssh-put-bytes data (first p) 0 (- (first sig) 4))
                     (def msg (ssh-out-run data))
                     (if (Ed25519 verify pub sig64 (first msg) 0 (rest msg))
                       (do (%send c (%packet-of ssh-msg-userauth-success))
                           (%log (Str8 append "Pubkey auth succeeded for '" user "' with ssh-ed25519 key "
                                              (ssh-key-fingerprint pub) " from " peer))
                           user)
                       (do (%failure c) (self)))))))
         (do (%failure c) (self)))))))

; --- the command, on three pipes ------------------------------------------

; The command run in the user's shell, its standard input, output and
; error each a pipe: (PID IN OUT ERR), IN the end we write, OUT and ERR
; the ends we read.
(def %spawn
  (fn (_ command sock)
    (def i (Sys pipe)) (def o (Sys pipe)) (def e (Sys pipe))
    (def pid (Sys fork))
    (when (= pid 0)
      (Sys dup2 (first i) 0) (Sys dup2 (rest o) 1) (Sys dup2 (rest e) 2)
      (List for-each (fn (_ fd) (Sys close fd))
        (list (first i) (rest i) (first o) (rest o) (first e) (rest e) sock))
      (def shell (Sys getenv "SHELL"))
      (Sys exec (if (if (null? shell) #t (= (Str8 length shell) 0)) "/bin/sh" shell) (list "-c" command))
      (Sys exit 127))
    (Sys close (first i)) (Sys close (rest o)) (Sys close (rest e))
    (list pid (rest i) (first o) (first e))))

; --- the clocks Dropbear's -K and -I read ------------------------------------
;
; Seconds since the epoch: 1 the last packet sent, 2 the last received,
; 3 the last carrying data either way, 4 the last keepalive asked.  A
; keepalive is asked after -K seconds without sending or receiving; the
; connection is given up after three times that without receiving
; anything; -I seconds without data either way is the idle timeout.  One
; connection a process.
(def %SENT 1) (def %RECV 2) (def %DATA 3) (def %ASKED 4)
(def %clock (Vector make 4 0))
(def %KEEPALIVE-LIMIT 3)

(def %clocks-start! (fn (_) (def now (Sys now)) (%oset! %clock %SENT now) (%oset! %clock %RECV now) (%oset! %clock %DATA now) (%oset! %clock %ASKED now)))

; A keepalive asked: Dropbear's global request, wanting the answer that
; counts as the other end alive.
(def %keepalive!
  (fn (_ c)
    (def req (%packet-of ssh-msg-global-request))
    (ssh-put-text req "keepalive@openssh.com")
    (ssh-put-bool req #t)
    (%send c req)
    (%oset! %clock %ASKED (Sys now))))

; How long a wait may last before a clock wants looking at, in
; milliseconds, or -1 for no limit: limits is (KEEPALIVE . IDLE), 0 for
; never.
(def %wait-ms
  (fn (_ limits)
    (def now (Sys now))
    (def k (first limits)) (def i (rest limits))
    (def dues
      (List append
        (if (> k 0) (list (- (+ (%oref %clock %SENT) k) now) (- (+ (%oref %clock %RECV) k) now)
                          (- (+ (%oref %clock %RECV) (* k %KEEPALIVE-LIMIT)) now)) ())
        (if (> i 0) (list (- (+ (%oref %clock %DATA) i) now)) ())))
    (if (null? dues) -1
      (do (def least (List fold (fn (_ a b) (if (< a b) a b)) (first dues) (rest dues)))
          (if (< least 0) 0 (* 1000 least))))))

; The clocks read: a keepalive asked when due, the connection given up
; or closed when a limit has passed, as Dropbear says it.
(def %clocks!
  (fn (_ c limits)
    (def now (Sys now))
    (def k (first limits)) (def i (rest limits))
    (when (> k 0)
      (do (when (>= (- now (%oref %clock %RECV)) (* k %KEEPALIVE-LIMIT))
            (do (%log "Keepalive timeout") (Err raise 'io "Keepalive timeout" ())))
          (when (if (>= (- now (%oref %clock %SENT)) k) #t
                  (if (>= (- now (%oref %clock %RECV)) k) (>= (- now (%oref %clock %ASKED)) k) #f))
            (%keepalive! c))))
    (when (if (> i 0) (>= (- now (%oref %clock %DATA)) i) #f)
      (do (%log "Idle timeout") (Err raise 'io "Idle timeout" ())))))

; --- the channels (RFC 4254) ---------------------------------------------------
;
; A channel's state, in a vector: 1 the client's channel number, () until
; the client has confirmed one we opened, 2 ours, 3 its window, 4 its
; largest packet, 5 its kind, session or forward, 6 a session's command
; as (PID IN OUT ERR) or (), 7 whether OUT and 8 whether ERR are still
; open (a forward's OUT: whether its connection is still read), 9 a
; forward's connection, 10 whether the client has closed the
; channel, 11 whether we have, 12 whether the client has sent EOF.
(def %PEER 1) (def %OURS 2) (def %WINDOW 3) (def %MAX 4) (def %KIND 5) (def %CHILD 6)
(def %OUT 7) (def %ERR 8) (def %FD 9) (def %PEER-CLOSED 10) (def %CLOSED 11) (def %PEER-EOF 12)
(def %ch (fn (_ ch i) (%oref ch i)))
(def %ch! (fn (_ ch i v) (%oset! ch i v)))

; The connection's state: 1 the channels, 2 the next channel number, 3
; the bytes moved since the last collect, 4 whether a client's forwards
; are served, 5 the session channel or (), 6 whether a client's remote
; forwards are served, 7 whether their listeners may bind an address
; other than localhost, 8 the listeners as (FD ADDRESS PORT), ADDRESS as
; the client asked.
(def %CHANNELS 1) (def %NEXT 2) (def %MOVED 3) (def %FORWARDING 4) (def %SESSION 5)
(def %REMOTE 6) (def %ANY-HOST 7) (def %LISTENERS 8)
(def %rn (fn (_ run i) (%oref run i)))
(def %rn! (fn (_ run i v) (%oset! run i v)))
(def %min (fn (_ a b) (if (< a b) a b)))

(def %moved! (fn (_ run n) (%rn! run %MOVED (+ (%rn run %MOVED) n))))

; A channel added to the table, numbered next.
(def %channel!
  (fn (_ run kind peer window max)
    (def ch (Vector make 12 ()))
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
                      (%log (Str8 append "forward to " host ":" (%num port)))
                      (%confirm! c ch))))))
      (#t (%refuse! c sender 3 (Str8 append "channel type not served: " type))))))

; A global request from the client answered: tcpip-forward listens for
; a remote forward, on localhost unless the server allows any host and
; the client asked for another address, "" every one, as Dropbear has
; it; cancel-tcpip-forward closes that listener; nothing else is served.
(def %global!
  (fn (_ c run in)
    (def name (ssh-get-text in))
    (def want-reply (ssh-get-bool in))
    (def ok
      (match
        ((str=? name "tcpip-forward")
          (do (def address (ssh-get-text in))
              (def port (ssh-get-uint32 in))
              (def bind (if (if (%rn run %ANY-HOST) (not (str=? address "localhost")) #f)
                          (if (str=? address "") () (%address address))
                          "127.0.0.1"))
              (def fd (if (if (%rn run %REMOTE) (> port 0) #f)
                        (guard (e ()) (if (null? bind) (Socket tcp-listen port) (Socket tcp-listen-on bind port)))
                        ()))
              (unless (null? fd)
                (do (%log (Str8 append "remote forward on " address ":" (%num port)))
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
            (%log (Str8 append "the client refused a forwarded connection: " (ssh-get-text in)))
            (guard (e ()) (Socket close (%ch ch %FD)))
            (%drop! run ch)))
      ((= t %msg-channel-request)
        (do (def name (ssh-get-text in))
            (def want-reply (ssh-get-bool in))
            (if (if (str=? name "exec") (if (eq? (%ch ch %KIND) (lit session)) (null? (%ch ch %CHILD)) #f) #f)
              (do (def command (ssh-get-text in))
                  (%log (Str8 append "exec: " command))
                  (%ch! ch %CHILD (%spawn command sock))
                  (%ch! ch %OUT #t) (%ch! ch %ERR #t)
                  (%reply c ch want-reply #t))
              (%reply c ch want-reply #f))))
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
        (if (eq? (%ch ch %KIND) (lit session))
          (unless (null? (%ch ch %CHILD)) (Sys close (List ref 1 (%ch ch %CHILD))))
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
; until the connection ends.  local, remote and any-host are what the
; server allows: a client's forwards, its remote forwards, and those on
; an address other than localhost.
(def %serve-session
  (fn (_ c sock local remote any-host limits)
    (def run (Vector make 8 ()))
    (%clocks-start!)
    (%rn! run %CHANNELS ()) (%rn! run %NEXT 0) (%rn! run %MOVED 0)
    (%rn! run %FORWARDING local) (%rn! run %SESSION ())
    (%rn! run %REMOTE remote) (%rn! run %ANY-HOST any-host) (%rn! run %LISTENERS ())
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
               (%log (Str8 append "exit status " (%num (%finish! c session)))))
             (when (> (%rn run %MOVED) %chunk) (do (Heap collect) (%rn! run %MOVED 0)))
             (self)))))))

; --- the listener ----------------------------------------------------------

; The host key read from keyfile, or under -R made there when the file is
; not there, logged with its fingerprint as Dropbear logs it.  Without
; one the server says what Dropbear says and exits 1.
(def %host-key
  (fn (_ keyfile make)
    (def key (guard (e ()) (ssh-key-of-file keyfile)))
    (match
      ((not (null? key)) key)
      ((not make)
        (do (%log "No hostkeys available. 'dropbear -R' may be useful or run dropbearkey.")
            (Sys exit 1)))
      (#t
        (do (def pub (ssh-keygen-make keyfile))
            (unless pub
              (do (%log (Str8 append "Couldn't read or generate hostkey " keyfile)) (Sys exit 1)))
            (%log (Str8 append "Generated hostkey " keyfile ", fingerprint is " (ssh-key-fingerprint pub)))
            (ssh-key-of-file keyfile))))))

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

; The standard descriptors on /dev/null: in the background the log goes
; nowhere, as Dropbear's does without syslog.
(def %quiet!
  (fn (_)
    (def null (File open "/dev/null" (lit rdwr)))
    (unless (< null 0)
      (do (Sys dup2 null 0) (Sys dup2 null 1) (Sys dup2 null 2)
          (when (> null 2) (File close null))))))

; The pid written to pidfile, so the server can be killed easily; a path
; that cannot be written is let be, as Dropbear lets it.
(def %pidfile!
  (fn (_ path)
    (def fd (File open path (list (lit wronly) (lit creat) (lit trunc)) 420))
    (unless (< fd 0)
      (do (def line (Str8 append (%num (Sys getpid)) "\n"))
          (File write fd line (%byte-len line))
          (File close fd)))))

(def %signal-number
  (fn (_ name)
    (def e (List find (fn (_ p) (str=? (first p) name)) (Sys signals)))
    (if (null? e) () (rest e))))

; One connection served, in its own process.
(def %serve-connection
  (fn (_ fd seed pub dir local remote any-host limits)
    (def peer ((fn (_ p) (Str8 append (first p) ":" (%num (rest p)))) (Socket peer fd)))
    (%log (Str8 append "Child connection from " peer))
    (def c (ssh-open fd ()))
    (def outcome
      (guard (e (Str8 append "Exit from <" peer ">: the connection ended"))
        (ssh-exchange-versions! c)
        (ssh-kex-server! c seed pub)
        (def user (%authenticate c dir peer))
        (%serve-session c fd local remote any-host limits)
        (Str8 append "Exit (" user ") from <" peer ">: Exited normally")))
    (%log outcome)
    (Socket close fd)))

; Connections taken until the process is stopped, each served in a
; process of its own while this one goes back to listening.  The host key
; is read once; a dead connection's process is reaped by the kernel.
(def ssh-serve
  (fn (_ keyfile addr port dir make background pidfile local remote any-host limits)
    (def key (%host-key keyfile make))
    (def lfd
      (guard (e (do (%log (Str8 append "Failed listening on '" (if (null? addr) "" addr) ":" (%num port)
                                       "': the address could not be bound"))
                    (Sys exit 1)))
        (if (null? addr) (Socket tcp-listen port) (Socket tcp-listen-on addr port))))
    (when background (%background!))
    (%log (if background "Running in background" "Not backgrounding"))
    (%pidfile! pidfile)
    (when background (%quiet!))
    ; the engines, built once: each connection's process inherits them
    (ssh-engines! ())
    (def chld (%signal-number "CHLD"))
    (unless (null? chld) (Sys signal chld (Sys sig-ign)))
    ((fn (self)
       (def fd (Socket accept lfd))
       (def pid (Sys fork))
       (if (= pid 0)
         (do (Socket close lfd)
             (unless (null? chld) (Sys signal chld (Sys sig-dfl)))
             (%serve-connection fd (first key) (rest key) dir local remote any-host limits)
             (Sys exit 0))
         (do (Socket close fd)
             (self)))))))

(provide ssh/server ssh-serve)
