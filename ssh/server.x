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
(import ssh/transport ssh-open ssh-fd ssh-session-id ssh-pending? ssh-exchange-versions! ssh-kex-server!
  ssh-send-packet! ssh-next-packet! ssh-expect! ssh-msg-service-request ssh-msg-service-accept
  ssh-msg-userauth-request ssh-msg-userauth-failure ssh-msg-userauth-success)
(import ssh/keys ssh-key-of-file)
(import ssh/keygen ssh-key-fingerprint)
(import x/codec/ed25519)
(import x/codec/x25519)

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
    (ssh-send-packet! c (first r) (rest r))))

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

; --- the session channel (RFC 4254) ------------------------------------------
;
; A channel's state, in a vector: 1 the client's channel number, 2 its
; window, 3 its largest packet, 4 the command's (PID IN OUT ERR) or (),
; 5 whether OUT and 6 whether ERR are still open, 7 whether the client
; has closed the channel, 8 whether we have, 9 bytes moved since the
; last collect.
(def %PEER 1) (def %WINDOW 2) (def %MAX 3) (def %CHILD 4) (def %OUT 5) (def %ERR 6)
(def %PEER-CLOSED 7) (def %CLOSED 8) (def %MOVED 9)
(def %st (fn (_ st i) (%oref st i)))
(def %st! (fn (_ st i v) (%oset! st i v)))
(def %min (fn (_ a b) (if (< a b) a b)))

(def %moved!
  (fn (_ st n) (%st! st %MOVED (+ (%st st %MOVED) n))))

(def %reply
  (fn (_ c st want-reply ok)
    (when want-reply
      (do (def r (%packet-of (if ok %msg-channel-success %msg-channel-failure)))
          (ssh-put-uint32 r (%st st %PEER))
          (%send c r)))))

; One read of the command's output or error sent on the channel; a read
; of nothing is its end.
(def %pump!
  (fn (_ c st fd slot extended)
    (def n (%min %chunk (%min (%st st %WINDOW) (- (%st st %MAX) 64))))
    (def buf (%make-str n))
    (def got (File read fd buf n))
    (if (< got 1)
      (do (Sys close fd) (%st! st slot #f))
      (do (def d (%packet-of (if extended %msg-channel-extended-data %msg-channel-data)))
          (ssh-put-uint32 d (%st st %PEER))
          (when extended (ssh-put-uint32 d 1))
          (ssh-put-string d buf 0 got)
          (%send c d)
          (%st! st %WINDOW (- (%st st %WINDOW) got))
          (%moved! st got)))))

; The command finished: its status sent, then EOF and CLOSE.
(def %finish!
  (fn (_ c st)
    (def status (Sys wait (first (%st st %CHILD))))
    (def r (%packet-of %msg-channel-request))
    (ssh-put-uint32 r (%st st %PEER))
    (ssh-put-text r "exit-status")
    (ssh-put-bool r #f)
    (ssh-put-uint32 r status)
    (%send c r)
    (def eof (%packet-of %msg-channel-eof))
    (ssh-put-uint32 eof (%st st %PEER))
    (%send c eof)
    (def cl (%packet-of %msg-channel-close))
    (ssh-put-uint32 cl (%st st %PEER))
    (%send c cl)
    (%st! st %CLOSED #t)
    status))

; One packet from the client handled.
(def %handle!
  (fn (_ c st sock)
    (def p (ssh-next-packet! c))
    (def t (%byte (first p) 0))
    (def in (ssh-in (first p) 1 (- (rest p) 1)))
    (match
      ((= t %msg-channel-open)
        (do (def type (ssh-get-text in))
            (def sender (ssh-get-uint32 in))
            (if (if (str=? type "session") (null? (%st st %PEER)) #f)
              (do (%st! st %PEER sender)
                  (%st! st %WINDOW (ssh-get-uint32 in))
                  (%st! st %MAX (ssh-get-uint32 in))
                  (def ok (%packet-of %msg-channel-open-confirmation))
                  (ssh-put-uint32 ok sender)
                  (ssh-put-uint32 ok 0)
                  (ssh-put-uint32 ok %window)
                  (ssh-put-uint32 ok %max-packet)
                  (%send c ok))
              (do (def no (%packet-of %msg-channel-open-failure))
                  (ssh-put-uint32 no sender)
                  (ssh-put-uint32 no 3)
                  (ssh-put-text no "only one session channel is served")
                  (ssh-put-text no "")
                  (%send c no)))))
      ((= t %msg-channel-request)
        (do (ssh-get-uint32 in)
            (def name (ssh-get-text in))
            (def want-reply (ssh-get-bool in))
            (if (if (str=? name "exec") (null? (%st st %CHILD)) #f)
              (do (def command (ssh-get-text in))
                  (%log (Str8 append "exec: " command))
                  (%st! st %CHILD (%spawn command sock))
                  (%st! st %OUT #t) (%st! st %ERR #t)
                  (%reply c st want-reply #t))
              (%reply c st want-reply #f))))
      ((= t %msg-channel-window-adjust)
        (do (ssh-get-uint32 in)
            (%st! st %WINDOW (+ (%st st %WINDOW) (ssh-get-uint32 in)))))
      ((= t %msg-channel-data)
        (do (ssh-get-uint32 in)
            (def r (ssh-get-string in))
            (unless (null? (%st st %CHILD))
              (File write (List ref 1 (%st st %CHILD)) (ssh-copy (ssh-in-buf in) (first r) (rest r)) (rest r)))
            (def adj (%packet-of %msg-channel-window-adjust))
            (ssh-put-uint32 adj (%st st %PEER))
            (ssh-put-uint32 adj (rest r))
            (%send c adj)
            (%moved! st (rest r))))
      ((= t %msg-channel-eof)
        (unless (null? (%st st %CHILD)) (Sys close (List ref 1 (%st st %CHILD)))))
      ((= t %msg-channel-close) (%st! st %PEER-CLOSED #t))
      (#t ()))))

(def %ready?
  (fn (_ ready fd)
    (List any? (fn (_ r) (if (= (first r) fd) (not (null? (rest r))) #f)) ready)))

; The session served until both ends have closed the channel.
(def %serve-session
  (fn (_ c sock)
    (def st (Vector make 9 ()))
    (%st! st %OUT #f) (%st! st %ERR #f)
    (%st! st %PEER-CLOSED #f) (%st! st %CLOSED #f) (%st! st %MOVED 0)
    ((fn (self)
       (unless (if (%st st %PEER-CLOSED) (%st st %CLOSED) #f)
         (do (def child (%st st %CHILD))
             (def room (if (null? (%st st %WINDOW)) #f (> (%st st %WINDOW) 0)))
             (def out (if (if room (%st st %OUT) #f) (List ref 2 child) ()))
             (def err (if (if room (%st st %ERR) #f) (List ref 3 child) ()))
             (if (ssh-pending? c)
               (%handle! c st sock)
               (do (def ready
                     (Sys poll (List append (list (pair sock (list (lit in))))
                                            (if (null? out) () (list (pair out (list (lit in)))))
                                            (if (null? err) () (list (pair err (list (lit in))))))
                               -1))
                   (when (if (null? out) #f (%ready? ready out)) (%pump! c st out %OUT #f))
                   (when (if (null? err) #f (%ready? ready err)) (%pump! c st err %ERR #t))
                   (when (%ready? ready sock) (%handle! c st sock))))
             (when (if (null? child) #f
                     (if (%st st %CLOSED) #f (if (%st st %OUT) #f (not (%st st %ERR)))))
               (%log (Str8 append "exit status " (%num (%finish! c st)))))
             (when (> (%st st %MOVED) %chunk) (do (Heap collect) (%st! st %MOVED 0)))
             (self)))))))

; --- the listener ----------------------------------------------------------

(def %signal-number
  (fn (_ name)
    (def e (List find (fn (_ p) (str=? (first p) name)) (Sys signals)))
    (if (null? e) () (rest e))))

; One connection served, in its own process.
(def %serve-connection
  (fn (_ fd seed pub dir)
    (def peer ((fn (_ p) (Str8 append (first p) ":" (%num (rest p)))) (Socket peer fd)))
    (%log (Str8 append "Child connection from " peer))
    (def c (ssh-open fd ()))
    (def outcome
      (guard (e (Str8 append "Exit from <" peer ">: the connection ended"))
        (ssh-exchange-versions! c)
        (ssh-kex-server! c seed pub)
        (def user (%authenticate c dir peer))
        (%serve-session c fd)
        (Str8 append "Exit (" user ") from <" peer ">: Exited normally")))
    (%log outcome)
    (Socket close fd)))

; Connections taken until the process is stopped, each served in a
; process of its own while this one goes back to listening.  The host key
; is read once; a dead connection's process is reaped by the kernel.
(def ssh-serve
  (fn (_ keyfile addr port dir)
    (def key (ssh-key-of-file keyfile))
    ; the curves' engines, built once: each connection's process inherits them
    (X25519 jit!)
    (Ed25519 jit!)
    (def chld (%signal-number "CHLD"))
    (def lfd
      (guard (e (do (%log (Str8 append "Failed listening on '" (if (null? addr) "" addr) ":" (%num port)
                                       "': the address could not be bound"))
                    (Sys exit 1)))
        (if (null? addr) (Socket tcp-listen port) (Socket tcp-listen-on addr port))))
    (%log "Not backgrounding")
    (unless (null? chld) (Sys signal chld (Sys sig-ign)))
    ((fn (self)
       (def fd (Socket accept lfd))
       (def pid (Sys fork))
       (if (= pid 0)
         (do (Socket close lfd)
             (unless (null? chld) (Sys signal chld (Sys sig-dfl)))
             (%serve-connection fd (first key) (rest key) dir)
             (Sys exit 0))
         (do (Socket close fd)
             (self)))))))

(provide ssh/server ssh-serve)
