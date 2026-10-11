; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/session.x -- the connection protocol: one session, one command
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; RFC 4254: a session channel opened, "exec" asked of it, the command's
; input sent and its output passed on as each arrives, its exit status
; kept, and the channel closed after the server closes it.  The input is
; a descriptor read as it has bytes, sent no faster than the server's
; window allows, with EOF sent when it ends -- what a protocol run over
; the command's pipes, git's among them, needs.  The window we give is
; refilled as data comes, so a long output never stalls.

(module ssh/session)

(import x/type/vector)
(import x/sys/posix)
(import x/sys/file)
(import x/sys/gc)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-text ssh-put-string ssh-out-run
  ssh-in ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-text ssh-in-buf)
(import ssh/transport ssh-fd ssh-pending? ssh-send-packet! ssh-next-packet! ssh-msg-disconnect)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))

(def %msg-channel-open 90) (def %msg-channel-open-confirmation 91)
(def %msg-channel-open-failure 92) (def %msg-channel-window-adjust 93)
(def %msg-channel-data 94) (def %msg-channel-extended-data 95)
(def %msg-channel-eof 96) (def %msg-channel-close 97)
(def %msg-channel-request 98) (def %msg-channel-success 99) (def %msg-channel-failure 100)

(def %window 2097152)
(def %max-packet 32768)

(def %send
  (fn (_ c out)
    (def r (ssh-out-run out))
    (ssh-send-packet! c (first r) (rest r))))

(def %packet-of
  (fn (_ type)
    (def out (ssh-out))
    (ssh-put-byte out type)
    out))

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %make-str (prim-ref (lit str) (lit make)))

; A channel's state, in a vector: 1 the server's channel number, 2 how
; many bytes it will take from us (its window), 3 the most a packet may
; carry, 4 whether our input is still open, 5 the exit status, 6 whether
; the server has closed the channel, 7 the bytes moved since the last
; collect.
(def %SERVER 1) (def %WINDOW 2) (def %MAX 3) (def %INPUT 4) (def %STATUS 5) (def %CLOSED 6)
(def %MOVED 7)
(def %st (fn (_ st i) (%oref st i)))
(def %st! (fn (_ st i v) (%oset! st i v)))

; The most a read of our input takes at once.
(def %chunk 16384)

(def %min (fn (_ a b) (if (< a b) a b)))

; Bytes moved between collects.  x collects only when asked, and every
; byte through the cipher and the authenticator leaves garbage behind, so
; a long transfer is swept as it goes, every input chunk's worth: a 16 KB
; chunk leaves hundreds of megabytes while the codecs run pure-x.
(def %collect-every 16384)

(def %moved! (fn (_ st n) (%st! st %MOVED (+ (%st st %MOVED) n))))

; Our input's end: EOF to the server, and no more reads.
(def %input-done!
  (fn (_ c st)
    (def eof (%packet-of %msg-channel-eof))
    (ssh-put-uint32 eof (%st st %SERVER))
    (%send c eof)
    (%st! st %INPUT #f)))

; One read of our input sent as channel data: as much as is there, the
; window and the packet size allow; a read of nothing is its end.
(def %pump!
  (fn (_ c st input)
    (def n (%min %chunk (%min (%st st %WINDOW) (- (%st st %MAX) 64))))
    (def buf (%make-str n))
    (def got (File read input buf n))
    (if (< got 1)
      (%input-done! c st)
      (do (def data (%packet-of %msg-channel-data))
          (ssh-put-uint32 data (%st st %SERVER))
          (ssh-put-string data buf 0 got)
          (%send c data)
          (%st! st %WINDOW (- (%st st %WINDOW) got))
          (%moved! st got)))))

; One packet from the server handled.
(def %handle!
  (fn (_ c st command input on-out on-err)
    (def p (ssh-next-packet! c))
    (def t (%byte (first p) 0))
    (def in (ssh-in (first p) 1 (- (rest p) 1)))
    (match
      ((= t %msg-channel-open-confirmation)
        (do (ssh-get-uint32 in)
            (%st! st %SERVER (ssh-get-uint32 in))
            (%st! st %WINDOW (ssh-get-uint32 in))
            (%st! st %MAX (ssh-get-uint32 in))
            (def req (%packet-of %msg-channel-request))
            (ssh-put-uint32 req (%st st %SERVER))
            (ssh-put-text req "exec")
            (ssh-put-bool req #t)
            (ssh-put-text req command)
            (%send c req)
            (when (null? input) (%input-done! c st))))
      ((= t %msg-channel-open-failure)
        (do (ssh-get-uint32 in) (ssh-get-uint32 in)
            (Err raise 'io (Str8 append "ssh: the server refused a session: " (ssh-get-text in)) ())))
      ((= t %msg-channel-failure)
        (Err raise 'io "ssh: the server refused the command" ()))
      ((= t %msg-channel-window-adjust)
        (do (ssh-get-uint32 in)
            (%st! st %WINDOW (+ (%st st %WINDOW) (ssh-get-uint32 in)))))
      ((= t %msg-channel-data)
        (do (ssh-get-uint32 in)
            (def r (ssh-get-string in))
            (on-out (ssh-in-buf in) (first r) (rest r))
            (%refill c (%st st %SERVER) (rest r))
            (%moved! st (rest r))))
      ((= t %msg-channel-extended-data)
        (do (ssh-get-uint32 in)
            (ssh-get-uint32 in)
            (def r (ssh-get-string in))
            (on-err (ssh-in-buf in) (first r) (rest r))
            (%refill c (%st st %SERVER) (rest r))
            (%moved! st (rest r))))
      ((= t %msg-channel-request)
        (do (ssh-get-uint32 in)
            (def name (ssh-get-text in))
            (def want-reply (ssh-get-bool in))
            (when (str=? name "exit-status") (%st! st %STATUS (ssh-get-uint32 in)))
            (when want-reply
              (do (def no (%packet-of %msg-channel-failure))
                  (ssh-put-uint32 no (%st st %SERVER))
                  (%send c no)))))
      ((= t %msg-channel-close)
        (do (def cl (%packet-of %msg-channel-close))
            (ssh-put-uint32 cl (%st st %SERVER))
            (%send c cl)
            (%st! st %CLOSED #t)))
      ; success, EOF and anything else need nothing
      (#t ()))))

(def %ready?
  (fn (_ ready fd)
    (List any? (fn (_ r) (if (= (first r) fd) (not (null? (rest r))) #f)) ready)))

; The command run on the server: input the descriptor its standard input
; is read from (() for none: EOF at once), on-out and on-err called with
; each (BUF START LEN) of its output as it arrives.  The exit status is
; answered, or () when the server gave none.  The socket and the input
; are waited on together; the input only while the channel is open, the
; input not yet ended and the server's window not full.
(def ssh-exec!
  (fn (_ c command input on-out on-err)
    (def st (Vector make 7 ()))
    (%st! st %MOVED 0)
    (%st! st %WINDOW 0)
    (%st! st %MAX 32768)
    (%st! st %INPUT (not (null? input)))
    (%st! st %CLOSED #f)
    (def open (%packet-of %msg-channel-open))
    (ssh-put-text open "session")
    (ssh-put-uint32 open 0)
    (ssh-put-uint32 open %window)
    (ssh-put-uint32 open %max-packet)
    (%send c open)
    (def sock (ssh-fd c))
    ((fn (self)
       (unless (%st st %CLOSED)
         (do (if (ssh-pending? c)
               (%handle! c st command input on-out on-err)
               (do (def reading
                     (if (%st st %INPUT)
                       (if (null? (%st st %SERVER)) #f (> (%st st %WINDOW) 0))
                       #f))
                   (def ready
                     (Sys poll (if reading
                                 (list (pair sock (list (lit in))) (pair input (list (lit in))))
                                 (list (pair sock (list (lit in)))))
                               -1))
                   (when (if reading (%ready? ready input) #f) (%pump! c st input))
                   (when (%ready? ready sock) (%handle! c st command input on-out on-err))))
             (when (> (%st st %MOVED) %collect-every)
               (do (Heap collect) (%st! st %MOVED 0)))
             (self)))))
    (%st st %STATUS)))

; The window given back as it is used: the server may keep sending.
(def %refill
  (fn (_ c server n)
    (def adj (%packet-of %msg-channel-window-adjust))
    (ssh-put-uint32 adj server)
    (ssh-put-uint32 adj n)
    (%send c adj)))

; A courteous end: DISCONNECT by application, before the socket closes.
(def ssh-disconnect!
  (fn (_ c)
    (def d (%packet-of ssh-msg-disconnect))
    (ssh-put-uint32 d 11)
    (ssh-put-text d "by application")
    (ssh-put-text d "")
    (%send c d)))

(provide ssh/session ssh-exec! ssh-disconnect!)
