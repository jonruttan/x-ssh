; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/session.x -- the connection protocol: one session, one command
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; RFC 4254: a session channel opened, "exec" asked of it, its output
; passed on as it arrives, its exit status kept, and the channel closed
; after the server closes it.  The client sends no input: its end of the
; channel is at EOF from the start, which is what a command run for its
; output wants.  The window is refilled as data comes, so a long output
; never stalls.

(module ssh/session)

(import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-text ssh-out-run
  ssh-in ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-text ssh-in-buf)
(import ssh/transport ssh-send-packet! ssh-next-packet! ssh-msg-disconnect)

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

; The command run on the server, on-out and on-err called with each
; (BUF START LEN) of its output as it arrives; the exit status answered,
; or () when the server gave none.
(def ssh-exec!
  (fn (_ c command on-out on-err)
    (def open (%packet-of %msg-channel-open))
    (ssh-put-text open "session")
    (ssh-put-uint32 open 0)
    (ssh-put-uint32 open %window)
    (ssh-put-uint32 open %max-packet)
    (%send c open)
    ((fn (self server status closed)
       (def p (ssh-next-packet! c))
       (def t (%byte (first p) 0))
       (def in (ssh-in (first p) 1 (- (rest p) 1)))
       (match
         ((= t %msg-channel-open-confirmation)
           (do (ssh-get-uint32 in)
               (def s (ssh-get-uint32 in))
               (def req (%packet-of %msg-channel-request))
               (ssh-put-uint32 req s)
               (ssh-put-text req "exec")
               (ssh-put-bool req #t)
               (ssh-put-text req command)
               (%send c req)
               (def eof (%packet-of %msg-channel-eof))
               (ssh-put-uint32 eof s)
               (%send c eof)
               (self s status closed)))
         ((= t %msg-channel-open-failure)
           (do (ssh-get-uint32 in) (ssh-get-uint32 in)
               (Err raise 'io (Str8 append "ssh: the server refused a session: " (ssh-get-text in)) ())))
         ((= t %msg-channel-failure)
           (Err raise 'io "ssh: the server refused the command" ()))
         ((= t %msg-channel-success) (self server status closed))
         ((= t %msg-channel-window-adjust) (self server status closed))
         ((= t %msg-channel-data)
           (do (ssh-get-uint32 in)
               (def r (ssh-get-string in))
               (on-out (ssh-in-buf in) (first r) (rest r))
               (%refill c server (rest r))
               (self server status closed)))
         ((= t %msg-channel-extended-data)
           (do (ssh-get-uint32 in)
               (ssh-get-uint32 in)
               (def r (ssh-get-string in))
               (on-err (ssh-in-buf in) (first r) (rest r))
               (%refill c server (rest r))
               (self server status closed)))
         ((= t %msg-channel-eof) (self server status closed))
         ((= t %msg-channel-request)
           (do (ssh-get-uint32 in)
               (def name (ssh-get-text in))
               (def want-reply (ssh-get-bool in))
               (def st (if (str=? name "exit-status") (ssh-get-uint32 in) status))
               (when want-reply
                 (do (def no (%packet-of %msg-channel-failure))
                     (ssh-put-uint32 no server)
                     (%send c no)))
               (self server st closed)))
         ((= t %msg-channel-close)
           (do (unless closed
                 (do (def cl (%packet-of %msg-channel-close))
                     (ssh-put-uint32 cl server)
                     (%send c cl)))
               status))
         (#t (self server status closed))))
     () () #f)))

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
