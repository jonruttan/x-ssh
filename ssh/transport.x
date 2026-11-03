; # x-ssh -- SSH on x-lang
;
; ## ssh/transport.x -- the transport layer, from either end
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; RFC 4253: the version exchange, the binary packet protocol, the key
; exchange and the keys it derives; RFC 4252 for the authentication that
; follows.  The key exchange is curve25519-sha256.  The ciphers are
; chacha20-poly1305@openssh.com, whose framing is OpenSSH's
; PROTOCOL.chacha20poly1305 -- two keys from the 64 derived, the length
; under the second, the payload under the first from block one, the
; Poly1305 key from block zero, the packet's sequence number the nonce;
; aes128-gcm@openssh.com and aes256-gcm@openssh.com (RFC 5647, the length
; the additional data); and aes128-, aes192- and aes256-ctr (RFC 4344)
; with hmac-sha2-256 or -512 (RFC 6668), or their -etm@openssh.com forms.
;
; Both ends are here: the client's key exchange and authentication, and
; the server's key exchange, the rest of the server being ssh/server.x.
; A connection is a vector: the socket, the bytes received and not yet
; read, the two sequence numbers, the key we send under and the key we
; receive under once there are any, the session id, and the peer's
; version string and host key.

(module ssh/transport)

(import x/type/vector)
(import x/sys/socket)
(import x/sys/file)
(import x/sys/posix)
(import x/codec/hex)
(import x/codec/sha256)
(import x/codec/chacha20)
(import x/codec/poly1305)
(import x/codec/aes)
(import x/codec/ghash)
(import x/codec/hmac)
(import x/codec/sha512)
(import x/codec/x25519)
(import x/codec/ed25519)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-bytes ssh-put-string ssh-put-text ssh-put-mpint ssh-put-names ssh-out-run
  ssh-in ssh-in-left ssh-in-buf ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-bytes ssh-get-text ssh-get-names
  ssh-copy ssh-join ssh-same-bytes?)
(import ssh/pubkey ssh-pubkey-of ssh-pubkey-verify? ssh-pubkey-type ssh-pubkey-base64 ssh-pubkey-blob ssh-pubkey-algorithms
  ssh-identity-pubkey ssh-identity-sign)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset1 (prim-ref (lit ptr) (lit set!)))

(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))

(def ssh-version-string "SSH-2.0-x-ssh_0.1.0")

(def %prefix?
  (fn (_ p s)
    (if (>= (Str8 length s) (Str8 length p)) (str=? (Str8 sub 0 (Str8 length p) s) p) #f)))

; RFC 4253 12 and RFC 4252/4254's message numbers, the ones this client speaks.
(def ssh-msg-disconnect 1) (def ssh-msg-ignore 2) (def ssh-msg-unimplemented 3)
(def ssh-msg-debug 4) (def ssh-msg-service-request 5) (def ssh-msg-service-accept 6)
(def ssh-msg-ext-info 7)
(def ssh-msg-kexinit 20) (def ssh-msg-newkeys 21)
(def ssh-msg-kex-ecdh-init 30) (def ssh-msg-kex-ecdh-reply 31)
(def ssh-msg-userauth-request 50) (def ssh-msg-userauth-failure 51)
(def ssh-msg-userauth-success 52) (def ssh-msg-userauth-banner 53) (def ssh-msg-userauth-pk-ok 60)
(def ssh-msg-global-request 80) (def ssh-msg-request-success 81) (def ssh-msg-request-failure 82)

; --- the connection record ------------------------------------------------
;
; slots: 1 fd | 2 pending bytes (BUF . LEN) | 3 send seq | 4 recv seq
;        5 send keys, a record (below), or () | 6 receive keys or () | 7 session id
;        8 peer's version | 9 server's host key | 10 the trace fn or ()
;        11 the pending packet's length as (SEQ KEY LEN), once unveiled, or ()
;        12 the server's server-sig-algs (RFC 8308), or () until it says
;        13 the ciphers and MACs offered, as (CIPHERS . MACS)

(def %slot (fn (_ c i) (%oref c i)))
(def %slot! (fn (_ c i v) (%oset! c i v)))

(def ssh-open
  (fn (_ fd trace)
    (def c (Vector make 13 ()))
    (%slot! c 1 fd)
    (%slot! c 2 (pair (%make-str 0) 0))
    (%slot! c 3 0)
    (%slot! c 4 0)
    (%slot! c 10 trace)
    (%slot! c 13 (pair ssh-cipher-names ssh-mac-names))
    c))

(def ssh-fd (fn (_ c) (%slot c 1)))
(def ssh-session-id (fn (_ c) (%slot c 7)))
(def ssh-host-key (fn (_ c) (%slot c 9)))
(def ssh-server-sig-algs (fn (_ c) (%slot c 12)))

; Whether received bytes are waiting to be read as a packet: a caller
; that waits on the socket must not, while they are.
; Whether a whole packet is buffered, so a read of it cannot block: its
; length field unveiled as the receive unveils it (under the keys, a
; pure function of the same bytes and sequence number, nothing
; consumed) and the bytes counted against it, the tag included.  A loop
; that waits on other descriptors beside the socket asks this before it
; reads a packet; "any bytes" would have it block in the socket for the
; rest of a packet while a forward's connection waits.
(def ssh-pending?
  (fn (_ c)
    (def run (%slot c 2))
    (def key (%slot c 6))
    (if (< (rest run) (%head-size key)) #f
      (do (def seq (%slot c 4))
          (def known (%slot c 11))
          (def len (if (if (null? known) #f (if (= (first known) seq) (eq? (List ref 1 known) key) #f))
                     (List ref 2 known)
                     (do (def n (%packet-length key seq (first run)))
                         (%slot! c 11 (list seq key n))
                         n)))
          (>= (rest run) (+ 4 len (%trailer key)))))))

(def ssh-trace
  (fn (_ c text) (unless (null? (%slot c 10)) ((%slot c 10) text))))

; The compiled engines, asked for once a process: the key exchange's
; X25519, the signatures' Ed25519, and the packet cipher's ChaCha20 and
; Poly1305.  The curves' builds cost less than one pure-x exchange or
; signature.  The cipher builds its own engine at the first region of 8 KB,
; but Poly1305 only at 48 KB, above any packet: left to itself every
; packet's tag is pure-x, 6.5M objects and 670 ms a 32 KB packet against
; 2 ms compiled.  A host without the JIT answers #f and carries on pure-x,
; identically.  With no connection to trace on, c is ().
(def ssh-engines!
  (fn (_ c)
    (def x (X25519 jit!))
    (def e (Ed25519 jit!))
    (def ch (ChaCha20 jit!))
    (def p (Poly1305 jit!))
    (def %state (fn (_ b) (if b "compiled" "pure-x")))
    (unless (null? c)
      (ssh-trace c (Str8 append "engines x25519 " (%state x) " ed25519 " (%state e)
                              " chacha20 " (%state ch) " poly1305 " (%state p))))
    (and x e ch p)))

; n random bytes, from the system's source.
(def ssh-random
  (fn (_ n)
    (def fd (File open "/dev/urandom" (lit rdonly)))
    (when (< fd 0) (Err raise 'io "ssh: no /dev/urandom" ()))
    (def buf (%make-str n))
    (def got (File read fd buf n))
    (File close fd)
    (unless (= got n) (Err raise 'io "ssh: /dev/urandom came up short" ()))
    buf))

; --- bytes in and out --------------------------------------------------------

; At least n bytes pending: the socket read until there are.
(def %pending!
  (fn (self c n)
    (def run (%slot c 2))
    (when (< (rest run) n)
      (do (def got (Socket recv-run (%slot c 1) 65536))
          (when (null? got) (Err raise 'io "ssh: the connection closed" ()))
          (%slot! c 2 (ssh-join (list (list (first run) 0 (rest run)) (list (first got) 0 (rest got)))))
          (self c n)))))

; The first n pending bytes taken: a fresh string.
(def %take!
  (fn (_ c n)
    (%pending! c n)
    (def run (%slot c 2))
    (def out (ssh-copy (first run) 0 n))
    (%slot! c 2 (pair (ssh-copy (first run) n (- (rest run) n)) (- (rest run) n)))
    out))

(def %send!
  (fn (_ c s n) (Socket send-run (%slot c 1) s n)))

; --- the version exchange (4.2) ------------------------------------------

; Ours sent, theirs read: lines until one begins SSH-, the rest being a
; banner the server may send first.
(def ssh-exchange-versions!
  (fn (_ c)
    (%send! c (Str8 append ssh-version-string "\r\n") (+ (Str8 length ssh-version-string) 2))
    (def line
      ((fn (self)
         (def l (%line! c))
         (if (%prefix? "SSH-" l) l (self)))))
    (%slot! c 8 line)
    (ssh-trace c (Str8 append "server version " line))
    (unless (%prefix? "SSH-2.0-" line)
      (Err raise 'value (Str8 append "ssh: not an SSH 2.0 server: " line) ()))
    line))

; A line of the pending bytes, without its CR LF (LF alone also ends it).
(def %line!
  (fn (_ c)
    ((fn (self i)
       (%pending! c (+ i 1))
       (def run (%slot c 2))
       (if (= (%byte (first run) i) 10)
         (do (def end (if (if (> i 0) (= (%byte (first run) (- i 1)) 13) #f) (- i 1) i))
             (def l (ssh-copy (first run) 0 end))
             (%take! c (+ i 1))
             l)
         (self (+ i 1))))
     0)))

; --- the binary packet protocol (6) -------------------------------------
;
; A direction's keys are a record, made when NEWKEYS puts them in place:
;   1 the cipher: chacha, gcm or ctr
;   2 its key: chacha's as (K_1 . K_2), AES's the derived bytes
;   3 AES's key size in bytes
;   4 AES's IV, a string that moves on as packets go: ctr's 16-byte
;     counter block, gcm's 12-byte nonce, its last 8 bytes the count
;   5 the MAC, for ctr: (HASH KEY SIZE ETM?), HASH sha256 or sha512
; Under chacha20-poly1305 and AES-GCM the length is outside the padding's
; alignment and the tag is the cipher's own.  Under AES-CTR the length is
; enciphered with the rest and aligned with it, and the MAC is
; HMAC(seq || packet); under an -etm MAC (OpenSSH's PROTOCOL) the length
; stays clear and outside the alignment, and the MAC is over seq, the
; length and the ciphertext, checked before a byte is deciphered.

(def %k-cipher (fn (_ k) (%oref k 1)))
(def %k-key (fn (_ k) (%oref k 2)))
(def %k-size (fn (_ k) (%oref k 3)))
(def %k-iv (fn (_ k) (%oref k 4)))
(def %k-mac (fn (_ k) (%oref k 5)))

(def %etm? (fn (_ k) (if (null? k) #f (if (null? (%k-mac k)) #f (List ref 3 (%k-mac k))))))

; Whether the length field is enciphered with the packet (CTR without
; -etm): then the first block, not the first four bytes, tells it.
(def %length-hidden? (fn (_ k) (if (null? k) #f (if (eq? (%k-cipher k) 'ctr) (not (%etm? k)) #f))))

; The bytes after the packet: the tag or the MAC.
(def %trailer
  (fn (_ k)
    (match ((null? k) 0)
           ((eq? (%k-cipher k) 'ctr) (List ref 2 (%k-mac k)))
           (#t 16))))

; The nonce for a sequence number: the eight-byte counter, then the
; number as eight big-endian bytes, which is how the cipher's IV reads.
; constraint: endian = little -- the counter's word write puts it in byte 0
(def %iv
  (fn (_ counter seq)
    (def iv (%make-str 16))
    (def p (%str->ptr iv))
    (%pset1 p 0 counter 8) (%pset1 p 8 0 4)
    (%pset1 p 12 (>> seq 24) 1) (%pset1 p 13 (>> seq 16) 1)
    (%pset1 p 14 (>> seq 8) 1) (%pset1 p 15 seq 1)
    iv))

; A 64-byte key as the cipher uses it, split once as it is put in place:
; (K_1 . K_2), K_1 the second half (the length's), K_2 the first (the
; payload's).
(def %split-key (fn (_ key) (pair (ssh-copy key 32 32) (ssh-copy key 0 32))))

(def %poly-key
  (fn (_ k2 iv0) (ssh-copy (ChaCha20 block k2 iv0) 0 32)))

; n added to the big-endian number in s's bytes from..to-1, in place,
; the carry out of byte from dropped: ctr's counter moved on n blocks,
; gcm's invocation count by one.
(def %bump!
  (fn (_ s from to n)
    (def p (%str->ptr s))
    ((fn (self i carry)
       (unless (if (< i from) #t (= carry 0))
         (do (def v (+ (%byte s i) carry))
             (%pset1 p i (& v 255) 1)
             (self (- i 1) (>> v 8)))))
     (- to 1) n)))

; A sequence number as four big-endian bytes, as the MAC reads it.
(def %seq-bytes
  (fn (_ seq)
    (def s (%make-str 4))
    (def p (%str->ptr s))
    (%pset1 p 0 (>> seq 24) 1) (%pset1 p 1 (>> seq 16) 1) (%pset1 p 2 (>> seq 8) 1) (%pset1 p 3 seq 1)
    s))

; The MAC over seq and a region, as a fresh string.
(def %mac
  (fn (_ k seq s start len)
    (def m (%k-mac k))
    (def in (ssh-join (list (list (%seq-bytes seq) 0 4) (list s start len))))
    (Hmac mac (first m) (list (List ref 1 m) 0 (List ref 2 m)) (list (first in) 0 (rest in)))))

; n bytes of x and y alike, every byte looked at, so how far a forgery
; matched is not timed.
(def %tags-match?
  (fn (_ x xs y ys n)
    (= ((fn (self i acc) (if (= i n) acc (self (+ i 1) (| acc (- (| (%byte x (+ xs i)) (%byte y (+ ys i))) (& (%byte x (+ xs i)) (%byte y (+ ys i))))))))
        0 0)
       0)))

; A packet's length field unveiled from the bytes that start it, nothing
; consumed: the clear bytes under no key, GCM or an -etm MAC; K_1's
; keystream over them under chacha; the first block deciphered under
; CTR, its counter left where it is.
(def %packet-length
  (fn (_ key seq head)
    (def lenb
      (match ((null? key) head)
             ((eq? (%k-cipher key) 'chacha) (ChaCha20 xor (first (%k-key key)) (%iv 0 seq) head 0 4))
             ((%length-hidden? key) (Aes ctr (%k-key key) (%k-size key) (%k-iv key) head 0 16))
             (#t head)))
    (| (<< (%byte lenb 0) 24) (| (<< (%byte lenb 1) 16) (| (<< (%byte lenb 2) 8) (%byte lenb 3))))))

; How many bytes must be in before the length can be unveiled.
(def %head-size (fn (_ key) (if (%length-hidden? key) 16 4)))

; A payload sent as one packet: padded to the cipher's block, eight
; under none and chacha, sixteen under AES, with at least four bytes of
; padding, the length field counted toward the alignment only where it
; is enciphered with the rest; then in the clear or under the keys.
(def ssh-send-packet!
  (fn (_ c payload n)
    (def key (%slot c 5))
    (def seq (%slot c 3))
    (def block (if (null? key) 8 (if (eq? (%k-cipher key) 'chacha) 8 16)))
    (def counted (+ n 1 (if (if (null? key) #t (%length-hidden? key)) 4 0)))
    (def pad ((fn (_ p) (if (< p 4) (+ p block) p)) (- block (& counted (- block 1)))))
    (def len (+ 1 n pad))
    (def body (ssh-out))
    (ssh-put-uint32 body len)
    (ssh-put-byte body pad)
    (ssh-put-bytes body payload 0 n)
    (ssh-put-bytes body (ssh-random pad) 0 pad)
    ; the packet, its length field first: 4 + len bytes
    (def b (first (ssh-out-run body)))
    (def total (+ 4 len))
    (def wire
      (match
        ((null? key) (list (list b 0 total)))
        ((eq? (%k-cipher key) 'chacha)
          (do (def iv0 (%iv 0 seq))
              (def enc-len (ChaCha20 xor (first (%k-key key)) iv0 b 0 4))
              (def enc (ChaCha20 xor (rest (%k-key key)) (%iv 1 seq) b 4 len))
              (def framed (ssh-join (list (list enc-len 0 4) (list enc 0 len))))
              (def tag (Poly1305 mac (%poly-key (rest (%k-key key)) iv0) (first framed) 0 (rest framed)))
              (list (list (first framed) 0 total) (list tag 0 16))))
        ((eq? (%k-cipher key) 'gcm)
          (do (def sealed (Aes gcm-seal (%k-key key) (%k-size key) (%k-iv key) b 0 4 4 len))
              (%bump! (%k-iv key) 4 12 1)
              (list (list b 0 4) (list (first sealed) 0 len) (list (rest sealed) 0 16))))
        ((%etm? key)
          (do (def enc (Aes ctr (%k-key key) (%k-size key) (%k-iv key) b 4 len))
              (%bump! (%k-iv key) 0 16 (>> len 4))
              (def framed (ssh-join (list (list b 0 4) (list enc 0 len))))
              (def mac (%mac key seq (first framed) 0 total))
              (list (list (first framed) 0 total) (list mac 0 (%trailer key)))))
        (#t
          (do (def mac (%mac key seq b 0 total))
              (def enc (Aes ctr (%k-key key) (%k-size key) (%k-iv key) b 0 total))
              (%bump! (%k-iv key) 0 16 (>> total 4))
              (list (list enc 0 total) (list mac 0 (%trailer key)))))))
    (def whole (ssh-join wire))
    (%send! c (first whole) (rest whole))
    (%slot! c 3 (+ seq 1))))

; A packet received: its payload as (BUF . LEN).  Under the keys, the
; length is unveiled first, then the tag or MAC checked before a byte of
; the payload is trusted -- under CTR without -etm, which MACs the
; plaintext, before any is handed on.
(def ssh-recv-packet!
  (fn (_ c)
    (def key (%slot c 6))
    (def seq (%slot c 4))
    (%pending! c (%head-size key))
    (def known (%slot c 11))
    (def len (if (if (null? known) #f (if (= (first known) seq) (eq? (List ref 1 known) key) #f))
               (List ref 2 known)
               (%packet-length key seq (first (%slot c 2)))))
    (%slot! c 11 ())
    (when (if (> len 262144) #t (< len 5)) (Err raise 'value "ssh: a packet of an impossible length" ()))
    (unless (if (null? key) #t (if (eq? (%k-cipher key) 'chacha) #t (= (& (if (%length-hidden? key) (+ len 4) len) 15) 0)))
      (Err raise 'value "ssh: a packet not a whole number of cipher blocks" ()))
    (def total (+ 4 len))
    (def t (%trailer key))
    (def w (%take! c (+ total t)))
    (def forged (fn (_) (Err raise 'value "ssh: a packet failed its authentication tag" ())))
    ; the packet from its padding-length byte on
    (def body
      (match
        ((null? key) (ssh-copy w 4 len))
        ((eq? (%k-cipher key) 'chacha)
          (do (def want (Poly1305 mac (%poly-key (rest (%k-key key)) (%iv 0 seq)) w 0 total))
              (unless (%tags-match? want 0 w total 16) (forged))
              (ChaCha20 xor (rest (%k-key key)) (%iv 1 seq) w 4 len)))
        ((eq? (%k-cipher key) 'gcm)
          (do (def plain (Aes gcm-open (%k-key key) (%k-size key) (%k-iv key) w 0 4 4 len (ssh-copy w total 16)))
              (when (null? plain) (forged))
              (%bump! (%k-iv key) 4 12 1)
              plain))
        ((%etm? key)
          (do (unless (%tags-match? (%mac key seq w 0 total) 0 w total t) (forged))
              (def plain (Aes ctr (%k-key key) (%k-size key) (%k-iv key) w 4 len))
              (%bump! (%k-iv key) 0 16 (>> len 4))
              plain))
        (#t
          (do (def plain (Aes ctr (%k-key key) (%k-size key) (%k-iv key) w 0 total))
              (%bump! (%k-iv key) 0 16 (>> total 4))
              (unless (%tags-match? (%mac key seq plain 0 total) 0 w total t) (forged))
              (ssh-copy plain 4 len)))))
    (%slot! c 4 (+ seq 1))
    (def pad (%byte body 0))
    (pair (ssh-copy body 1 (- len 1 pad)) (- len 1 pad))))

; The next packet that is the transport's business handled here, any
; other handed back: IGNORE, DEBUG and EXT_INFO dropped, a DISCONNECT
; raised with its message; a GLOBAL_REQUEST is the channel layer's to
; answer.
(def ssh-next-packet!
  (fn (self c)
    (def p (ssh-recv-packet! c))
    (def t (%byte (first p) 0))
    (match
      ((= t ssh-msg-ignore) (self c))
      ((= t ssh-msg-debug) (self c))
      ; extensions (RFC 8308): server-sig-algs kept, the rest passed over
      ((= t ssh-msg-ext-info)
        (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
            ((fn (self n)
               (unless (= n 0)
                 (do (def name (ssh-get-text in))
                     (def value (ssh-get-text in))
                     (when (str=? name "server-sig-algs") (%slot! c 12 (Str8 split "," value)))
                     (self (- n 1)))))
             (ssh-get-uint32 in))
            (self c)))
      ((= t ssh-msg-disconnect)
        (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
            (def code (ssh-get-uint32 in))
            (def text (ssh-get-text in))
            (Err raise 'io (Str8 append "ssh: the server disconnected: " text) ())))
      (#t p))))

; The next packet, which must be of type t.
(def ssh-expect!
  (fn (_ c t what)
    (def p (ssh-next-packet! c))
    (unless (= (%byte (first p) 0) t)
      (Err raise 'value (Str8 append "ssh: expected " what ", got message "
                                     ((prim-ref (lit convert) (lit to)) (%byte (first p) 0) (Type named STRING) 10)) ()))
    p))

; --- the keepalive clocks ----------------------------------------------------

; The clocks ServerAliveInterval or ClientAliveInterval and ChannelTimeout
; read, seconds since the epoch: 1 the last packet sent, 2 the last
; received, 3 the last carrying data either way, 4 the last keepalive
; asked.  A keepalive is asked after the interval without sending or
; receiving; the connection is given up after ServerAliveCountMax or
; ClientAliveCountMax intervals without receiving anything; the global
; ChannelTimeout without data either way closes it.  One connection a
; process.
(def ssh-clock-sent 1) (def ssh-clock-recv 2) (def ssh-clock-data 3) (def %ASKED 4)
(def %clock (Vector make 4 0))

(def ssh-clock-mark! (fn (_ i) (%oset! %clock i (Sys now))))

(def ssh-clocks-start! (fn (_) (def now (Sys now)) (%oset! %clock ssh-clock-sent now) (%oset! %clock ssh-clock-recv now) (%oset! %clock ssh-clock-data now) (%oset! %clock %ASKED now)))

; A keepalive asked: OpenSSH's global request, wanting the answer that
; counts as the other end alive.
(def %keepalive!
  (fn (_ c)
    (def req (ssh-out))
    (ssh-put-byte req ssh-msg-global-request)
    (ssh-put-text req "keepalive@openssh.com")
    (ssh-put-bool req #t)
    (def r (ssh-out-run req))
    (ssh-send-packet! c (first r) (rest r))
    (%oset! %clock ssh-clock-sent (Sys now))
    (%oset! %clock %ASKED (Sys now))))

; How long a wait may last before a clock wants looking at, in
; milliseconds, or -1 for no limit: limits is (INTERVAL COUNT IDLE), an
; interval or idle time of 0 for never.
(def ssh-wait-ms
  (fn (_ limits)
    (def now (Sys now))
    (def k (first limits)) (def n (List ref 1 limits)) (def i (List ref 2 limits))
    (def dues
      (List append
        (if (> k 0) (list (- (+ (%oref %clock ssh-clock-sent) k) now) (- (+ (%oref %clock ssh-clock-recv) k) now)
                          (- (+ (%oref %clock ssh-clock-recv) (* k n)) now)) ())
        (if (> i 0) (list (- (+ (%oref %clock ssh-clock-data) i) now)) ())))
    (if (null? dues) -1
      (do (def least (List fold (fn (_ a b) (if (< a b) a b)) (first dues) (rest dues)))
          (if (< least 0) 0 (* 1000 least))))))

; The clocks read: a keepalive asked when due, the connection given up
; or closed when a limit has passed; the error's message names which.
(def ssh-clocks!
  (fn (_ c limits)
    (def now (Sys now))
    (def k (first limits)) (def n (List ref 1 limits)) (def i (List ref 2 limits))
    (when (> k 0)
      (do (when (>= (- now (%oref %clock ssh-clock-recv)) (* k n))
            (Err raise 'io "keepalive" ()))
          (when (if (>= (- now (%oref %clock ssh-clock-sent)) k) #t
                  (if (>= (- now (%oref %clock ssh-clock-recv)) k) (>= (- now (%oref %clock %ASKED)) k) #f))
            (%keepalive! c))))
    (when (if (> i 0) (>= (- now (%oref %clock ssh-clock-data)) i) #f)
      (Err raise 'io "idle" ()))))

; --- the key exchange (7), curve25519-sha256 (RFC 8731) --------------------

(def %kex-names (list "curve25519-sha256" "curve25519-sha256@libssh.org"))
; The host key algorithms this end checks, as a client offers them unless
; known_hosts says which it already knows the host by.
(def ssh-hostkey-names (list "ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "rsa-sha2-512" "rsa-sha2-256"))
; The ciphers and MACs served, in OpenSSH's order of preference.  A MAC
; is agreed only for a cipher without its own tag.
(def ssh-cipher-names
  (list "chacha20-poly1305@openssh.com" "aes128-ctr" "aes192-ctr" "aes256-ctr"
        "aes128-gcm@openssh.com" "aes256-gcm@openssh.com"))
(def ssh-mac-names
  (list "hmac-sha2-256-etm@openssh.com" "hmac-sha2-512-etm@openssh.com" "hmac-sha2-256" "hmac-sha2-512"))
(def %comp-names (list "none"))

; The value a name has in an alist keyed by names, or ().
(def %named (fn (_ name al) ((fn (_ e) (if (null? e) () (rest e))) (List find (fn (_ e) (str=? (first e) name)) al))))

; A cipher's name as (CIPHER . KEY-SIZE).
(def %cipher-of
  (fn (_ name)
    (%named name
      (list (pair "chacha20-poly1305@openssh.com" (pair 'chacha 64))
            (pair "aes128-ctr" (pair 'ctr 16)) (pair "aes192-ctr" (pair 'ctr 24)) (pair "aes256-ctr" (pair 'ctr 32))
            (pair "aes128-gcm@openssh.com" (pair 'gcm 16)) (pair "aes256-gcm@openssh.com" (pair 'gcm 32))))))

; A MAC's name as (HASH SIZE ETM?).
(def %mac-of
  (fn (_ name)
    (%named name
      (list (pair "hmac-sha2-256-etm@openssh.com" (list 'sha256 32 #t)) (pair "hmac-sha2-512-etm@openssh.com" (list 'sha512 64 #t))
            (pair "hmac-sha2-256" (list 'sha256 32 #f)) (pair "hmac-sha2-512" (list 'sha512 64 #f))))))

(def %aead? (fn (_ name) (not (eq? (first (%cipher-of name)) 'ctr))))

; The ciphers and MACs this end offers, from its configuration: subsets
; of ssh-cipher-names and ssh-mac-names, in the order preferred.
(def ssh-algorithms!
  (fn (_ c ciphers macs) (%slot! c 13 (pair ciphers macs))))

(def %kexinit
  (fn (_ c hostkeys extra)
    (def out (ssh-out))
    (ssh-put-byte out ssh-msg-kexinit)
    (ssh-put-bytes out (ssh-random 16) 0 16)
    (ssh-put-names out (List append %kex-names extra))
    (ssh-put-names out hostkeys)
    (ssh-put-names out (first (%slot c 13))) (ssh-put-names out (first (%slot c 13)))
    (ssh-put-names out (rest (%slot c 13))) (ssh-put-names out (rest (%slot c 13)))
    (ssh-put-names out %comp-names) (ssh-put-names out %comp-names)
    (ssh-put-text out "") (ssh-put-text out "")
    (ssh-put-bool out #f)
    (ssh-put-uint32 out 0)
    (ssh-out-run out)))

; The algorithm agreed (7.1): the first of the client's list that the
; server lists too, or ().
(def %agree
  (fn (_ client server)
    (List find (fn (_ n) (List any? (fn (_ m) (str=? m n)) server)) client)))

; The peer's KEXINIT read: each list must share a name with ours, the MAC
; lists only for a cipher without its own tag.  The client's list leads,
; whichever side reads it.  Answers (WRONG-GUESS CHOSEN EXT): whether a
; guessed packet that must be discarded follows; the kex, host key, the
; two ciphers and the two MACs agreed (a MAC () under an AEAD cipher),
; client-to-server first; then whether the client asked for extension
; negotiation (RFC 8308).
(def %read-kexinit
  (fn (_ c p server? hostkeys)
    (def in (ssh-in (first p) 17 (- (rest p) 17)))
    (def kex (ssh-get-names in))
    (def hk (ssh-get-names in))
    (def c2s (ssh-get-names in)) (def s2c (ssh-get-names in))
    (def m1 (ssh-get-names in)) (def m2 (ssh-get-names in))
    (def z1 (ssh-get-names in)) (def z2 (ssh-get-names in))
    (def pick (fn (_ ours theirs) (if server? (%agree theirs ours) (%agree ours theirs))))
    (def ciphers (first (%slot c 13)))
    (def macs (rest (%slot c 13)))
    (def chosen (list (pick %kex-names kex) (pick hostkeys hk) (pick ciphers c2s) (pick ciphers s2c)))
    (when (List any? null? chosen)
      (Err raise 'value "ssh: the peer offers none of our algorithms" ()))
    (def mac-for (fn (_ cipher theirs) (if (%aead? cipher) () (pick macs theirs))))
    (def mc (mac-for (List ref 2 chosen) m1))
    (def ms (mac-for (List ref 3 chosen) m2))
    (when (if (if (null? mc) (not (%aead? (List ref 2 chosen))) #f) #t (if (null? ms) (not (%aead? (List ref 3 chosen))) #f))
      (Err raise 'value "ssh: the peer offers none of our MACs" ()))
    (def mac-text (fn (_ m) (if (null? m) "" (Str8 append " " m))))
    (ssh-trace c (Str8 append "kex " (first chosen) " hostkey " (List ref 1 chosen)
                          " cipher " (List ref 2 chosen) (mac-text mc) " / " (List ref 3 chosen) (mac-text ms)))
    ; the languages, then whether a guessed key exchange packet follows
    ; (7.1): a guess is wrong when the client's first kex or host key
    ; algorithm is not the one agreed, and then the packet is discarded
    (ssh-get-names in) (ssh-get-names in)
    (def follows (ssh-get-bool in))
    (def wrong-guess
      (if follows
        (if (str=? (first kex) (first chosen)) (not (str=? (first hk) (List ref 1 chosen))) #t)
        #f))
    (list wrong-guess (List append chosen (list mc ms)) (List any? (fn (_ n) (str=? n "ext-info-c")) kex))))

; SHA-256 of what an OUT holds, as 32 bytes.
(def %sha256-out
  (fn (_ out)
    (def r (ssh-out-run out))
    (Hex decode (Sha256 hex-n (first r) (rest r)))))

; A key's 64 bytes (7.2): HASH(K || H || X || session_id), then
; HASH(K || H || K1) after it.
(def %derive
  (fn (_ kmp h x sid)
    (def a (ssh-out))
    (ssh-put-bytes a (first kmp) 0 (rest kmp))
    (ssh-put-bytes a h 0 32)
    (ssh-put-byte a x)
    (ssh-put-bytes a sid 0 32)
    (def k1 (%sha256-out a))
    (def b (ssh-out))
    (ssh-put-bytes b (first kmp) 0 (rest kmp))
    (ssh-put-bytes b h 0 32)
    (ssh-put-bytes b k1 0 32)
    (def k2 (%sha256-out b))
    (first (ssh-join (list (list k1 0 32) (list k2 0 32))))))

; One direction's keys as the packet layer's record: the cipher and MAC
; agreed for it, and letter the IV's (7.2): A (65) client to server, B
; the other way, the cipher's key two letters on and the MAC's four.
; The engines the cipher and MAC want are asked for here, once a
; process, so no packet runs pure-x for want of one.
(def %keys
  (fn (_ c kmp h cipher mac letter)
    (def sid (%slot c 7))
    (def spec (%cipher-of cipher))
    (def kind (first spec))
    (def k (Vector make 5 ()))
    (%oset! k 1 kind)
    (def enc (%derive kmp h (+ letter 2) sid))
    (if (eq? kind 'chacha)
      (%oset! k 2 (%split-key enc))
      (do (%oset! k 2 enc)
          (%oset! k 3 (rest spec))
          (%oset! k 4 (ssh-copy (%derive kmp h letter sid) 0 (if (eq? kind 'gcm) 12 16)))
          (Aes jit!)
          (when (eq? kind 'gcm) (Ghash jit!))))
    (unless (null? mac)
      (do (def m (%mac-of mac))
          (%oset! k 5 (list (first m) (%derive kmp h (+ letter 4) sid) (List ref 1 m) (List ref 2 m)))
          (if (eq? (first m) 'sha256) (Sha256 jit!) (Sha512 jit!))))
    k))

; The whole exchange: KEXINIT both ways, our ephemeral key out, the
; server's back with its host key and signature over the exchange hash,
; the hash checked, NEWKEYS both ways, and the keys in place after.
; hostkeys are the host key algorithms offered, in the order preferred.
(def ssh-kex!
  (fn (_ c hostkeys)
    ; ext-info-c asks the server for its server-sig-algs (RFC 8308 2.1)
    (def ic (%kexinit c hostkeys (list "ext-info-c")))
    (ssh-send-packet! c (first ic) (rest ic))
    (def is (ssh-expect! c ssh-msg-kexinit "KEXINIT"))
    (def chosen (List ref 1 (%read-kexinit c is #f hostkeys)))
    (def k (ssh-random 32))
    (def qc (X25519 base k))
    (def init (ssh-out))
    (ssh-put-byte init ssh-msg-kex-ecdh-init)
    (ssh-put-string init qc 0 32)
    (def ir (ssh-out-run init))
    (ssh-send-packet! c (first ir) (rest ir))
    (def reply (ssh-expect! c ssh-msg-kex-ecdh-reply "KEX_ECDH_REPLY"))
    ; string K_S, string Q_S, string the signature
    (def in (ssh-in (first reply) 1 (- (rest reply) 1)))
    (def ks-run (ssh-get-string in))
    (def qs (ssh-get-bytes in))
    (def sig-run (ssh-get-string in))
    ; the host key, of any type served
    (def hostkey (ssh-pubkey-of (first reply) (first ks-run) (rest ks-run)))
    (def shared (X25519 scalarmult k qs))
    (when (not (List any? (fn (_ i) (not (= (%byte shared i) 0))) (list 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)))
      (Err raise 'value "ssh: the shared secret is zero" ()))
    ; the exchange hash (RFC 8731 3.1)
    (def hin (ssh-out))
    (ssh-put-text hin ssh-version-string)
    (ssh-put-text hin (%slot c 8))
    (ssh-put-string hin (first ic) 0 (rest ic))
    (ssh-put-string hin (first is) 0 (rest is))
    (ssh-put-string hin (first reply) (first ks-run) (rest ks-run))
    (ssh-put-string hin qc 0 32)
    (ssh-put-string hin qs 0 32)
    (ssh-put-mpint hin shared 0 32)
    (def h (%sha256-out hin))
    ; the signature blob, by the host key over the exchange hash
    (unless (ssh-pubkey-verify? hostkey (list (first reply) (first sig-run) (rest sig-run)) (list h 0 32))
      (Err raise 'value "ssh: the host key's signature does not check" ()))
    (ssh-trace c (Str8 append "host key " (ssh-pubkey-type hostkey) " " (ssh-pubkey-base64 hostkey)))
    (%slot! c 9 hostkey)
    (when (null? (%slot c 7)) (%slot! c 7 h))
    (def nk (ssh-out))
    (ssh-put-byte nk ssh-msg-newkeys)
    (def nr (ssh-out-run nk))
    (ssh-send-packet! c (first nr) (rest nr))
    (ssh-expect! c ssh-msg-newkeys "NEWKEYS")
    ; K as an mpint, as the derivation hashes it
    (def kout (ssh-out))
    (ssh-put-mpint kout shared 0 32)
    (def kmp (ssh-out-run kout))
    (%slot! c 5 (%keys c kmp h (List ref 2 chosen) (List ref 4 chosen) 65))
    (%slot! c 6 (%keys c kmp h (List ref 3 chosen) (List ref 5 chosen) 66))
    (ssh-trace c "keys in place")
    c))

; The exchange as the server runs it: KEXINIT both ways, the client's
; ephemeral key in, ours out with our host key and our signature of the
; exchange hash, NEWKEYS both ways, and the keys in place -- ours to send
; the server-to-client key, as the client's is the other.  ids are the
; host keys, as ssh/pubkey's identities: their algorithms that allowed
; names are offered, in
; order, and the one agreed signs.
(def ssh-kex-server!
  (fn (_ c ids allowed)
    (def offered (List filter (fn (_ a) (List any? (fn (_ x) (str=? x a)) allowed))
                   (List flat-map (fn (_ id) (ssh-pubkey-algorithms (ssh-identity-pubkey id))) ids)))
    (def is (%kexinit c offered ()))
    (ssh-send-packet! c (first is) (rest is))
    (def ic (ssh-expect! c ssh-msg-kexinit "KEXINIT"))
    (def agreed (%read-kexinit c ic #t offered))
    (def alg (List ref 1 (List ref 1 agreed)))
    (def id (List find (fn (_ i) (List any? (fn (_ a) (str=? a alg)) (ssh-pubkey-algorithms (ssh-identity-pubkey i)))) ids))
    (def blob (ssh-pubkey-blob (ssh-identity-pubkey id)))
    ; a client that guessed another exchange sent its packet already
    (when (first agreed) (ssh-next-packet! c))
    (def init (ssh-expect! c ssh-msg-kex-ecdh-init "KEX_ECDH_INIT"))
    (def qc (ssh-get-bytes (ssh-in (first init) 1 (- (rest init) 1))))
    (def k (ssh-random 32))
    (def qs (X25519 base k))
    (def shared (X25519 scalarmult k qc))
    (when (not (List any? (fn (_ i) (not (= (%byte shared i) 0))) (list 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31)))
      (Err raise 'value "ssh: the shared secret is zero" ()))
    (def ks (ssh-out))
    (ssh-put-bytes ks (first blob) (List ref 1 blob) (List ref 2 blob))
    (def ksr (ssh-out-run ks))
    ; the exchange hash: the client's version and KEXINIT first
    (def hin (ssh-out))
    (ssh-put-text hin (%slot c 8))
    (ssh-put-text hin ssh-version-string)
    (ssh-put-string hin (first ic) 0 (rest ic))
    (ssh-put-string hin (first is) 0 (rest is))
    (ssh-put-string hin (first ksr) 0 (rest ksr))
    (ssh-put-string hin qc 0 32)
    (ssh-put-string hin qs 0 32)
    (ssh-put-mpint hin shared 0 32)
    (def h (%sha256-out hin))
    (def sigr ((fn (_ s) (pair (ssh-copy (first s) (List ref 1 s) (List ref 2 s)) (List ref 2 s))) (ssh-identity-sign id (list h 0 32) alg)))
    (def reply (ssh-out))
    (ssh-put-byte reply ssh-msg-kex-ecdh-reply)
    (ssh-put-string reply (first ksr) 0 (rest ksr))
    (ssh-put-string reply qs 0 32)
    (ssh-put-string reply (first sigr) 0 (rest sigr))
    (def rr (ssh-out-run reply))
    (ssh-send-packet! c (first rr) (rest rr))
    (when (null? (%slot c 7)) (%slot! c 7 h))
    (def nk (ssh-out))
    (ssh-put-byte nk ssh-msg-newkeys)
    (def nr (ssh-out-run nk))
    (ssh-send-packet! c (first nr) (rest nr))
    (ssh-expect! c ssh-msg-newkeys "NEWKEYS")
    (def kout (ssh-out))
    (ssh-put-mpint kout shared 0 32)
    (def kmp (ssh-out-run kout))
    (%slot! c 5 (%keys c kmp h (List ref 3 (List ref 1 agreed)) (List ref 5 (List ref 1 agreed)) 66))
    (%slot! c 6 (%keys c kmp h (List ref 2 (List ref 1 agreed)) (List ref 4 (List ref 1 agreed)) 65))
    (ssh-trace c "keys in place")
    ; a client that asked for extensions is told the signature algorithms
    ; its key may sign with (RFC 8308 3.1): OpenSSH's signs with an RSA key
    ; as rsa-sha2-256 or -512 only when the server names them
    (when (List ref 2 agreed)
      (do (def ext (ssh-out))
          (ssh-put-byte ext ssh-msg-ext-info)
          (ssh-put-uint32 ext 1)
          (ssh-put-text ext "server-sig-algs")
          (ssh-put-names ext ssh-hostkey-names)
          (def er (ssh-out-run ext))
          (ssh-send-packet! c (first er) (rest er))))
    c))

; --- authentication (RFC 4252): publickey, of any type served, and password -

; The ssh-userauth service asked for, before any method is tried.
(def ssh-auth-service!
  (fn (_ c)
    (def sr (ssh-out))
    (ssh-put-byte sr ssh-msg-service-request)
    (ssh-put-text sr "ssh-userauth")
    (def srr (ssh-out-run sr))
    (ssh-send-packet! c (first srr) (rest srr))
    (ssh-expect! c ssh-msg-service-accept "SERVICE_ACCEPT")
    #t))

; The answer to an authentication request: #t on success, pk-ok when a
; key asked about would do, the server's remaining methods otherwise; a
; banner traced on the way.
(def %auth-answer
  (fn (self c)
    (def p (ssh-next-packet! c))
    (def t (%byte (first p) 0))
    (match
      ((= t ssh-msg-userauth-success) #t)
      ((= t ssh-msg-userauth-pk-ok) (lit pk-ok))
      ((= t ssh-msg-userauth-banner)
        (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
            (ssh-trace c (Str8 append "banner: " (ssh-get-text in)))
            (self c)))
      ((= t ssh-msg-userauth-failure)
        (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
            (ssh-get-names in)))
      (#t (Err raise 'value "ssh: an unexpected answer to authentication" ())))))

; A password request for the user, and its answer as %auth-answer has it.
(def ssh-auth-password!
  (fn (_ c user password)
    (def req (ssh-out))
    (ssh-put-byte req ssh-msg-userauth-request)
    (ssh-put-text req user)
    (ssh-put-text req "ssh-connection")
    (ssh-put-text req "password")
    (ssh-put-bool req #f)
    (ssh-put-text req password)
    (def rr (ssh-out-run req))
    (ssh-send-packet! c (first rr) (rest rr))
    (%auth-answer c)))

; The publickey request's body for a key and algorithm, up to the
; signature: (BUF . LEN).
(def %pk-request
  (fn (_ user key alg signed)
    (def blob (ssh-pubkey-blob key))
    (def out (ssh-out))
    (ssh-put-byte out ssh-msg-userauth-request)
    (ssh-put-text out user)
    (ssh-put-text out "ssh-connection")
    (ssh-put-text out "publickey")
    (ssh-put-bool out signed)
    (ssh-put-text out alg)
    (ssh-put-string out (first blob) (List ref 1 blob) (List ref 2 blob))
    (ssh-out-run out)))

; Whether the server would take a key, asked before it is signed with:
; the request without its signature, answered as %auth-answer has it.
; What a key sealed under a passphrase is offered with, so the
; passphrase is asked for only when the server takes the key.  key is
; ssh/pubkey's, alg one of its algorithms.
(def ssh-auth-publickey-query!
  (fn (_ c user key alg)
    (def rr (%pk-request user key alg #f))
    (ssh-send-packet! c (first rr) (rest rr))
    (%auth-answer c)))

; The request signed with an identity (ssh/pubkey's) as alg, and its
; answer as %auth-answer has it.  What is signed: the session id as a
; string, then the request itself (RFC 4252 7).
(def ssh-auth-publickey!
  (fn (_ c user id alg)
    (def br (%pk-request user (ssh-identity-pubkey id) alg #t))
    (def signed (ssh-out))
    (ssh-put-string signed (%slot c 7) 0 32)
    (ssh-put-bytes signed (first br) 0 (rest br))
    (def sgr (ssh-out-run signed))
    (def sig (ssh-identity-sign id (list (first sgr) 0 (rest sgr)) alg))
    (def req (ssh-out))
    (ssh-put-bytes req (first br) 0 (rest br))
    (ssh-put-string req (first sig) (List ref 1 sig) (List ref 2 sig))
    (def rr (ssh-out-run req))
    (ssh-send-packet! c (first rr) (rest rr))
    (%auth-answer c)))

(provide ssh/transport ssh-version-string ssh-open ssh-fd ssh-session-id ssh-host-key ssh-server-sig-algs ssh-hostkey-names ssh-pending? ssh-random ssh-engines!
  ssh-cipher-names ssh-mac-names ssh-algorithms!
  ssh-exchange-versions! ssh-send-packet! ssh-recv-packet! ssh-next-packet! ssh-expect! ssh-kex! ssh-kex-server! ssh-auth-service! ssh-auth-publickey-query! ssh-auth-publickey! ssh-auth-password!
  ssh-msg-disconnect ssh-msg-global-request ssh-msg-request-success ssh-msg-request-failure ssh-msg-service-request ssh-msg-service-accept
  ssh-msg-userauth-request ssh-msg-userauth-failure ssh-msg-userauth-success ssh-trace
  ssh-clock-sent ssh-clock-recv ssh-clock-data ssh-clock-mark! ssh-clocks-start! ssh-wait-ms ssh-clocks!)
