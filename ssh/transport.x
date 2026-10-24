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
; follows.  One cipher suite, the one OpenSSH prefers and the
; codecs x-lang has: curve25519-sha256, ssh-ed25519, and
; chacha20-poly1305@openssh.com, whose framing is OpenSSH's
; PROTOCOL.chacha20poly1305 -- two keys from the 64 derived, the length
; under the second, the payload under the first from block one, the
; Poly1305 key from block zero, the packet's sequence number the nonce.
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
(import x/codec/hex)
(import x/codec/sha256)
(import x/codec/chacha20)
(import x/codec/poly1305)
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
;        5 send key as (K_1 . K_2) or () | 6 receive key or () | 7 session id
;        8 peer's version | 9 server's host key | 10 the trace fn or ()
;        11 the pending packet's length as (SEQ KEY LEN), once unveiled, or ()
;        12 the server's server-sig-algs (RFC 8308), or () until it says

(def %slot (fn (_ c i) (%oref c i)))
(def %slot! (fn (_ c i v) (%oset! c i v)))

(def ssh-open
  (fn (_ fd trace)
    (def c (Vector make 12 ()))
    (%slot! c 1 fd)
    (%slot! c 2 (pair (%make-str 0) 0))
    (%slot! c 3 0)
    (%slot! c 4 0)
    (%slot! c 10 trace)
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
    (if (< (rest run) 4) #f
      (do (def key (%slot c 6))
          (def seq (%slot c 4))
          (def known (%slot c 11))
          (def len (if (if (null? known) #f (if (= (first known) seq) (eq? (List ref 1 known) key) #f))
                     (List ref 2 known)
                     (do (def n (%packet-length key seq (first run)))
                         (%slot! c 11 (list seq key n))
                         n)))
          (>= (rest run) (+ 4 len (if (null? key) 0 16)))))))

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

; --- the binary packet protocol (6), with chacha20-poly1305 --------------

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

; A packet's length field unveiled: the clear bytes under no key, else
; K_1's keystream over them.
(def %packet-length
  (fn (_ key seq head)
    (def lenb (if (null? key) head (ChaCha20 xor (first key) (%iv 0 seq) head 0 4)))
    (| (<< (%byte lenb 0) 24) (| (<< (%byte lenb 1) 16) (| (<< (%byte lenb 2) 8) (%byte lenb 3))))))

; A payload sent as one packet: padded to a multiple of eight (the
; length field aside, as the AEAD framing has it), at least four bytes
; of it, then in the clear or under the keys.
(def ssh-send-packet!
  (fn (_ c payload n)
    (def key (%slot c 5))
    (def seq (%slot c 3))
    ; in the clear the length field counts toward the alignment (6.1);
    ; under the AEAD it is associated data, outside it
    (def pad ((fn (_ p) (if (< p 4) (+ p 8) p)) (- 8 (& (+ n (if (null? key) 5 1)) 7))))
    (def len (+ 1 n pad))
    (def body (ssh-out))
    (ssh-put-byte body pad)
    (ssh-put-bytes body payload 0 n)
    (ssh-put-bytes body (ssh-random pad) 0 pad)
    (def b (ssh-out-run body))
    (def head (ssh-out))
    (ssh-put-uint32 head len)
    (def h (ssh-out-run head))
    (if (null? key)
      (do (def whole (ssh-join (list (list (first h) 0 4) (list (first b) 0 len))))
          (%send! c (first whole) (rest whole)))
      (do (def iv0 (%iv 0 seq))
          (def enc-len (ChaCha20 xor (first key) iv0 (first h) 0 4))
          (def enc (ChaCha20 xor (rest key) (%iv 1 seq) (first b) 0 len))
          (def framed (ssh-join (list (list enc-len 0 4) (list enc 0 len))))
          (def tag (Poly1305 mac (%poly-key (rest key) iv0) (first framed) 0 (rest framed)))
          (def whole (ssh-join (list (list (first framed) 0 (rest framed)) (list tag 0 16))))
          (%send! c (first whole) (rest whole))))
    (%slot! c 3 (+ seq 1))))

; A packet received: its payload as (BUF . LEN).  Under the keys, the
; length is unveiled first, then the tag checked over the whole before
; a byte of the payload is trusted.
(def ssh-recv-packet!
  (fn (_ c)
    (def key (%slot c 6))
    (def seq (%slot c 4))
    (def head (%take! c 4))
    (def known (%slot c 11))
    (def len (if (if (null? known) #f (if (= (first known) seq) (eq? (List ref 1 known) key) #f))
               (List ref 2 known)
               (%packet-length key seq head)))
    (%slot! c 11 ())
    (when (if (> len 262144) #t (< len 5)) (Err raise 'value "ssh: a packet of an impossible length" ()))
    (def body
      (if (null? key)
        (%take! c len)
        (do (def enc (%take! c len))
            (def tag (%take! c 16))
            (def framed (ssh-join (list (list head 0 4) (list enc 0 len))))
            (def want (Poly1305 mac (%poly-key (rest key) (%iv 0 seq)) (first framed) 0 (rest framed)))
            (unless (ssh-same-bytes? want 0 tag 0 16)
              (Err raise 'value "ssh: a packet failed its authentication tag" ()))
            (ChaCha20 xor (rest key) (%iv 1 seq) enc 0 len))))
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

; --- the key exchange (7), curve25519-sha256 (RFC 8731) --------------------

(def %kex-names (list "curve25519-sha256" "curve25519-sha256@libssh.org"))
; The host key algorithms this end checks, as a client offers them unless
; known_hosts says which it already knows the host by.
(def ssh-hostkey-names (list "ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "rsa-sha2-512" "rsa-sha2-256"))
(def %cipher-names (list "chacha20-poly1305@openssh.com"))
(def %mac-names (list "hmac-sha2-256"))
(def %comp-names (list "none"))

(def %kexinit
  (fn (_ hostkeys extra)
    (def out (ssh-out))
    (ssh-put-byte out ssh-msg-kexinit)
    (ssh-put-bytes out (ssh-random 16) 0 16)
    (ssh-put-names out (List append %kex-names extra))
    (ssh-put-names out hostkeys)
    (ssh-put-names out %cipher-names) (ssh-put-names out %cipher-names)
    (ssh-put-names out %mac-names) (ssh-put-names out %mac-names)
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

; The peer's KEXINIT read: each list must share a name with ours.  The
; client's list leads, whichever side reads it.  Answers (WRONG-GUESS
; CHOSEN EXT): whether a guessed packet that must be discarded follows,
; the kex, host key and two cipher names agreed, then whether the
; client asked for extension negotiation (RFC 8308).
(def %read-kexinit
  (fn (_ c p server? hostkeys)
    (def in (ssh-in (first p) 17 (- (rest p) 17)))
    (def kex (ssh-get-names in))
    (def hk (ssh-get-names in))
    (def c2s (ssh-get-names in)) (def s2c (ssh-get-names in))
    (def m1 (ssh-get-names in)) (def m2 (ssh-get-names in))
    (def z1 (ssh-get-names in)) (def z2 (ssh-get-names in))
    (def pick (fn (_ ours theirs) (if server? (%agree theirs ours) (%agree ours theirs))))
    (def chosen (list (pick %kex-names kex) (pick hostkeys hk)
                      (pick %cipher-names c2s) (pick %cipher-names s2c)))
    (when (List any? null? chosen)
      (Err raise 'value "ssh: the peer offers none of our algorithms" ()))
    (ssh-trace c (Str8 append "kex " (first chosen) " hostkey " (first (rest chosen))
                          " cipher " (first (rest (rest chosen)))))
    ; the languages, then whether a guessed key exchange packet follows
    ; (7.1): a guess is wrong when the client's first kex or host key
    ; algorithm is not the one agreed, and then the packet is discarded
    (ssh-get-names in) (ssh-get-names in)
    (def follows (ssh-get-bool in))
    (def wrong-guess
      (if follows
        (if (str=? (first kex) (first chosen)) (not (str=? (first hk) (first (rest chosen)))) #t)
        #f))
    (list wrong-guess chosen (List any? (fn (_ n) (str=? n "ext-info-c")) kex))))

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

; The whole exchange: KEXINIT both ways, our ephemeral key out, the
; server's back with its host key and signature over the exchange hash,
; the hash checked, NEWKEYS both ways, and the keys in place after.
; hostkeys are the host key algorithms offered, in the order preferred.
(def ssh-kex!
  (fn (_ c hostkeys)
    ; ext-info-c asks the server for its server-sig-algs (RFC 8308 2.1)
    (def ic (%kexinit hostkeys (list "ext-info-c")))
    (ssh-send-packet! c (first ic) (rest ic))
    (def is (ssh-expect! c ssh-msg-kexinit "KEXINIT"))
    (%read-kexinit c is #f hostkeys)
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
    (%slot! c 5 (%split-key (%derive kmp h 67 (%slot c 7))))
    (%slot! c 6 (%split-key (%derive kmp h 68 (%slot c 7))))
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
    (def is (%kexinit offered ()))
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
    (%slot! c 5 (%split-key (%derive kmp h 68 (%slot c 7))))
    (%slot! c 6 (%split-key (%derive kmp h 67 (%slot c 7))))
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
  ssh-exchange-versions! ssh-send-packet! ssh-recv-packet! ssh-next-packet! ssh-expect! ssh-kex! ssh-kex-server! ssh-auth-service! ssh-auth-publickey-query! ssh-auth-publickey! ssh-auth-password!
  ssh-msg-disconnect ssh-msg-global-request ssh-msg-request-success ssh-msg-request-failure ssh-msg-service-request ssh-msg-service-accept
  ssh-msg-userauth-request ssh-msg-userauth-failure ssh-msg-userauth-success ssh-trace)
