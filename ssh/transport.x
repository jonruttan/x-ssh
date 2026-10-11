; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/transport.x -- the transport layer, as the client sees it
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; RFC 4253: the version exchange, the binary packet protocol, the key
; exchange and the keys it derives; RFC 4252 for the authentication that
; follows.  One cipher suite, the one Dropbear and OpenSSH prefer and the
; codecs x-lang has: curve25519-sha256, ssh-ed25519, and
; chacha20-poly1305@openssh.com, whose framing is OpenSSH's
; PROTOCOL.chacha20poly1305 -- two keys from the 64 derived, the length
; under the second, the payload under the first from block one, the
; Poly1305 key from block zero, the packet's sequence number the nonce.
;
; A connection is a vector: the socket, the bytes received and not yet
; read, the two sequence numbers, the two keys once there are any, the
; session id, and the server's version string and host key.

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
(def ssh-msg-userauth-success 52) (def ssh-msg-userauth-banner 53)
(def ssh-msg-global-request 80) (def ssh-msg-request-success 81) (def ssh-msg-request-failure 82)

; --- the connection record ------------------------------------------------
;
; slots: 1 fd | 2 pending bytes (BUF . LEN) | 3 send seq | 4 recv seq
;        5 c2s key (64 bytes) or () | 6 s2c key or () | 7 session id
;        8 server version | 9 host key bytes (32) | 10 the trace fn or ()

(def %slot (fn (_ c i) (%oref c i)))
(def %slot! (fn (_ c i v) (%oset! c i v)))

(def ssh-open
  (fn (_ fd trace)
    (def c (Vector make 10 ()))
    (%slot! c 1 fd)
    (%slot! c 2 (pair (%make-str 0) 0))
    (%slot! c 3 0)
    (%slot! c 4 0)
    (%slot! c 10 trace)
    c))

(def ssh-fd (fn (_ c) (%slot c 1)))
(def ssh-session-id (fn (_ c) (%slot c 7)))
(def ssh-host-key (fn (_ c) (%slot c 9)))

; Whether received bytes are waiting to be read as a packet: a caller
; that waits on the socket must not, while they are.
(def ssh-pending?
  (fn (_ c) (> (rest (%slot c 2)) 0)))

(def %trace
  (fn (_ c text) (unless (null? (%slot c 10)) ((%slot c 10) text))))

; The compiled engines of the exchange's curves, asked for once a
; process: the key exchange's X25519 and the signatures' Ed25519.  A
; build costs less than one pure-x exchange or signature, and a host
; without the JIT answers #f and carries on pure-x, identically.
(def ssh-engines!
  (fn (_ c)
    (def x (X25519 jit!))
    (def e (Ed25519 jit!))
    (%trace c (Str8 append "engines x25519 " (if x "compiled" "pure-x") " ed25519 " (if e "compiled" "pure-x")))
    (and x e)))

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
    (%trace c (Str8 append "server version " line))
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
(def %iv
  (fn (_ counter seq)
    (def iv (%make-str 16))
    (def p (%str->ptr iv))
    ((fn (self i) (unless (= i 16) (do (%pset1 p i 0 1) (self (+ i 1))))) 0)
    (%pset1 p 0 counter 1)
    (%pset1 p 12 (>> seq 24) 1) (%pset1 p 13 (>> seq 16) 1)
    (%pset1 p 14 (>> seq 8) 1) (%pset1 p 15 seq 1)
    iv))

; The two keys of a 64-byte key: K_2 the first half (the payload's),
; K_1 the second (the length's).
(def %k1 (fn (_ key) (ssh-copy key 32 32)))
(def %k2 (fn (_ key) (ssh-copy key 0 32)))

(def %poly-key
  (fn (_ key seq) (ssh-copy (ChaCha20 block (%k2 key) (%iv 0 seq)) 0 32)))

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
      (do (def enc-len (ChaCha20 xor (%k1 key) (%iv 0 seq) (first h) 0 4))
          (def enc (ChaCha20 xor (%k2 key) (%iv 1 seq) (first b) 0 len))
          (def framed (ssh-join (list (list enc-len 0 4) (list enc 0 len))))
          (def tag (Poly1305 mac (%poly-key key seq) (first framed) 0 (rest framed)))
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
    (def lenb (if (null? key) head (ChaCha20 xor (%k1 key) (%iv 0 seq) head 0 4)))
    (def len (| (<< (%byte lenb 0) 24) (| (<< (%byte lenb 1) 16) (| (<< (%byte lenb 2) 8) (%byte lenb 3)))))
    (when (if (> len 262144) #t (< len 5)) (Err raise 'value "ssh: a packet of an impossible length" ()))
    (def body
      (if (null? key)
        (%take! c len)
        (do (def enc (%take! c len))
            (def tag (%take! c 16))
            (def framed (ssh-join (list (list head 0 4) (list enc 0 len))))
            (def want (Poly1305 mac (%poly-key key seq) (first framed) 0 (rest framed)))
            (unless (ssh-same-bytes? want 0 tag 0 16)
              (Err raise 'value "ssh: a packet failed its authentication tag" ()))
            (ChaCha20 xor (%k2 key) (%iv 1 seq) enc 0 len))))
    (%slot! c 4 (+ seq 1))
    (def pad (%byte body 0))
    (pair (ssh-copy body 1 (- len 1 pad)) (- len 1 pad))))

; The next packet that is the transport's business handled here, any
; other handed back: IGNORE and DEBUG dropped, a GLOBAL_REQUEST refused,
; a DISCONNECT raised with its message.
(def ssh-next-packet!
  (fn (self c)
    (def p (ssh-recv-packet! c))
    (def t (%byte (first p) 0))
    (match
      ((= t ssh-msg-ignore) (self c))
      ((= t ssh-msg-debug) (self c))
      ((= t ssh-msg-ext-info) (self c))
      ((= t ssh-msg-global-request)
        (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
            (def name (ssh-get-text in))
            (def want-reply (ssh-get-bool in))
            (%trace c (Str8 append "global request " name))
            (when want-reply
              (do (def out (ssh-out))
                  (ssh-put-byte out ssh-msg-request-failure)
                  (def r (ssh-out-run out))
                  (ssh-send-packet! c (first r) (rest r))))
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
(def %hostkey-names (list "ssh-ed25519"))
(def %cipher-names (list "chacha20-poly1305@openssh.com"))
(def %mac-names (list "hmac-sha2-256"))
(def %comp-names (list "none"))

(def %kexinit
  (fn (_)
    (def out (ssh-out))
    (ssh-put-byte out ssh-msg-kexinit)
    (ssh-put-bytes out (ssh-random 16) 0 16)
    (ssh-put-names out %kex-names)
    (ssh-put-names out %hostkey-names)
    (ssh-put-names out %cipher-names) (ssh-put-names out %cipher-names)
    (ssh-put-names out %mac-names) (ssh-put-names out %mac-names)
    (ssh-put-names out %comp-names) (ssh-put-names out %comp-names)
    (ssh-put-text out "") (ssh-put-text out "")
    (ssh-put-bool out #f)
    (ssh-put-uint32 out 0)
    (ssh-out-run out)))

; The first of ours the server lists too, or ().
(def %agree
  (fn (_ ours theirs)
    (List find (fn (_ n) (List any? (fn (_ m) (str=? m n)) theirs)) ours)))

; The server's KEXINIT read: each list must share a name with ours.
(def %read-kexinit
  (fn (_ c p)
    (def in (ssh-in (first p) 17 (- (rest p) 17)))
    (def kex (ssh-get-names in))
    (def hk (ssh-get-names in))
    (def c2s (ssh-get-names in)) (def s2c (ssh-get-names in))
    (def m1 (ssh-get-names in)) (def m2 (ssh-get-names in))
    (def z1 (ssh-get-names in)) (def z2 (ssh-get-names in))
    (def chosen (list (%agree %kex-names kex) (%agree %hostkey-names hk)
                      (%agree %cipher-names c2s) (%agree %cipher-names s2c)))
    (when (List any? null? chosen)
      (Err raise 'value "ssh: the server offers none of this client's algorithms" ()))
    (%trace c (Str8 append "kex " (first chosen) " hostkey " (first (rest chosen))
                          " cipher " (first (rest (rest chosen)))))
    chosen))

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
(def ssh-kex!
  (fn (_ c)
    (def ic (%kexinit))
    (ssh-send-packet! c (first ic) (rest ic))
    (def is (ssh-expect! c ssh-msg-kexinit "KEXINIT"))
    (%read-kexinit c is)
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
    (def sig (ssh-get-bytes in))
    ; the host key blob: string "ssh-ed25519", string the 32 bytes
    (def kin (ssh-in (first reply) (first ks-run) (rest ks-run)))
    (def ktype (ssh-get-text kin))
    (unless (str=? ktype "ssh-ed25519") (Err raise 'value (Str8 append "ssh: host key of a type not served: " ktype) ()))
    (def hostkey (ssh-get-bytes kin))
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
    ; the signature blob: string "ssh-ed25519", string the 64 bytes
    (def sin (ssh-in sig 0 (+ 4 11 4 64)))
    (def stype (ssh-get-text sin))
    (def sig64 (ssh-get-bytes sin))
    (unless (if (str=? stype "ssh-ed25519") (Ed25519 verify hostkey sig64 h 0 32) #f)
      (Err raise 'value "ssh: the host key's signature does not check" ()))
    (%trace c (Str8 append "host key ssh-ed25519 " (Hex encode hostkey)))
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
    (%slot! c 5 (%derive kmp h 67 (%slot c 7)))
    (%slot! c 6 (%derive kmp h 68 (%slot c 7)))
    (%trace c "keys in place")
    c))

; --- authentication (RFC 4252), publickey with ssh-ed25519 ---------------

; The public key blob of an Ed25519 key.
(def %pk-blob
  (fn (_ pub)
    (def out (ssh-out))
    (ssh-put-text out "ssh-ed25519")
    (ssh-put-string out pub 0 32)
    (ssh-out-run out)))

; The service asked for, the request signed with the user's key, and
; the answer: #t on success, the server's remaining methods otherwise.
(def ssh-auth-publickey!
  (fn (_ c user seed)
    (def sr (ssh-out))
    (ssh-put-byte sr ssh-msg-service-request)
    (ssh-put-text sr "ssh-userauth")
    (def srr (ssh-out-run sr))
    (ssh-send-packet! c (first srr) (rest srr))
    (ssh-expect! c ssh-msg-service-accept "SERVICE_ACCEPT")
    (def pub (Ed25519 public seed))
    (def blob (%pk-blob pub))
    ; what is signed: the session id as a string, then the request itself
    (def body (ssh-out))
    (ssh-put-byte body ssh-msg-userauth-request)
    (ssh-put-text body user)
    (ssh-put-text body "ssh-connection")
    (ssh-put-text body "publickey")
    (ssh-put-bool body #t)
    (ssh-put-text body "ssh-ed25519")
    (ssh-put-string body (first blob) 0 (rest blob))
    (def br (ssh-out-run body))
    (def signed (ssh-out))
    (ssh-put-string signed (%slot c 7) 0 32)
    (ssh-put-bytes signed (first br) 0 (rest br))
    (def sgr (ssh-out-run signed))
    (def sig (Ed25519 sign seed (first sgr) 0 (rest sgr)))
    (def sblob (ssh-out))
    (ssh-put-text sblob "ssh-ed25519")
    (ssh-put-string sblob sig 0 64)
    (def sbr (ssh-out-run sblob))
    (def req (ssh-out))
    (ssh-put-bytes req (first br) 0 (rest br))
    (ssh-put-string req (first sbr) 0 (rest sbr))
    (def rr (ssh-out-run req))
    (ssh-send-packet! c (first rr) (rest rr))
    ((fn (self)
       (def p (ssh-next-packet! c))
       (def t (%byte (first p) 0))
       (match
         ((= t ssh-msg-userauth-success) #t)
         ((= t ssh-msg-userauth-banner)
           (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
               (%trace c (Str8 append "banner: " (ssh-get-text in)))
               (self)))
         ((= t ssh-msg-userauth-failure)
           (do (def in (ssh-in (first p) 1 (- (rest p) 1)))
               (ssh-get-names in)))
         (#t (Err raise 'value "ssh: an unexpected answer to authentication" ())))))))

(provide ssh/transport ssh-version-string ssh-open ssh-fd ssh-session-id ssh-host-key ssh-pending? ssh-random ssh-engines!
  ssh-exchange-versions! ssh-send-packet! ssh-recv-packet! ssh-next-packet! ssh-expect! ssh-kex! ssh-auth-publickey!
  ssh-msg-disconnect ssh-msg-global-request ssh-msg-request-failure)
