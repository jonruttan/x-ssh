; # x-ssh -- SSH on x-lang
;
; ## ssh/pubkey.x -- public keys and their signatures
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; The public key types a signature is checked by, from their blobs as
; the wire and known_hosts and authorized_keys carry them (RFC 4253 6.6,
; RFC 5656 3.1, RFC 8332):
;
;   ssh-ed25519             string type, string the 32-byte key
;   ssh-rsa                 string type, mpint e, mpint n; signed as
;                           rsa-sha2-256 or rsa-sha2-512, PKCS#1 v1.5 over
;                           SHA-256 or SHA-512 -- the SHA-1 ssh-rsa is
;                           refused, as OpenSSH refuses it
;   ecdsa-sha2-nistp256     string type, string the curve, string the point
;   ecdsa-sha2-nistp384     (SEC 1 uncompressed); signed over SHA-256 or
;                           SHA-384, the signature mpint r then mpint s
;
; A key is (KIND BLOB ...): ed25519 with the 32 bytes, rsa with e and n,
; ecdsa with the curve and the point, BLOB and each part a region (BUF
; START LEN), as x-lang's codecs take them.  nistp521 is read but not
; checked: x-lang's Ecdsa has P-256 and P-384.

(module ssh/pubkey)

(import x/codec/base64)
(import x/codec/sha256)
(import x/codec/sha384)
(import x/codec/sha512)
(import x/codec/ed25519)
(import x/codec/rsa)
(import x/codec/ecdsa)
(import ssh/bytes ssh-in ssh-get-text ssh-get-string ssh-get-bytes ssh-copy)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))

(def %region (fn (_ buf r) (list buf (first r) (rest r))))

; A key from its blob's region, or a raise naming a type not served.
(def ssh-pubkey-of
  (fn (_ buf start len)
    (def in (ssh-in buf start len))
    (def type (ssh-get-text in))
    (def blob (list buf start len))
    (match
      ((str=? type "ssh-ed25519") (list (lit ed25519) blob (ssh-get-bytes in)))
      ((str=? type "ssh-rsa")
        (do (def e (ssh-get-string in))
            (def n (ssh-get-string in))
            (list (lit rsa) blob (%region buf e) (%region buf n))))
      ((List any? (fn (_ c) (str=? type (Str8 append "ecdsa-sha2-" c))) (list "nistp256" "nistp384" "nistp521"))
        (do (def curve (ssh-get-text in))
            (def q (ssh-get-string in))
            (unless (str=? type (Str8 append "ecdsa-sha2-" curve))
              (Err raise 'value (Str8 append "ssh: an ECDSA key whose curve is not its type's: " curve) ()))
            (list (lit ecdsa) blob curve (%region buf q))))
      (#t (Err raise 'value (Str8 append "ssh: a key of a type not served: " type) ())))))

(def ssh-pubkey-blob (fn (_ key) (List ref 1 key)))

; The type a key's blob and known_hosts name it by.
(def ssh-pubkey-type
  (fn (_ key)
    (match ((eq? (first key) (lit ed25519)) "ssh-ed25519")
           ((eq? (first key) (lit rsa)) "ssh-rsa")
           (#t (Str8 append "ecdsa-sha2-" (List ref 2 key))))))

; The type as OpenSSH's messages spell it: ED25519, RSA, ECDSA.
(def ssh-pubkey-label
  (fn (_ key)
    (match ((eq? (first key) (lit ed25519)) "ED25519") ((eq? (first key) (lit rsa)) "RSA") (#t "ECDSA"))))

; The key's size in bits: RSA's modulus's, the curve's, Ed25519's 256.
(def ssh-pubkey-bits
  (fn (_ key)
    (match
      ((eq? (first key) (lit ed25519)) 256)
      ((eq? (first key) (lit ecdsa))
        (match ((str=? (List ref 2 key) "nistp256") 256) ((str=? (List ref 2 key) "nistp384") 384) (#t 521)))
      (#t (do (def n (List ref 3 key))
              (def buf (first n)) (def at (List ref 1 n)) (def len (List ref 2 n))
              ; past the leading zero bytes, then the first byte's bits
              ((fn (self i)
                 (if (= i len) 0
                   (if (= (%byte buf (+ at i)) 0) (self (+ i 1))
                     (+ (* 8 (- len i 1))
                        ((fn (self b k) (if (= b 0) k (self (/ (- b (& b 1)) 2) (+ k 1)))) (%byte buf (+ at i)) 0)))))
               0))))))

; The signature algorithms a key verifies, ours first.
(def ssh-pubkey-algorithms
  (fn (_ key)
    (if (eq? (first key) (lit rsa)) (list "rsa-sha2-512" "rsa-sha2-256") (list (ssh-pubkey-type key)))))

; A digest of a region as a region of its own.
(def %digest
  (fn (_ hash data)
    (def bytes (ssh-copy (first data) (List ref 1 data) (List ref 2 data)))
    (def n (List ref 2 data))
    (match ((eq? hash (lit sha256)) (list (Sha256 bytes-n bytes n) 0 32))
           ((eq? hash (lit sha384)) (list (Sha384 bytes-n bytes n) 0 48))
           (#t (list (Sha512 bytes-n bytes n) 0 64)))))

; Whether a signature blob's region is key's over data's region: the
; algorithm one the key verifies, and the signature checked.
(def ssh-pubkey-verify?
  (fn (_ key sig data)
    (guard (e #f)
      (def in (ssh-in (first sig) (List ref 1 sig) (List ref 2 sig)))
      (def alg (ssh-get-text in))
      (def s (ssh-get-string in))
      (def buf (first sig))
      (match
        ((not (List any? (fn (_ a) (str=? a alg)) (ssh-pubkey-algorithms key))) #f)
        ((eq? (first key) (lit ed25519))
          (if (= (rest s) 64)
            (Ed25519 verify (List ref 2 key) (ssh-copy buf (first s) 64) (first data) (List ref 1 data) (List ref 2 data))
            #f))
        ((eq? (first key) (lit rsa))
          (do (def hash (if (str=? alg "rsa-sha2-512") (lit sha512) (lit sha256)))
              (Rsa verify-pkcs1 (List ref 3 key) (List ref 2 key) hash (%digest hash data) (%region buf s))))
        (#t
          (do (def curve (List ref 2 key))
              (def rs (ssh-in buf (first s) (rest s)))
              (def r (ssh-get-string rs))
              (def t (ssh-get-string rs))
              (match
                ((str=? curve "nistp256") (Ecdsa verify (lit p256) (List ref 3 key) (%digest (lit sha256) data) (%region buf r) (%region buf t)))
                ((str=? curve "nistp384") (Ecdsa verify (lit p384) (List ref 3 key) (%digest (lit sha384) data) (%region buf r) (%region buf t)))
                (#t #f))))))))

; A key's blob in base64, as known_hosts and authorized_keys spell it.
(def ssh-pubkey-base64
  (fn (_ key)
    (def b (ssh-pubkey-blob key))
    (def buf (first b)) (def at (List ref 1 b))
    (Base64 encode-bytes ((fn (self i acc) (if (< i 0) acc (self (- i 1) (pair (%byte buf (+ at i)) acc)))) (- (List ref 2 b) 1) ()))))

; A key from an authorized_keys or .pub line's two words, TYPE BASE64, or
; () when it is not a type served or does not read.
(def ssh-pubkey-of-line
  (fn (_ type b64)
    (guard (e ())
      (def bs (Base64 decode-bytes b64))
      (def n (List length bs))
      (def buf ((prim-ref (lit str) (lit make)) (+ n 1)))
      (def p ((prim-ref (lit str) (lit ->ptr)) buf))
      ((fn (self i bs) (unless (null? bs) (do ((prim-ref (lit ptr) (lit set!)) p i (first bs) 1) (self (+ i 1) (rest bs))))) 0 bs)
      (def key (ssh-pubkey-of buf 0 n))
      (if (str=? (ssh-pubkey-type key) type) key ()))))

(provide ssh/pubkey ssh-pubkey-of ssh-pubkey-of-line ssh-pubkey-blob ssh-pubkey-type ssh-pubkey-label ssh-pubkey-bits
  ssh-pubkey-algorithms ssh-pubkey-verify? ssh-pubkey-base64)
