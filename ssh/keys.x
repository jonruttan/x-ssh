; # x-ssh -- SSH on x-lang
;
; ## ssh/keys.x -- key files
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; The OpenSSH private key file (PROTOCOL.key): a PEM-like wrapper around
; base64 of "openssh-key-v1", NUL, string cipher, string kdf, string kdf
; options, uint32 how many keys, string the public blob, string the
; private section -- two check ints, string type, string public, string
; private (the seed then the public again), string comment, padding.
; Under a passphrase the private section is sealed: cipher aes256-ctr
; (or aes128-ctr, aes192-ctr), kdf bcrypt, its options string salt and
; uint32 rounds, and the cipher's key and counter block the bytes
; bcrypt-pbkdf derives from the passphrase and the salt.  The public
; blob is never sealed.  And Dropbear's own binary file, below.  Only
; ssh-ed25519 keys are read.

(module ssh/keys)

(import x/sys/file)
(import x/codec/base64)
(import x/codec/ed25519)
(import x/codec/aes)
(import x/codec/bcrypt)
(import ssh/bytes ssh-in ssh-get-uint32 ssh-get-string ssh-get-bytes ssh-get-text ssh-copy ssh-out ssh-put-text ssh-put-string ssh-out-run)
(import ssh/pubkey ssh-pubkey-of ssh-pubkey-type ssh-ecdsa-curve)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset1 (prim-ref (lit ptr) (lit set!)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))

; A byte list as a string, NULs and all.
(def %bytes->str
  (fn (_ bs)
    (def n (List length bs))
    (def s (%make-str n))
    (def p (%str->ptr s))
    ((fn (self i xs) (unless (null? xs) (do (%pset1 p i (first xs) 1) (self (+ i 1) (rest xs))))) 0 bs)
    (pair s n)))

; The base64 body between the BEGIN and END lines of a key file's text.
(def %body
  (fn (_ text)
    (Str8 join ""
      (List filter (fn (_ l) (if (= (Str8 length l) 0) #f (not (str=? (Str8 sub 0 1 l) "-"))))
        (Str8 split "\n" text)))))

; What OpenSSH says of a sealed key given no passphrase or a wrong one.
(def ssh-key-wrong-passphrase "incorrect passphrase supplied to decrypt private key")

; The key types a key file is read for.
(def %types (list "ssh-ed25519" "ssh-rsa" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521"))

; The ciphers a key file is sealed with, and their key sizes; none's 0.
(def %ciphers (list (pair "none" 0) (pair "aes128-ctr" 16) (pair "aes192-ctr" 24) (pair "aes256-ctr" 32)))

; An OpenSSH key file's text taken apart, nothing opened: (BUF CIPHER
; KDF OPTIONS PUB PRIVATE BLOB), BUF the decoded bytes, OPTIONS, PRIVATE
; and BLOB regions of it as (START . LEN), BLOB the public key's, PUB an
; Ed25519 key's 32 bytes or () for another type.
(def %parts
  (fn (_ text)
    (def raw (%bytes->str (Base64 decode-bytes (%body text))))
    (def buf (first raw))
    (def in (ssh-in buf 15 (- (rest raw) 15)))
    (def cipher (ssh-get-text in))
    (def kdf (ssh-get-text in))
    (def options (ssh-get-string in))
    (unless (= (ssh-get-uint32 in) 1) (Err raise 'value "a key file with other than one key" ()))
    (def blob (ssh-get-string in))
    (def bin (ssh-in buf (first blob) (rest blob)))
    (def ktype (ssh-get-text bin))
    (unless (List any? (fn (_ t) (str=? t ktype)) %types) (Err raise 'value (Str8 append "a key of a type not served: " ktype) ()))
    (def ed? (str=? ktype "ssh-ed25519"))
    (def pk (if ed? (ssh-get-string bin) (pair 0 32)))
    (unless (= (rest pk) 32) (Err raise 'value "an ssh-ed25519 key that is not 32 bytes" ()))
    (list buf cipher kdf options (if ed? (ssh-copy buf (first pk) 32) ()) (ssh-get-string in) blob)))

; The private section's bytes, opened with the passphrase when sealed:
; (BUF . LEN).  No passphrase, or an empty one, opens no sealed key.
(def %private
  (fn (_ parts pass)
    (def buf (first parts))
    (def cipher (List ref 1 parts))
    (def pr (List ref 5 parts))
    (def size ((fn (_ c) (if (null? c) () (rest c))) (List find (fn (_ c) (str=? (first c) cipher)) %ciphers)))
    (match
      ((null? size) (Err raise 'value (Str8 append "a key sealed with " cipher ", a cipher not served") ()))
      ((= size 0) (pair (ssh-copy buf (first pr) (rest pr)) (rest pr)))
      ((not (str=? (List ref 2 parts) "bcrypt"))
        (Err raise 'value (Str8 append "a key sealed under " (List ref 2 parts) ", a kdf not served") ()))
      ((if (null? pass) #t (= (%byte-len pass) 0)) (Err raise 'value ssh-key-wrong-passphrase ()))
      (#t
        (do (def opts (List ref 3 parts))
            (def oin (ssh-in buf (first opts) (rest opts)))
            (def salt (ssh-get-string oin))
            (def rounds (ssh-get-uint32 oin))
            (def kiv (Bcrypt pbkdf pass (%byte-len pass) (ssh-copy buf (first salt) (rest salt)) (rest salt)
                                rounds (+ size 16)))
            (pair (Aes ctr kiv size (ssh-copy kiv size 16) buf (first pr) (rest pr)) (rest pr)))))))

; An OpenSSH ssh-ed25519 key file's text as (SEED PUB COMMENT), the seed
; 32 bytes, a sealed one opened with pass.  Check ints that differ are a
; wrong passphrase.
(def ssh-key-of-text
  (fn (_ text pass)
    (def parts (%parts text))
    (def p (%private parts pass))
    (def pin (ssh-in (first p) 0 (rest p)))
    (unless (= (ssh-get-uint32 pin) (ssh-get-uint32 pin)) (Err raise 'value ssh-key-wrong-passphrase ()))
    (def ktype (ssh-get-text pin))
    (unless (List any? (fn (_ t) (str=? t ktype)) %types) (Err raise 'value (Str8 append "a key of a type not served: " ktype) ()))
    (ssh-get-string pin)
    (def sk (ssh-get-string pin))
    (list (ssh-copy (first p) (first sk) 32) (List ref 4 parts) (ssh-get-text pin))))

; An OpenSSH key file's text as an identity (ssh/pubkey's): Ed25519,
; RSA or ECDSA, a sealed one opened with pass.  The private section
; holds, after the check ints and the type: Ed25519's public key, its
; secret and public again; RSA's mpint n, e, d, iqmp, p, q; ECDSA's
; curve, point and mpint d.  Then the comment.
(def ssh-key-identity-of-text
  (fn (_ text pass)
    (def parts (%parts text))
    (def blob (List ref 6 parts))
    (def key (ssh-pubkey-of (first parts) (first blob) (rest blob)))
    (def p (%private parts pass))
    (def pb (first p))
    (def pin (ssh-in pb 0 (rest p)))
    (unless (= (ssh-get-uint32 pin) (ssh-get-uint32 pin)) (Err raise 'value ssh-key-wrong-passphrase ()))
    (def ktype (ssh-get-text pin))
    (unless (str=? ktype (ssh-pubkey-type key)) (Err raise 'value "a key file whose halves are of two types" ()))
    (def region (fn (_ r) (list pb (first r) (rest r))))
    (def secret
      (match
        ((str=? ktype "ssh-ed25519") (do (ssh-get-string pin) (ssh-copy pb (first (ssh-get-string pin)) 32)))
        ((str=? ktype "ssh-rsa")
          (do (def n (ssh-get-string pin))
              (def e (ssh-get-string pin))
              (def d (ssh-get-string pin))
              (def iqmp (ssh-get-string pin))
              (def p (ssh-get-string pin))
              (def q (ssh-get-string pin))
              (list (region n) (region d) (region e) (region iqmp) (region p) (region q))))
        (#t
          (do (def curve (ssh-get-text pin))
              (ssh-get-string pin)
              (def d (ssh-get-string pin))
              (list (ssh-ecdsa-curve curve) (region d))))))
    (list key secret (ssh-get-text pin))))

; A key file read as an identity in either format: OpenSSH's, opened with
; pass when sealed; Dropbear's, Ed25519's alone here, never sealed, with
; no comment.
(def ssh-identity-read-file
  (fn (_ path pass)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      (ssh-key-identity-of-text (ssh-copy (first r) 0 (rest r)) pass)
      ((fn (_ k) (list (%ed25519-pubkey (rest k)) (first k) "")) (ssh-key-of-dropbear-bytes (first r) (rest r))))))

; An Ed25519 public key's 32 bytes as ssh/pubkey's key.
(def %ed25519-pubkey
  (fn (_ pub)
    (def out (ssh-out))
    (ssh-put-text out "ssh-ed25519")
    (ssh-put-string out pub 0 32)
    (def r (ssh-out-run out))
    (ssh-pubkey-of (first r) 0 (rest r))))

; A key file's public key, of any type, read without its passphrase.
(def ssh-pubkey-of-key-file
  (fn (_ path)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      ((fn (_ parts) ((fn (_ b) (ssh-pubkey-of (first parts) (first b) (rest b))) (List ref 6 parts)))
       (%parts (ssh-copy (first r) 0 (rest r))))
      (%ed25519-pubkey (rest (ssh-key-of-dropbear-bytes (first r) (rest r)))))))

; The 32-byte seed of an ssh-ed25519 key file's text, opened with the
; passphrase when one is given.
(def ssh-seed-of-key-text
  (fn (_ text . pass) (first (ssh-key-of-text text (if (null? pass) () (first pass))))))

; A key file's bytes, NULs and all: (BUF . LEN).  A key file is small;
; one read of a buffer past any key's size takes it whole.
(def %file-bytes
  (fn (_ path)
    (def fd (File open path (lit rdonly)))
    (when (< fd 0) (Err raise 'io (Str8 append "ssh: cannot read " path) ()))
    (def buf (%make-str 16384))
    (def n (File read fd buf 16384))
    (File close fd)
    (when (< n 0) (Err raise 'io (Str8 append "ssh: cannot read " path) ()))
    (pair buf n)))

; Dropbear's own key file: string "ssh-ed25519", then a string of 64
; bytes, the 32-byte secret then the 32-byte public key.  Answers
; (SEED . PUB).
(def ssh-key-of-dropbear-bytes
  (fn (_ buf n)
    (def in (ssh-in buf 0 n))
    (def ktype (ssh-get-text in))
    (unless (str=? ktype "ssh-ed25519") (Err raise 'value (Str8 append "ssh: a key of a type not served: " ktype) ()))
    (def k (ssh-get-string in))
    (unless (= (rest k) 64) (Err raise 'value "ssh: an ssh-ed25519 key that is not 64 bytes" ()))
    (pair (ssh-copy buf (first k) 32) (ssh-copy buf (+ (first k) 32) 32))))

; A key file read as (SEED PUB COMMENT) in either format: OpenSSH's is
; text that begins with its BEGIN line, opened with pass when sealed;
; Dropbear's is binary, never sealed, and keeps no comment.
(def ssh-key-read-file
  (fn (_ path pass)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      (ssh-key-of-text (ssh-copy (first r) 0 (rest r)) pass)
      ((fn (_ k) (list (first k) (rest k) "")) (ssh-key-of-dropbear-bytes (first r) (rest r))))))

(def %pass (fn (_ more) (if (null? more) () (first more))))

; The 32-byte seed of a key file in either format.
(def ssh-seed-of-key-file (fn (_ path . pass) (first (ssh-key-read-file path (%pass pass)))))

; A key file's two halves, (SEED . PUB), in either format.
(def ssh-key-of-file
  (fn (_ path . pass) ((fn (_ k) (pair (first k) (List ref 1 k))) (ssh-key-read-file path (%pass pass)))))

; A key file's comment: OpenSSH's file keeps one; Dropbear's has none, "".
(def ssh-key-comment-of-file (fn (_ path . pass) (List ref 2 (ssh-key-read-file path (%pass pass)))))

; Whether a key file is sealed under a passphrase: only OpenSSH's can be.
(def ssh-key-file-sealed?
  (fn (_ path)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      (not (str=? (List ref 1 (%parts (ssh-copy (first r) 0 (rest r)))) "none"))
      #f)))

; A key file's 32-byte public key, read without its passphrase: OpenSSH's
; file keeps it unsealed, Dropbear's beside the secret.
(def ssh-public-of-key-file
  (fn (_ path)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      (List ref 4 (%parts (ssh-copy (first r) 0 (rest r))))
      (rest (ssh-key-of-dropbear-bytes (first r) (rest r))))))

; A public line, `ssh-ed25519 BASE64 [COMMENT]`, as (PUB . COMMENT).
(def ssh-key-of-public-line
  (fn (_ line)
    (def ws (List filter (fn (_ w) (> (Str8 length w) 0)) (Str8 split " " line)))
    (unless (if (> (List length ws) 1) (str=? (first ws) "ssh-ed25519") #f)
      (Err raise 'value "not an ssh-ed25519 public line" ()))
    (def raw (%bytes->str (Base64 decode-bytes (List ref 1 ws))))
    (def in (ssh-in (first raw) 0 (rest raw)))
    (unless (str=? (ssh-get-text in) "ssh-ed25519") (Err raise 'value "not an ssh-ed25519 public line" ()))
    (def k (ssh-get-string in))
    (unless (= (rest k) 32) (Err raise 'value "an ssh-ed25519 key that is not 32 bytes" ()))
    (pair (ssh-copy (first raw) (first k) 32) (Str8 join " " (List drop 2 ws)))))

(provide ssh/keys ssh-key-of-text ssh-seed-of-key-text ssh-seed-of-key-file ssh-key-of-dropbear-bytes ssh-key-of-file
  ssh-key-comment-of-file ssh-key-read-file ssh-key-file-sealed? ssh-public-of-key-file ssh-key-of-public-line ssh-key-wrong-passphrase
  ssh-key-identity-of-text ssh-identity-read-file ssh-pubkey-of-key-file)
