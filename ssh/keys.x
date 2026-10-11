; # x-ssh -- SSH on x-lang, after Dropbear
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
; And Dropbear's own binary file, below.  Only an unencrypted
; ssh-ed25519 key is read: the one ssh-keygen -t
; ed25519 -N '' writes, and the one a user key for this client is.

(module ssh/keys)

(import x/sys/file)
(import x/codec/base64)
(import x/codec/ed25519)
(import ssh/bytes ssh-in ssh-get-uint32 ssh-get-string ssh-get-bytes ssh-get-text ssh-copy)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset1 (prim-ref (lit ptr) (lit set!)))

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

; The 32-byte seed of an unencrypted ssh-ed25519 key file's text.
(def ssh-seed-of-key-text
  (fn (_ text)
    (def raw (%bytes->str (Base64 decode-bytes (%body text))))
    (def in (ssh-in (first raw) 15 (- (rest raw) 15)))
    (def cipher (ssh-get-text in))
    (unless (str=? cipher "none") (Err raise 'value "ssh: the key is encrypted, and a passphrase is not served yet" ()))
    (ssh-get-text in)
    (ssh-get-text in)
    (def nkeys (ssh-get-uint32 in))
    (unless (= nkeys 1) (Err raise 'value "ssh: a key file with other than one key" ()))
    (ssh-get-string in)
    ; the private section, read in place: past its two check ints
    (def pr (ssh-get-string in))
    (def pin (ssh-in (first raw) (+ (first pr) 8) (- (rest pr) 8)))
    (def ktype (ssh-get-text pin))
    (unless (str=? ktype "ssh-ed25519") (Err raise 'value (Str8 append "ssh: a key of a type not served: " ktype) ()))
    (ssh-get-string pin)
    (def sk (ssh-get-string pin))
    (ssh-copy (first raw) (first sk) 32)))

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

; The 32-byte seed of a key file in either format: OpenSSH's is text that
; begins with its BEGIN line, Dropbear's is binary.
(def ssh-seed-of-key-file
  (fn (_ path)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      (ssh-seed-of-key-text (ssh-copy (first r) 0 (rest r)))
      (first (ssh-key-of-dropbear-bytes (first r) (rest r))))))

; A key file's two halves, (SEED . PUB), in either format: Dropbear's
; holds both, OpenSSH's seed makes its public half.
(def ssh-key-of-file
  (fn (_ path)
    (def r (%file-bytes path))
    (if (if (>= (rest r) 5) (str=? (Str8 sub 0 5 (first r)) "-----") #f)
      (do (def seed (ssh-seed-of-key-text (ssh-copy (first r) 0 (rest r))))
          (pair seed (Ed25519 public seed)))
      (ssh-key-of-dropbear-bytes (first r) (rest r)))))

(provide ssh/keys ssh-seed-of-key-text ssh-seed-of-key-file ssh-key-of-dropbear-bytes ssh-key-of-file)
