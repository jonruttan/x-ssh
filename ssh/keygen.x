; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/keygen.x -- dropbearkey: making a key and showing one
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; `dropbearkey -t ed25519 -f FILE` makes an Ed25519 key from 32 random
; bytes and writes it in Dropbear's own format -- string "ssh-ed25519",
; then a string of the 32-byte secret and the 32-byte public key -- with
; FILE.pub beside it, the public line OpenSSH's authorized_keys and
; known_hosts take.  `dropbearkey -y -f FILE` shows an existing key's.
; Either prints what Dropbear prints: the public line, then the key's
; fingerprint, SHA256 of its blob in unpadded base64.  Neither file is
; ever written over; both are made readable by their owner alone.

(module ssh/keygen)

(import x/sys/file)
(import x/sys/posix)
(import x/codec/hex)
(import x/codec/base64)
(import x/codec/sha256)
(import x/codec/ed25519)
(import ssh/bytes ssh-out ssh-put-text ssh-put-string ssh-put-uint32 ssh-put-bytes ssh-out-run)
(import ssh/transport ssh-random)
(import ssh/keys ssh-key-of-dropbear-bytes)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %make-str (prim-ref (lit str) (lit make)))

(def %say (fn (_ fd text) (File write fd text (%byte-len text))))

(def %bytes
  (fn (_ s n)
    ((fn (self i acc) (if (< i 0) acc (self (- i 1) (pair (%char->int (%byte-ref s i)) acc))))
     (- n 1) ())))

; The public key's blob: string "ssh-ed25519", string the 32 bytes.
(def %blob
  (fn (_ pub)
    (def out (ssh-out))
    (ssh-put-text out "ssh-ed25519")
    (ssh-put-string out pub 0 32)
    (ssh-out-run out)))

; The public line: type, blob in base64, comment.
(def ssh-key-public-line
  (fn (_ pub comment)
    (def b (%blob pub))
    (Str8 append "ssh-ed25519 " (Base64 encode-bytes (%bytes (first b) (rest b))) " " comment)))

; The fingerprint: "SHA256:" and the blob's digest in base64, unpadded.
(def ssh-key-fingerprint
  (fn (_ pub)
    (def b (%blob pub))
    (def d (Base64 encode-bytes (Hex decode-bytes (Sha256 hex-n (first b) (rest b)))))
    (Str8 append "SHA256:" (Str8 sub 0 43 d))))

; The comment Dropbear gives a key it makes: user@host.
(def %default-comment
  (fn (_)
    (def user (Sys getenv "USER"))
    (def node (List find (fn (_ p) (eq? (first p) (lit nodename))) (Sys uname)))
    (Str8 append (if (null? user) "" user) "@" (if (null? node) "" (rest node)))))

; What dropbearkey prints for a key, to standard output.
(def %show
  (fn (_ pub comment)
    (%say 1 (Str8 append "Public key portion is:\n" (ssh-key-public-line pub comment) "\n"
                         "Fingerprint: " (ssh-key-fingerprint pub) "\n"))))

; A file made new, owner-only, holding n bytes of s; #f when it exists.
(def %write-new
  (fn (_ path s n)
    (def fd (File open path (list (lit wronly) (lit creat) (lit excl)) 384))
    (if (< fd 0) #f
      (do (File write fd s n) (File close fd) #t))))

; A key made and written to path, path.pub beside it, and shown.  The
; status: 0, or 1 when path is there already.
(def ssh-keygen-generate
  (fn (_ path comment)
    (%say 2 "Generating 256 bit ed25519 key, this may take a while...\n")
    (def seed (ssh-random 32))
    (def pub (Ed25519 public seed))
    (def file (ssh-out))
    (ssh-put-text file "ssh-ed25519")
    (ssh-put-uint32 file 64)
    (ssh-put-bytes file seed 0 32)
    (ssh-put-bytes file pub 0 32)
    (def r (ssh-out-run file))
    (def c (if (null? comment) (%default-comment) comment))
    (if (%write-new path (first r) (rest r))
      (do (def line (Str8 append (ssh-key-public-line pub c) "\n"))
          (unless (%write-new (Str8 append path ".pub") line (%byte-len line))
            (%say 2 (Str8 append "Save public key to " path ".pub failed: File exists\n")))
          (%show pub c)
          0)
      (do (%say 2 (Str8 append "Failed moving key file to " path ": File exists\n"
                               "Failed to generate key.\n"))
          1))))

; An existing key's public line and fingerprint shown.  The status: 0, or
; 1 when the file cannot be read or holds no key.
(def ssh-keygen-print
  (fn (_ path comment)
    (def fd (File open path (lit rdonly)))
    (if (< fd 0)
      (do (%say 2 (Str8 append "Failed reading '" path "'\n")) 1)
      (do (def buf (%make-str 16384))
          (def n (File read fd buf 16384))
          (File close fd)
          (def key (guard (e ()) (ssh-key-of-dropbear-bytes buf n)))
          (if (null? key)
            (do (%say 2 (Str8 append "Bad key in '" path "'\n")) 1)
            (do (%show (rest key) (if (null? comment) (%default-comment) comment)) 0))))))

(provide ssh/keygen ssh-keygen-generate ssh-keygen-print ssh-key-public-line ssh-key-fingerprint)
