; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/convert.x -- dropbearconvert: a key file in the other format
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; An ssh-ed25519 key read in one format (ssh/keys) and written in the
; other.  Dropbear's is string "ssh-ed25519", string the seed then the
; public key.  OpenSSH's (PROTOCOL.key) is "openssh-key-v1", NUL, string
; cipher "none", string kdf "none", string kdf options "", uint32 one
; key, string the public blob, string the private section: two check
; ints (zero, as Dropbear writes them), string type, string public,
; string the seed then the public, string comment "", then padding bytes
; 1, 2, .. to a multiple of eight; the whole in base64, 70 columns a
; line, between BEGIN and END lines.  The messages are Dropbear's, on
; standard error.

(module ssh/convert)

(import x/sys/file)
(import x/codec/base64)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-put-text ssh-put-string ssh-put-bytes ssh-out-run)
(import ssh/keys ssh-key-of-file)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))

(def %say (fn (_ text) (File write 2 text (%byte-len text))))

(def %bytes
  (fn (_ s n)
    ((fn (self i acc) (if (< i 0) acc (self (- i 1) (pair (%char->int (%byte-ref s i)) acc))))
     (- n 1) ())))

; The key in Dropbear's format: (BUF . LEN).
(def ssh-key-dropbear-bytes
  (fn (_ seed pub)
    (def out (ssh-out))
    (ssh-put-text out "ssh-ed25519")
    (ssh-put-uint32 out 64)
    (ssh-put-bytes out seed 0 32)
    (ssh-put-bytes out pub 0 32)
    (ssh-out-run out)))

; A base64 text in lines of 70 columns, each ended.
(def %lines
  (fn (self s)
    (if (<= (Str8 length s) 70) (Str8 append s "\n")
      (Str8 append (Str8 sub 0 70 s) "\n" (self (Str8 sub 70 (- (Str8 length s) 70) s))))))

; The key as an OpenSSH private key file's text.
(def ssh-key-openssh-text
  (fn (_ seed pub)
    (def blob (ssh-out))
    (ssh-put-text blob "ssh-ed25519")
    (ssh-put-string blob pub 0 32)
    (def b (ssh-out-run blob))
    (def pr (ssh-out))
    (ssh-put-uint32 pr 0)
    (ssh-put-uint32 pr 0)
    (ssh-put-text pr "ssh-ed25519")
    (ssh-put-string pr pub 0 32)
    (ssh-put-uint32 pr 64)
    (ssh-put-bytes pr seed 0 32)
    (ssh-put-bytes pr pub 0 32)
    (ssh-put-text pr "")
    ((fn (self i) (unless (= 0 (& (rest (ssh-out-run pr)) 7)) (do (ssh-put-byte pr i) (self (+ i 1))))) 1)
    (def p (ssh-out-run pr))
    (def out (ssh-out))
    (ssh-put-bytes out "openssh-key-v1" 0 14)
    (ssh-put-byte out 0)
    (ssh-put-text out "none")
    (ssh-put-text out "none")
    (ssh-put-text out "")
    (ssh-put-uint32 out 1)
    (ssh-put-string out (first b) 0 (rest b))
    (ssh-put-string out (first p) 0 (rest p))
    (def r (ssh-out-run out))
    (Str8 append "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                 (%lines (Base64 encode-bytes (%bytes (first r) (rest r))))
                 "-----END OPENSSH PRIVATE KEY-----\n")))

; Whether a file's first bytes are an OpenSSH key file's BEGIN line.
(def %openssh-file?
  (fn (_ path)
    (def fd (File open path (lit rdonly)))
    (if (< fd 0) #f
      (do (def buf ((prim-ref (lit str) (lit make)) 5))
          (def n (File read fd buf 5))
          (File close fd)
          (if (= n 5) (str=? (Str8 sub 0 5 buf) "-----") #f)))))

; n bytes of s written to path, read by its owner only, as Dropbear's
; umask has it; answers whether they were.
(def %write
  (fn (_ path s n)
    (def fd (File open path (list (lit wronly) (lit creat) (lit trunc)) 384))
    (if (< fd 0) #f
      (do (def w (File write fd s n)) (File close fd) (= w n)))))

; The key at in-path, in in-type's format, written to out-path in
; out-type's; answers the exit status.
(def ssh-convert
  (fn (_ in-type out-type in-path out-path)
    (def key
      (guard (e ())
        (if (eq? (str=? in-type "openssh") (%openssh-file? in-path)) (ssh-key-of-file in-path) ())))
    (if (null? key)
      (do (%say (Str8 append "Error reading key from '" in-path "'\n")) 1)
      (do (%say "Key is a ssh-ed25519 key\n")
          (def r (if (str=? out-type "openssh")
                   ((fn (_ t) (pair t (%byte-len t))) (ssh-key-openssh-text (first key) (rest key)))
                   (ssh-key-dropbear-bytes (first key) (rest key))))
          (if (%write out-path (first r) (rest r))
            (do (%say (Str8 append "Wrote key to '" out-path "'\n")) 0)
            (do (%say (Str8 append "Error writing key to '" out-path "'\n")) 1))))))

(provide ssh/convert ssh-key-dropbear-bytes ssh-key-openssh-text ssh-convert)
