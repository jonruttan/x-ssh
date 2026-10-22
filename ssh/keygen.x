; # x-ssh -- SSH on x-lang
;
; ## ssh/keygen.x -- ssh-keygen: keys made, shown and rewritten
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What OpenSSH's ssh-keygen does with a key: make an Ed25519 one from 32
; random bytes, or an ECDSA one on P-256 or P-384, and write it in
; OpenSSH's private key format, sealed under a passphrase when one is
; given, FILE.pub beside it the public line authorized_keys and
; known_hosts take, then say so with its fingerprint -- SHA256 of the
; key's blob in unpadded base64 -- and its randomart; print a key file's
; public line (-y) or fingerprint (-l), Ed25519's, RSA's or ECDSA's;
; rewrite one under a new passphrase or none (-p), which turns a
; Dropbear key file into OpenSSH's; make the host keys a server wants
; (-A); and find or remove a host in known_hosts (-F, -R).

(module ssh/keygen)

(import x/type/vector)
(import x/sys/file)
(import x/sys/posix)
(import x/codec/hex)
(import x/codec/base64)
(import x/codec/sha256)
(import x/codec/ed25519)
(import x/codec/aes)
(import x/codec/bcrypt)
(import x/codec/ecdsa)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-text ssh-put-string ssh-put-uint32 ssh-put-bytes ssh-put-mpint ssh-out-run
  ssh-in ssh-get-uint32 ssh-get-string ssh-get-text ssh-copy)
(import ssh/transport ssh-random)
(import ssh/ask ssh-ask-secret)
(import ssh/keys ssh-key-file-sealed? ssh-identity-read-file ssh-pubkey-of-key-file
  ssh-key-wrong-passphrase)
(import ssh/known ssh-known-find ssh-known-remove!)
(import ssh/pubkey ssh-pubkey-of ssh-pubkey-of-line ssh-pubkey-blob ssh-pubkey-type ssh-pubkey-label ssh-pubkey-bits
  ssh-pubkey-base64 ssh-identity-pubkey ssh-identity-comment)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %cvt (prim-ref (lit convert) (lit to)))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))

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

; The public line: type, blob in base64, and the comment when there is one.
(def ssh-key-public-line
  (fn (_ pub comment)
    (def b (%blob pub))
    (Str8 append "ssh-ed25519 " (Base64 encode-bytes (%bytes (first b) (rest b)))
                 (if (if (null? comment) #t (= (Str8 length comment) 0)) "" (Str8 append " " comment)))))

; A blob's SHA256 digest, as bytes: the blob a region (BUF START LEN).
(def %digest
  (fn (_ b) (Hex decode-bytes (Sha256 hex-n (ssh-copy (first b) (List ref 1 b) (List ref 2 b)) (List ref 2 b)))))

(def %blob-region (fn (_ pub) ((fn (_ b) (list (first b) 0 (rest b))) (%blob pub))))

; The fingerprint: "SHA256:" and a blob's digest in base64, unpadded;
; an Ed25519 key's from its 32 bytes.
(def ssh-blob-fingerprint
  (fn (_ b) (Str8 append "SHA256:" (Str8 sub 0 43 (Base64 encode-bytes (%digest b))))))

(def ssh-key-fingerprint (fn (_ pub) (ssh-blob-fingerprint (%blob-region pub))))

; The digest's randomart, OpenSSH's drunken bishop: from the middle of a
; 17 by 9 field, each byte's four 2-bit pairs, low first, step a
; diagonal, each square visited counting up a symbol; S where it began, E
; where it ended.  The title is the key's type and size, [RSA 3072].
(def ssh-blob-randomart
  (fn (_ b title)
    (def w 17) (def h 9)
    (def symbols " .o+=*BOX@%&#/^SE")
    (def field (Vector make (* w h) 0))
    (def at (fn (_ x y) (+ 1 x (* w y))))
    (def clamp (fn (_ v hi) (if (< v 0) 0 (if (> v hi) hi v))))
    (def end
      (List fold
        (fn (_ xy byte)
          ((fn (self k b xy)
             (if (= k 4) xy
               (do (def x (clamp (+ (first xy) (if (= (& b 1) 0) -1 1)) (- w 1)))
                   (def y (clamp (+ (rest xy) (if (= (& b 2) 0) -1 1)) (- h 1)))
                   (when (< (%oref field (at x y)) 14) (%oset! field (at x y) (+ (%oref field (at x y)) 1)))
                   (self (+ k 1) (/ (- b (& b 3)) 4) (pair x y)))))
           0 byte xy))
        (pair 8 4) (%digest b)))
    (%oset! field (at 8 4) 15)
    (%oset! field (at (first end) (rest end)) 16)
    (def border
      (fn (_ title)
        (def pad (/ (- w (Str8 length title) (& (- w (Str8 length title)) 1)) 2))
        (Str8 append "+" (Str8 repeat pad "-") title (Str8 repeat (- w pad (Str8 length title)) "-") "+")))
    (Str8 join "\n"
      (List append
        (list (border title))
        (List map (fn (_ y) (Str8 append "|" (Str8 join "" (List map (fn (_ x) (Str8 sub (%oref field (at x y)) 1 symbols)) (List range 0 w))) "|"))
          (List range 0 h))
        (list (border "[SHA256]") "")))))

(def ssh-key-randomart (fn (_ pub) (ssh-blob-randomart (%blob-region pub) "[ED25519 256]")))

; A base64 text in lines of 70 columns, each ended.
(def %lines
  (fn (self s)
    (if (<= (Str8 length s) 70) (Str8 append s "\n")
      (Str8 append (Str8 sub 0 70 s) "\n" (self (Str8 sub 70 (- (Str8 length s) 70) s))))))

; An identity (ssh/pubkey's) as an OpenSSH private key file's text: the
; public blob, then the private section -- two check ints one random
; number, the type, the key's own parts, the comment, and padding 1, 2,
; 3 and on to the cipher's block, eight bytes unsealed.  The parts are
; Ed25519's public key and secret-then-public; ECDSA's curve, point and
; mpint d; RSA's mpint n, e, d, iqmp, p, q.  Under a passphrase, lock
; (PASS ROUNDS), the section is sealed as OpenSSH's ssh-keygen seals it:
; aes256-ctr, its 32-byte key and 16-byte counter block what bcrypt-pbkdf
; derives from the passphrase and 16 random bytes of salt over the
; rounds, padded to 16.
(def ssh-identity-openssh-text
  (fn (_ id comment . lock)
    (def pass (if (null? lock) "" (first lock)))
    (def sealed (> (%byte-len pass) 0))
    (def key (ssh-identity-pubkey id))
    (def secret (List ref 1 id))
    (def b (ssh-pubkey-blob key))
    (def bin (ssh-in (first b) (List ref 1 b) (List ref 2 b)))
    (def type (ssh-get-text bin))
    (def check (ssh-random 4))
    (def mp (fn (_ out r) (ssh-put-mpint out (first r) (List ref 1 r) (List ref 2 r))))
    (def pr (ssh-out))
    (ssh-put-bytes pr check 0 4)
    (ssh-put-bytes pr check 0 4)
    (ssh-put-text pr type)
    (match
      ((str=? type "ssh-ed25519")
        (do (def pk (ssh-get-string bin))
            (ssh-put-string pr (first b) (first pk) 32)
            (ssh-put-uint32 pr 64)
            (ssh-put-bytes pr secret 0 32)
            (ssh-put-bytes pr (first b) (first pk) 32)))
      ((str=? type "ssh-rsa")
        (do (mp pr (first secret)) (mp pr (List ref 2 secret)) (mp pr (List ref 1 secret))
            (mp pr (List ref 3 secret)) (mp pr (List ref 4 secret)) (mp pr (List ref 5 secret))))
      (#t
        (do (def curve (ssh-get-text bin))
            (def q (ssh-get-string bin))
            (ssh-put-text pr curve)
            (ssh-put-string pr (first b) (first q) (rest q))
            (mp pr (List ref 1 secret)))))
    (ssh-put-text pr (if (null? comment) "" comment))
    (def mask (if sealed 15 7))
    ((fn (self i) (unless (= 0 (& (rest (ssh-out-run pr)) mask)) (do (ssh-put-byte pr i) (self (+ i 1))))) 1)
    (def p (ssh-out-run pr))
    (def opts (ssh-out))
    (def salt (if sealed (ssh-random 16) ()))
    (when sealed
      (do (ssh-put-string opts salt 0 16)
          (ssh-put-uint32 opts (List ref 1 lock))))
    (def o (ssh-out-run opts))
    (def section
      (if (not sealed) (first p)
        ((fn (_ kiv) (Aes ctr kiv 32 (ssh-copy kiv 32 16) (first p) 0 (rest p)))
         (Bcrypt pbkdf pass (%byte-len pass) salt 16 (List ref 1 lock) 48))))
    (def out (ssh-out))
    (ssh-put-bytes out "openssh-key-v1" 0 14)
    (ssh-put-byte out 0)
    (ssh-put-text out (if sealed "aes256-ctr" "none"))
    (ssh-put-text out (if sealed "bcrypt" "none"))
    (ssh-put-string out (first o) 0 (rest o))
    (ssh-put-uint32 out 1)
    (ssh-put-string out (first b) (List ref 1 b) (List ref 2 b))
    (ssh-put-string out section 0 (rest p))
    (def r (ssh-out-run out))
    (Str8 append "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                 (%lines (Base64 encode-bytes (%bytes (first r) (rest r))))
                 "-----END OPENSSH PRIVATE KEY-----\n")))

; An Ed25519 key's 32 bytes as ssh/pubkey's key.
(def %ed25519-key (fn (_ pub) ((fn (_ b) (ssh-pubkey-of (first b) 0 (rest b))) (%blob pub))))

; The Ed25519 key's file text from its two halves, as above.
(def ssh-key-openssh-text
  (fn (_ seed pub comment . lock)
    (def id (list (%ed25519-key pub) seed comment))
    (if (null? lock) (ssh-identity-openssh-text id comment)
      (ssh-identity-openssh-text id comment (first lock) (List ref 1 lock)))))

; A key's public line: its type, its blob in base64, and the comment when
; there is one.
(def %public-line
  (fn (_ key comment)
    (Str8 append (ssh-pubkey-type key) " " (ssh-pubkey-base64 key)
                 (if (if (null? comment) #t (= (Str8 length comment) 0)) "" (Str8 append " " comment)))))

; A key's size, fingerprint and type, as -l and making a key say them,
; and its randomart's title.
(def %bits (fn (_ key) (%num (ssh-pubkey-bits key))))
(def %title (fn (_ key) (Str8 append "[" (ssh-pubkey-label key) " " (%bits key) "]")))
(def %art (fn (_ key) (ssh-blob-randomart (ssh-pubkey-blob key) (%title key))))
(def %print (fn (_ key) (ssh-blob-fingerprint (ssh-pubkey-blob key))))

; text written to path with mode, made or truncated; #f when it cannot be.
(def %write
  (fn (_ path text mode)
    (def fd (File open path (list (lit wronly) (lit creat) (lit trunc)) mode))
    (if (< fd 0) #f
      (do (File chmod path mode)
          (def n (File write fd text (%byte-len text)))
          (File close fd)
          (= n (%byte-len text))))))

; A new identity of a type: ed25519, from 32 random bytes; ecdsa on a
; curve of bits 256 or 384, d random bytes of its length tried until one
; lies in 1..n-1.
(def ssh-identity-make
  (fn (_ type bits)
    (if (str=? type "ed25519")
      ((fn (_ seed) (list (%ed25519-key (Ed25519 public seed)) seed "")) (ssh-random 32))
      (do (def curve (if (= bits 384) (lit p384) (lit p256)))
          (def name (if (= bits 384) "nistp384" "nistp256"))
          (def len (if (= bits 384) 48 32))
          ((fn (self)
             (def d (ssh-random len))
             (def q (guard (e ()) (Ecdsa public curve (list d 0 len))))
             (if (null? q) (self)
               (do (def out (ssh-out))
                   (ssh-put-text out (Str8 append "ecdsa-sha2-" name))
                   (ssh-put-text out name)
                   (ssh-put-string out (first q) (List ref 1 q) (List ref 2 q))
                   (def r (ssh-out-run out))
                   (list (ssh-pubkey-of (first r) 0 (rest r)) (list curve (list d 0 len)) "")))))))))

; A key of a type made and written to path, sealed under lock (PASS
; ROUNDS) when one is given, path.pub beside it: its public key, or #f
; when a file could not be written.
(def ssh-keygen-make
  (fn (_ path comment type bits . lock)
    (def id (ssh-identity-make type bits))
    (def key (ssh-identity-pubkey id))
    (def text (if (null? lock) (ssh-identity-openssh-text id comment)
                (ssh-identity-openssh-text id comment (first lock) (List ref 1 lock))))
    (if (if (%write path text 384)
          (%write (Str8 append path ".pub") (Str8 append (%public-line key comment) "\n") 420) #f)
      key #f)))

; The comment OpenSSH gives a key it makes: user@host.
(def %default-comment
  (fn (_)
    (def user (Sys getenv "USER"))
    (def node (List find (fn (_ p) (eq? (first p) (lit nodename))) (Sys uname)))
    (Str8 append (if (null? user) "" user) "@" (if (null? node) "" (rest node)))))

; A line read from standard input -- the platform keeps it on fd 3 -- or
; () at its end.
(def %read-line
  (fn (_)
    (def one (%make-str 1))
    ((fn (self acc)
       (if (< (guard (e -1) (File read 3 one 1)) 1)
         (if (null? acc) () (Str8 join "" (List reverse acc)))
         (if (= (%char->int (%byte-ref one 0)) 10) (Str8 join "" (List reverse acc))
           (self (pair (Str8 sub 0 1 one) acc)))))
     ())))

; A passphrase asked for as ssh-keygen's read_passphrase asks, standard
; input allowed; "" when there is none.
(def %secret (fn (_ text) ((fn (_ a) (if (null? a) "" a)) (ssh-ask-secret text #t))))

(def %message (fn (_ e) (guard (e2 "an internal error") (e msg))))

; The default key file of a type: ~/.ssh/id_ed25519, ~/.ssh/id_ecdsa.
(def %home-key (fn (_ type) (Str8 append (Sys getenv "HOME") "/.ssh/id_" type)))

; The file named, or the one asked for, the default when the answer is
; empty.
(def %file
  (fn (_ file question . type)
    (def home (%home-key (if (null? type) "ed25519" (first type))))
    (if (not (null? file)) file
      (do (%say 1 (Str8 append question " (" home "): "))
          (def a (%read-line))
          (if (if (null? a) #t (= (Str8 length a) 0)) home a)))))

; A key made: the file asked for when not named, one already there kept
; unless the answer is y, the passphrase asked for when -N gives none --
; twice, and again until the two agree, unless the first is empty -- and
; the key sealed under it over rounds of bcrypt-pbkdf.
(def %generate
  (fn (_ file comment passphrase quiet rounds type bits)
    (unless quiet (%say 1 (Str8 append "Generating public/private " type " key pair.\n")))
    (def path (%file file "Enter file in which to save the key" type))
    (def slash ((fn (self i) (if (< i 0) () (if (= (%byte-ref path i) #\/) i (self (- i 1))))) (- (Str8 length path) 1)))
    (def dir (if (if (null? slash) #t (= slash 0)) () (Str8 sub 0 slash path)))
    (when (if (null? file) (if (null? dir) #f (not (File exists? dir))) #f)
      (do (File mkdir dir 448) (%say 1 (Str8 append "Created directory '" dir "'.\n"))))
    (def overwrite
      (if (not (File exists? path)) #t
        (do (%say 1 (Str8 append path " already exists.\nOverwrite (y/n)? "))
            (def a (%read-line))
            (if (null? a) #f (if (> (Str8 length a) 0) (if (= (%byte-ref a 0) #\y) #t (= (%byte-ref a 0) #\Y)) #f)))))
    (def pass
      (match
        ((not overwrite) "")
        ((not (null? passphrase)) passphrase)
        (#t ((fn (self)
               (def a (%secret (Str8 append "Enter passphrase for \"" path "\" (empty for no passphrase): ")))
               (if (= (Str8 length a) 0) a
                 (if (str=? a (%secret "Enter same passphrase again: ")) a
                   (do (%say 1 "Passphrases do not match.  Try again.\n") (self)))))))))
    (def c (if (null? comment) (%default-comment) comment))
    (if (not overwrite) 1
      (do (def key (if (= (Str8 length pass) 0) (ssh-keygen-make path c type bits) (ssh-keygen-make path c type bits pass rounds)))
          (if (not key)
            (do (%say 2 (Str8 append "Saving key \"" path "\" failed\n")) 1)
            (do (unless quiet
                  (%say 1 (Str8 append "Your identification has been saved in " path "\n"
                                       "Your public key has been saved in " path ".pub\n"
                                       "The key fingerprint is:\n" (%print key) " " c "\n"
                                       "The key's randomart image is:\n" (%art key))))
                0))))))

; A key file read: (ID KEY COMMENT), ID the identity or () -- a public
; line's file has none -- KEY its public key, of any type served; () when
; it holds no key this tool reads.  A sealed key is opened with the
; passphrase (ask) answers, or read for its public half alone, comment
; (), when ask is (); wrong when the passphrase is.
(def %read-key
  (fn (_ path ask)
    (def text (guard (e ()) (File read-all path)))
    (def ws (if (null? text) () (List filter (fn (_ w) (> (Str8 length w) 0)) (Str8 split " " (first (Str8 split "\n" text))))))
    (def line (if (< (List length ws) 2) () (ssh-pubkey-of-line (first ws) (List ref 1 ws))))
    (match
      ((null? text) ())
      ((not (null? line)) (list () line (Str8 join " " (List drop 2 ws))))
      (#t
        (guard (e (if (str=? (%message e) ssh-key-wrong-passphrase) (lit wrong) ()))
          (def sealed (ssh-key-file-sealed? path))
          (def id (match ((not sealed) (ssh-identity-read-file path ""))
                         ((null? ask) ())
                         (#t (ssh-identity-read-file path (ask)))))
          (if (null? id) (list () (ssh-pubkey-of-key-file path) ())
            (list id (ssh-identity-pubkey id) (ssh-identity-comment id))))))))

(def %missing (fn (_ path) (%say 2 (Str8 append path ": No such file or directory\n")) 255))

; A line ssh-keygen dies with: OpenSSH's log ends a line on standard
; error CR LF.
(def %fatal (fn (_ text) (%say 2 (Str8 append text "\r\n")) 255))

(def %wrong (fn (_ key) (eq? key (lit wrong))))

; -y: the public line of a private key file; a sealed one's passphrase
; -P's, or asked for.
(def %public
  (fn (_ file given)
    (def path (%file file "Enter file in which the key is"))
    (if (not (File exists? path)) (%missing path)
      (do (def key (%read-key path (fn (_) (if (null? given) (%secret (Str8 append "Enter passphrase for \"" path "\": ")) given))))
          (match
            ((%wrong key) (%fatal (Str8 append "Load key \"" path "\": " ssh-key-wrong-passphrase)))
            ((if (null? key) #t (null? (first key)))
              (%fatal (Str8 append "Load key \"" path "\": invalid format")))
            (#t (do (%say 1 (Str8 append (%public-line (List ref 1 key) (List ref 2 key)) "\n")) 0)))))))

; -l: a key's size, fingerprint, comment and type; under -v its randomart.
; Only the public half is read, so a sealed key asks for nothing: its
; comment is FILE.pub's, as OpenSSH's sshkey_load_public finds it, or
; none.
(def %fingerprint
  (fn (_ file art)
    (def path (%file file "Enter file in which the key is"))
    (if (not (File exists? path)) (%missing path)
      (do (def key (%read-key path ()))
          (if (if (null? key) #t (%wrong key))
            (do (%say 2 (Str8 append path " is not a key file.\n")) 255)
            (do (def line? (if (null? (first key)) (not (null? (List ref 2 key))) #f))
                (def beside (if line? () (%read-key (Str8 append path ".pub") ())))
                (def c (if (if (null? beside) #f (not (%wrong beside))) (List ref 2 beside) (List ref 2 key)))
                (def k (List ref 1 key))
                (%say 1 (Str8 append (%bits k) " " (%print k) " "
                                     (if (if (null? c) #t (= (Str8 length c) 0)) "no comment" c) " (" (ssh-pubkey-label k) ")\n"
                                     (if art (%art k) "")))
                0))))))

; -p: the key rewritten in OpenSSH's format under the new passphrase: the
; old one -P's or asked for when the key is sealed, the new one -N's or
; asked for twice, sealed over rounds of bcrypt-pbkdf unless it is empty.
(def %passphrase
  (fn (_ file old new rounds)
    (def path (%file file "Enter file in which the key is"))
    (if (not (File exists? path)) (%missing path)
      (do (def key (%read-key path (fn (_) (if (null? old) (%secret "Enter old passphrase: ") old))))
          (match
            ((%wrong key) (%fatal (Str8 append "Failed to load key " path ": " ssh-key-wrong-passphrase)))
            ((if (null? key) #t (null? (first key))) (%fatal (Str8 append "Load key \"" path "\": invalid format")))
            (#t
              (do (def c (List ref 2 key))
                  (%say 1 (Str8 append "Key has comment '" (if (null? c) "" c) "'\n"))
                  (def pass (if (not (null? new)) new
                              (do (def a (%secret "Enter new passphrase (empty for no passphrase): "))
                                  (if (str=? a (%secret "Enter same passphrase again: ")) a #f))))
                  (if (not pass)
                    (do (%say 1 "Pass phrases do not match.  Try again.\n") 1)
                    (if (%write path (ssh-identity-openssh-text (first key) c pass rounds) 384)
                      (do (%say 1 "Your identification has been saved with the new passphrase.\n") 0)
                      (do (%say 2 (Str8 append "Saving key \"" path "\" failed\n")) 255))))))))))

; -A: each host key a server reads by default made where it is missing,
; under a prefix directory when one is given: ECDSA's on P-256 and
; Ed25519's, the types this tool makes, named in the order made.
(def %hosts
  (fn (_ prefix)
    (def node (List find (fn (_ p) (eq? (first p) (lit nodename))) (Sys uname)))
    (def comment (Str8 append "root@" (if (null? node) "" (rest node))))
    (def path (fn (_ name) (Str8 append (if (null? prefix) "" prefix) "/etc/ssh/ssh_host_" name "_key")))
    (def wanted (List filter (fn (_ t) (not (File exists? (path (first t)))))
                  (list (list "ecdsa" "ECDSA" 256) (list "ed25519" "ED25519" 256))))
    (unless (null? wanted)
      (do (%say 1 "ssh-keygen: generating new host keys:")
          (List for-each
            (fn (_ t)
              (%say 1 (Str8 append " " (List ref 1 t)))
              (unless (ssh-keygen-make (path (first t)) comment (first t) (List ref 2 t))
                (%say 2 (Str8 append "Could not save your private key in " (path (first t)) ": No such file or directory\n"))))
            wanted)
          (%say 1 " \n")))
    0))

(def %known-file (fn (_ file) (if (null? file) (Str8 append (Sys getenv "HOME") "/.ssh/known_hosts") file)))

; -F: the lines of known_hosts naming a host; 1 when there are none.
(def %find
  (fn (_ host file)
    (def found (ssh-known-find (%known-file file) host))
    (List for-each (fn (_ l) (%say 1 (Str8 append "# Host " host " found: line " (%num (first l)) " \n" (rest l) "\n"))) found)
    (if (null? found) 1 0)))

; -R: the lines naming a host taken out of known_hosts, its old text kept.
(def %remove
  (fn (_ host file)
    (def path (%known-file file))
    (if (not (File exists? path)) (%missing path)
      (do (def gone (ssh-known-remove! path host))
          (if (null? gone)
            (%say 2 (Str8 append "Host " host " not found in " path "\n"))
            (do (List for-each (fn (_ n) (%say 1 (Str8 append "# Host " host " found: line " (%num n) "\n"))) gone)
                (%say 1 (Str8 append path " updated.\nOriginal contents retained as " path ".old\n"))))
          0))))

; The key tool's plan done; the exit status.
(def ssh-keygen-main
  (fn (_ what)
    (def a (fn (_ i) (List ref i what)))
    (match
      ((eq? (first what) (lit generate)) (%generate (a 1) (a 2) (a 3) (a 4) (a 5) (a 6) (a 7)))
      ((eq? (first what) (lit public)) (%public (a 1) (a 2)))
      ((eq? (first what) (lit fingerprint)) (%fingerprint (a 1) (a 2)))
      ((eq? (first what) (lit passphrase)) (%passphrase (a 1) (a 2) (a 3) (a 4)))
      ((eq? (first what) (lit hosts)) (%hosts (a 1)))
      ((eq? (first what) (lit find)) (%find (a 1) (a 2)))
      (#t (%remove (a 1) (a 2))))))

(provide ssh/keygen ssh-keygen-main ssh-keygen-make ssh-key-public-line ssh-key-fingerprint ssh-key-randomart
  ssh-blob-fingerprint ssh-blob-randomart
  ssh-key-openssh-text ssh-identity-openssh-text ssh-identity-make)
