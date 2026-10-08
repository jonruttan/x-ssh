; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/bytes.x -- the wire's encodings
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; RFC 4251 5: byte, boolean, uint32, string (a uint32 count then the
; bytes), mpint (a string holding a two's-complement big-endian number)
; and name-list (a string of comma-separated names).  Everything is
; binary -- a packet has NULs inside -- so bytes are read through
; byte-ref and written through the pointer door, never through the
; string's own length.
;
; An OUT is a growing buffer: (BUF LEN CAP) in a three-slot vector, the
; bytes written so far in BUF's first LEN.  An IN is a window on a
; string: (BUF POS END), POS the next byte to read.  A reader past its
; end raises, since a short packet is an error, never a zero.

(module ssh/bytes)

(import x/type/vector)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset1 (prim-ref (lit ptr) (lit set!)))

(def %byte (fn (_ s i) (%char->int (%byte-ref s i))))

; --- writing ------------------------------------------------------------

(def ssh-out
  (fn (_)
    (def v (Vector make 3 0))
    (%oset! v 1 (%make-str 256))
    (%oset! v 2 0)
    (%oset! v 3 256)
    v))

; Room for n more bytes: the buffer doubled until they fit.
(def %room!
  (fn (self out n)
    (when (> (+ (%oref out 2) n) (%oref out 3))
      (do (def cap (* (%oref out 3) 2))
          (def buf (%make-str cap))
          (def p (%str->ptr buf))
          (def old (%oref out 1))
          ((fn (self i) (unless (= i (%oref out 2)) (do (%pset1 p i (%byte old i) 1) (self (+ i 1))))) 0)
          (%oset! out 1 buf)
          (%oset! out 3 cap)
          (self out n)))))

(def ssh-put-byte
  (fn (_ out b)
    (%room! out 1)
    (%pset1 (%str->ptr (%oref out 1)) (%oref out 2) (& b 255) 1)
    (%oset! out 2 (+ (%oref out 2) 1))))

(def ssh-put-uint32
  (fn (_ out n)
    (ssh-put-byte out (>> n 24))
    (ssh-put-byte out (>> n 16))
    (ssh-put-byte out (>> n 8))
    (ssh-put-byte out n)))

; The bytes start..start+len of s, raw.
(def ssh-put-bytes
  (fn (_ out s start len)
    (%room! out len)
    (def p (%str->ptr (%oref out 1)))
    (def at (%oref out 2))
    ((fn (self i) (unless (= i len) (do (%pset1 p (+ at i) (%byte s (+ start i)) 1) (self (+ i 1))))) 0)
    (%oset! out 2 (+ at len))))

; A string: its count, then its bytes.
(def ssh-put-string
  (fn (_ out s start len)
    (ssh-put-uint32 out len)
    (ssh-put-bytes out s start len)))

; A text as a string: all of it, measured as text is.
(def ssh-put-text
  (fn (_ out t) (ssh-put-string out t 0 (Str8 length t))))

(def ssh-put-bool (fn (_ out b) (ssh-put-byte out (if b 1 0))))

; An mpint from an unsigned big-endian region: leading zeros dropped, a
; zero byte prefixed when the top bit is set, so the number stays positive.
(def ssh-put-mpint
  (fn (_ out s start len)
    (def first ((fn (self i) (if (if (< i len) (= (%byte s (+ start i)) 0) #f) (self (+ i 1)) i)) 0))
    (def n (- len first))
    (def lead (if (if (> n 0) (>= (%byte s (+ start first)) 128) #f) 1 0))
    (ssh-put-uint32 out (+ n lead))
    (when (= lead 1) (ssh-put-byte out 0))
    (ssh-put-bytes out s (+ start first) n)))

; A name-list: the names joined by commas, as a string.
(def ssh-put-names
  (fn (_ out names) (ssh-put-text out (Str8 join "," names))))

; What was written: (BUF . LEN), the buffer and how many of its bytes.
(def ssh-out-run
  (fn (_ out) (pair (%oref out 1) (%oref out 2))))

; --- reading ------------------------------------------------------------

(def ssh-in
  (fn (_ s start len)
    (def v (Vector make 3 0))
    (%oset! v 1 s)
    (%oset! v 2 start)
    (%oset! v 3 (+ start len))
    v))

(def %need
  (fn (_ in n)
    (when (> (+ (%oref in 2) n) (%oref in 3))
      (Err raise 'value "ssh: a packet ends before its field does" ()))))

(def ssh-in-left (fn (_ in) (- (%oref in 3) (%oref in 2))))

(def ssh-get-byte
  (fn (_ in)
    (%need in 1)
    (def b (%byte (%oref in 1) (%oref in 2)))
    (%oset! in 2 (+ (%oref in 2) 1))
    b))

(def ssh-get-bool (fn (_ in) (not (= (ssh-get-byte in) 0))))

(def ssh-get-uint32
  (fn (_ in)
    (def a (ssh-get-byte in)) (def b (ssh-get-byte in))
    (def c (ssh-get-byte in)) (def d (ssh-get-byte in))
    (| (<< a 24) (| (<< b 16) (| (<< c 8) d)))))

; A string's region in the reader's buffer: (START . LEN), no copy.
(def ssh-get-string
  (fn (_ in)
    (def n (ssh-get-uint32 in))
    (%need in n)
    (def start (%oref in 2))
    (%oset! in 2 (+ start n))
    (pair start n)))

; A string copied out as its own bytes.
(def ssh-get-bytes
  (fn (_ in)
    (def r (ssh-get-string in))
    (ssh-copy (%oref in 1) (first r) (rest r))))

; A string as text: the same copy, for a name or a message.
(def ssh-get-text (fn (_ in) (ssh-get-bytes in)))

; The reader's buffer, for a region's bytes.
(def ssh-in-buf (fn (_ in) (%oref in 1)))

; A name-list's names.
(def ssh-get-names
  (fn (_ in)
    (def t (ssh-get-text in))
    (if (= (Str8 length t) 0) () (Str8 split "," t))))

; --- regions -------------------------------------------------------------

; A fresh string of the bytes start..start+len of s.
(def ssh-copy
  (fn (_ s start len)
    (def out (%make-str len))
    (def p (%str->ptr out))
    ((fn (self i) (unless (= i len) (do (%pset1 p i (%byte s (+ start i)) 1) (self (+ i 1))))) 0)
    out))

; The bytes of several (S START LEN) regions, joined.
(def ssh-join
  (fn (_ regions)
    (def out (ssh-out))
    ((fn (self rs)
       (unless (null? rs)
         (do (ssh-put-bytes out (first (first rs)) (first (rest (first rs))) (first (rest (rest (first rs)))))
             (self (rest rs))))) regions)
    (ssh-out-run out)))

(def ssh-same-bytes?
  (fn (_ x xs y ys n)
    ((fn (self i)
       (if (= i n) #t (if (= (%byte x (+ xs i)) (%byte y (+ ys i))) (self (+ i 1)) #f))) 0)))

(provide ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-bytes ssh-put-string ssh-put-text ssh-put-mpint ssh-put-names ssh-out-run
  ssh-in ssh-in-left ssh-in-buf ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-bytes ssh-get-text ssh-get-names
  ssh-copy ssh-join ssh-same-bytes?)
