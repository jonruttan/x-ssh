; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/scp.x -- scp: files copied over the ssh program's pipes
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; Dropbear's scp is OpenSSH's classic one, and so is this: the client
; runs `PROGRAM [-p PORT] [-i KEY] [-l USER] HOST "scp -t PATH"` (or -f to
; fetch), PROGRAM the ssh client (-S, default ssh), and speaks the scp
; protocol over its pipes with the scp at the far end.  The protocol, a
; file at a time: the sink says it is ready with a zero byte; the source
; sends `C<mode> <size> <name>\n`, the sink answers zero, the source sends
; the bytes and a zero, the sink answers zero.  A one byte and a line is
; an error the other end carries on after, a two byte and a line one it
; stops at.  `T<mtime> 0 <atime> 0\n` before a file carries its times
; under -p, and is acknowledged.  Files only, so far: a directory is
; refused, -r included.
;
; As the remote end (-t, -f) the protocol is on this process's standard
; input, which the platform keeps on fd 3, and its standard output.

(module ssh/scp)

(import x/sys/file)
(import x/sys/posix)
(import x/sys/gc)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset1 (prim-ref (lit ptr) (lit set!)))
(def %cvt (prim-ref (lit convert) (lit to)))

(def %num (fn (_ n radix) (%cvt n (Type named STRING) radix)))
(def %int (fn (_ t radix) (%cvt t (Type named INTEGER) radix)))

(def %say (fn (_ text) (File write 2 text (%byte-len text))))

(def %chunk 16384)

; --- the pipes ----------------------------------------------------------------

(def %write-all
  (fn (self fd s start n)
    (when (> n 0)
      (do (def w (File write fd (if (= start 0) s (%tail s start n)) n))
          (when (< w 1) (Err raise 'io "scp: lost connection" ()))
          (when (< w n) (self fd s (+ start w) (- n w)))))))

; Bytes start.. of s as a fresh string of n.
(def %tail
  (fn (_ s start n)
    (def out (%make-str n))
    (def p (%str->ptr out))
    ((fn (self i) (unless (= i n) (do (%pset1 p i (%char->int (%byte-ref s (+ start i))) 1) (self (+ i 1))))) 0)
    out))

(def %send-text (fn (_ fd t) (%write-all fd t 0 (%byte-len t))))

(def %send-byte
  (fn (_ fd b)
    (def s (%make-str 1))
    (%pset1 (%str->ptr s) 0 b 1)
    (%write-all fd s 0 1)))

; One byte, or () at end of input.
(def %read-byte
  (fn (_ fd)
    (def s (%make-str 1))
    (if (< (File read fd s 1) 1) () (%char->int (%byte-ref s 0)))))

; A line without its newline, or () at end of input.
(def %read-line
  (fn (_ fd first)
    ((fn (self acc)
       (def b (%read-byte fd))
       (match ((null? b) (if (null? acc) () (%bytes->str (List reverse acc))))
              ((= b 10) (%bytes->str (List reverse acc)))
              (#t (self (pair b acc)))))
     (if (null? first) () (list first)))))

(def %bytes->str
  (fn (_ bs)
    (def s (%make-str (List length bs)))
    (def p (%str->ptr s))
    ((fn (self i xs) (unless (null? xs) (do (%pset1 p i (first xs) 1) (self (+ i 1) (rest xs))))) 0 bs)
    s))

; The far end's answer: #t for zero, or its message said and #f; a fatal
; one or a lost connection raises.
(def %response
  (fn (_ in)
    (def b (%read-byte in))
    (match ((null? b) (Err raise 'io "scp: lost connection" ()))
           ((= b 0) #t)
           (#t (do (def line (%read-line in (if (if (= b 1) #t (= b 2)) () b)))
                   (%say (Str8 append (if (null? line) "" line) "\n"))
                   (when (= b 2) (Err raise 'io "scp: the far end stopped" ()))
                   #f)))))

; A one byte and a message to the far end, and the message said here.
(def %error-to
  (fn (_ out text)
    (%send-byte out 1)
    (%send-text out (Str8 append "scp: " text "\n"))
    (%say (Str8 append "scp: " text "\n"))))

; n bytes copied from one descriptor to another; answers whether all came.
; Each chunk's buffer is garbage once written, so a collect follows it, as
; the session loop collects every chunk it moves.
(def %copy
  (fn (self from to n)
    (if (= n 0) #t
      (do (def k (if (< n %chunk) n %chunk))
          (def buf (%make-str k))
          (def got (File read from buf k))
          (if (< got 1) #f
            (do (%write-all to buf 0 got)
                (Heap collect)
                (self from to (- n got))))))))

; --- the source: files sent -------------------------------------------------

(def %basename
  (fn (_ path)
    (def parts (List filter (fn (_ p) (> (Str8 length p) 0)) (Str8 split "/" path)))
    (if (null? parts) path (List ref (- (List length parts) 1) parts))))

(def %stat-get (fn (_ st k) (rest (List find (fn (_ p) (eq? (first p) k)) st))))

; Each file sent, as the protocol has it; answers how many failed.
(def %source
  (fn (_ in out files preserve)
    ((fn (self fs errs)
       (if (null? fs) errs
         (do (def path (first fs))
             (def st (guard (e ()) (File stat path)))
             (match
               ((null? st) (do (%error-to out (Str8 append path ": No such file or directory")) (self (rest fs) (+ errs 1))))
               ((not (eq? (%stat-get st (lit file-type)) (lit file)))
                 (do (%error-to out (Str8 append path ": not a regular file")) (self (rest fs) (+ errs 1))))
               (#t
                 (do (def size (%stat-get st (lit size)))
                     (def mode (& (%stat-get st (lit mode)) 4095))
                     (when preserve
                       (do (def t (%num (%stat-get st (lit mtime)) 10))
                           (%send-text out (Str8 append "T" t " 0 " t " 0\n"))
                           (%response in)))
                     (%send-text out (Str8 append "C" (Str pad-left 4 #\0 (%num mode 8)) " " (%num size 10) " " (%basename path) "\n"))
                     (if (not (%response in)) (self (rest fs) (+ errs 1))
                       (do (def fd (File open path (lit rdonly)))
                           (def ok (%copy fd out size))
                           (File close fd)
                           (%send-byte out (if ok 0 1))
                           (self (rest fs) (if (if ok (%response in) #f) errs (+ errs 1)))))))))))
     files 0)))

; --- the sink: files received -------------------------------------------------

(def %dir? (fn (_ path) (guard (e #f) (eq? (%stat-get (File stat path) (lit file-type)) (lit dir)))))

; Files received into target until the source ends; answers how many failed.
(def %sink
  (fn (_ in out target)
    (def into-dir (%dir? target))
    (%send-byte out 0)
    ((fn (self errs)
       (def b (%read-byte in))
       (match
         ((null? b) errs)
         ((if (= b 1) #t (= b 2))
           (do (def m (%read-line in ()))
               (%say (Str8 append (if (null? m) "" m) "\n"))
               (if (= b 2) (+ errs 1) (self (+ errs 1)))))
         ((= b (%char->int #\T)) (do (%read-line in b) (%send-byte out 0) (self errs)))
         ((= b (%char->int #\C))
           (do (def line (%read-line in ()))
               (def ws (Str8 split " " line))
               (def mode (%int (first ws) 8))
               (def size (%int (List ref 1 ws) 10))
               (def name (Str8 join " " (rest (rest ws))))
               (def path (if into-dir (Str8 append target "/" name) target))
               (def fd (File open path (list (lit wronly) (lit creat) (lit trunc)) mode))
               (if (< fd 0)
                 (do (%error-to out (Str8 append path ": cannot create")) (self (+ errs 1)))
                 (do (%send-byte out 0)
                     (def ok (%copy in fd size))
                     (File close fd)
                     (def end (%read-byte in))
                     (%send-byte out 0)
                     (self (if (if ok (eq? end 0) #f) errs (+ errs 1)))))))
         (#t
           (do (%read-line in b)
               (%send-byte out 2)
               (%send-text out "scp: directories are not served yet\n")
               (%say "scp: directories are not served yet\n")
               (+ errs 1)))))
     0)))

; --- the client: the ssh program spawned on two pipes -------------------------

; [user@]host:path, or () for a local path.
(def %remote
  (fn (_ arg)
    (def colon ((fn (self i) (if (= i (Str8 length arg)) ()
                              (match ((= (%char->int (%byte-ref arg i)) 58) i)
                                     ((= (%char->int (%byte-ref arg i)) 47) ())
                                     (#t (self (+ i 1)))))) 0))
    (if (if (null? colon) #t (= colon 0)) ()
      (do (def hostpart (Str8 sub 0 colon arg))
          (def path (Str8 sub (+ colon 1) (- (Str8 length arg) colon 1) arg))
          (def at ((fn (self i) (if (< i 0) () (if (= (%char->int (%byte-ref hostpart i)) 64) i (self (- i 1)))))
                   (- (Str8 length hostpart) 1)))
          (list (if (null? at) () (Str8 sub 0 at hostpart))
                (if (null? at) hostpart (Str8 sub (+ at 1) (- (Str8 length hostpart) at 1) hostpart))
                (if (= (Str8 length path) 0) "." path))))))

; The shell's quoting of a path for the remote command.
(def %quote
  (fn (_ s) (Str8 append "'" (Str8 join "'\\''" (Str8 split "'" s)) "'")))

; PROGRAM run with its stdin and stdout on pipes: (PID TO FROM), TO the
; end we write, FROM the end we read.
(def %spawn
  (fn (_ argv)
    (def a (Sys pipe)) (def b (Sys pipe))
    (def pid (Sys fork))
    (when (= pid 0)
      (Sys dup2 (first a) 0) (Sys dup2 (rest b) 1)
      (List for-each (fn (_ fd) (Sys close fd)) (list (first a) (rest a) (first b) (rest b)))
      (Sys exec (first argv) (rest argv))
      (Sys exit 127))
    (Sys close (first a)) (Sys close (rest b))
    (list pid (rest a) (first b))))

(def %program-argv
  (fn (_ program port key user host command)
    (List append (list program)
      (if (null? port) () (list "-p" port))
      (if (null? key) () (list "-i" key))
      (if (null? user) () (list "-l" user))
      (list host command))))

; The copy a client line asks for; answers the exit status.
(def ssh-scp-client
  (fn (_ operands program port key preserve)
    (def target (List ref (- (List length operands) 1) operands))
    (def sources (List take (- (List length operands) 1) operands))
    (def t (%remote target))
    (def flags (Str8 append (if preserve " -p" "") (if (> (List length sources) 1) " -d" "")))
    (match
      ((not (null? t))
        (if (List any? (fn (_ s) (not (null? (%remote s)))) sources)
          (do (%say "scp: copies between two remote hosts are not served yet\n") 1)
          (do (def kid (%spawn (%program-argv program port key (first t) (List ref 1 t)
                                (Str8 append "scp" flags " -t " (%quote (List ref 2 t))))))
              (def errs (guard (e 1)
                          (if (%response (List ref 2 kid)) (%source (List ref 2 kid) (List ref 1 kid) sources preserve) 1)))
              (Sys close (List ref 1 kid)) (Sys close (List ref 2 kid))
              (def status (Sys wait (first kid)))
              (if (if (= errs 0) (= status 0) #f) 0 1))))
      ((not (= (List length sources) 1))
        (do (%say "scp: one remote source at a time, so far\n") 1))
      (#t
        (do (def s (%remote (first sources)))
            (if (null? s)
              (do (%say "scp: a local copy is cp's\n") 1)
              (do (def kid (%spawn (%program-argv program port key (first s) (List ref 1 s)
                                    (Str8 append "scp" flags " -f " (%quote (List ref 2 s))))))
                  (def errs (guard (e 1) (%sink (List ref 2 kid) (List ref 1 kid) target)))
                  (Sys close (List ref 1 kid)) (Sys close (List ref 2 kid))
                  (def status (Sys wait (first kid)))
                  (if (if (= errs 0) (= status 0) #f) 0 1))))))))

; The remote ends: -t receives into the target, -f sends the files.
(def ssh-scp-remote
  (fn (_ to? operands preserve)
    (def errs
      (guard (e 1)
        (if to?
          (%sink 3 1 (first operands))
          (if (%response 3) (%source 3 1 operands preserve) 1))))
    (if (= errs 0) 0 1)))

(provide ssh/scp ssh-scp-client ssh-scp-remote)
