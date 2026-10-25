; # x-ssh -- SSH on x-lang
;
; ## ssh/sftp-client.x -- sftp, the client
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; OpenSSH's sftp: the ssh program (-S, default ssh) is run with `-s HOST
; sftp` (or -s's subsystem), or -D's command is run in its place, and its
; pipes speak SFTP version 3 to the server.  Commands are read from the
; terminal at an "sftp> " prompt, or from -b's file, each echoed, where a
; failure ends the batch unless its line starts with "-".  A path is the
; remote working directory's when relative, as the client makes it; a
; remote name with *, ? or [ in its last part is matched against the
; directory's names.  A transfer keeps -R's requests of -B's bytes in
; flight.

(module ssh/sftp-client)

(import x/sys/file)
(import x/sys/posix)
(import x/sys/gc)
(import x/sys/date Date)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-put-bytes ssh-put-string ssh-put-text ssh-out-run
  ssh-in ssh-in-left ssh-in-buf ssh-get-byte ssh-get-uint32 ssh-get-string ssh-get-text ssh-copy)
(import ssh/sftp ssh-sftp-reader ssh-sftp-take! ssh-sftp-write-all ssh-sftp-put-u64 ssh-sftp-get-u64
  ssh-sftp-get-attrs ssh-sftp-mode-text)

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %cvt (prim-ref (lit convert) (lit to)))

(def %ref (fn (_ v i) (%oref v (+ i 1))))
(def %set (fn (_ v i x) (%oset! v (+ i 1) x)))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))
(def %int (fn (_ t radix) (guard (e ()) (%cvt t (Type named INTEGER) radix))))
(def %min (fn (_ a b) (if (< a b) a b)))
(def %say (fn (_ fd t) (File write fd t (%byte-len t))))
(def %out (fn (_ t) (%say 1 t)))
(def %err (fn (_ t) (%say 2 t)))
(def %char (fn (_ s i) (%char->int (%byte-ref s i))))

(def %stdin 3)

; --- the protocol's numbers --------------------------------------------------

(def %INIT 1) (def %VERSION 2) (def %OPEN 3) (def %CLOSE 4) (def %READ 5) (def %WRITE 6)
(def %LSTAT 7) (def %FSTAT 8) (def %SETSTAT 9) (def %FSETSTAT 10) (def %OPENDIR 11)
(def %READDIR 12) (def %REMOVE 13) (def %MKDIR 14) (def %RMDIR 15) (def %REALPATH 16)
(def %STAT 17) (def %RENAME 18) (def %READLINK 19) (def %SYMLINK 20)
(def %STATUS 101) (def %HANDLE 102) (def %DATA 103) (def %NAME 104) (def %ATTRS 105)
(def %EXTENDED 200) (def %EXTENDED-REPLY 201)

(def %OK 0) (def %EOF 1)

(def %A-SIZE 1) (def %A-UIDGID 2) (def %A-PERMISSIONS 4) (def %A-ACMODTIME 8)

(def %F-READ 1) (def %F-WRITE 2) (def %F-CREAT 8) (def %F-TRUNC 16)

(def %texts
  (list "Success" "End of file" "No such file or directory" "Permission denied" "Failure"
        "Bad message" "No connection" "Connection lost" "Operation unsupported"))

; --- the connection ------------------------------------------------------------
;
; (READER OUT-FD NEXT-ID CWD EXTENSIONS BUFFER REQUESTS PID QUIET USERS
; GROUPS): the server's
; output read through READER, requests written to OUT-FD; CWD the remote
; working directory, absolute; QUIET for a batch or -q, where what is
; fetched or changed is not said; USERS and GROUPS the names the server
; gave ids, alists.
(def %connection
  (fn (_ in out buffer requests pid)
    (def c (Vector make 11 ()))
    (%set c 0 (ssh-sftp-reader in)) (%set c 1 out) (%set c 2 1)
    (%set c 5 buffer) (%set c 6 requests) (%set c 7 pid)
    c))

; A failed request: an Err whose message is the server's status, read as
; OpenSSH's sftp reads it.
(def %info (fn (_ c t) (unless (%ref c 8) (%out t))))

(def %fail (fn (_ code) (Err raise 'sftp (List ref (%min code 8) %texts) (list (pair (lit code) code)))))
(def %lost (fn (_) (Err raise 'sftp "Connection closed" (list (pair (lit code) 7)))))

(def %send!
  (fn (_ c body)
    (def run (ssh-out-run body))
    (def f (ssh-out))
    (ssh-put-uint32 f (rest run))
    (ssh-put-bytes f (first run) 0 (rest run))
    (def all (ssh-out-run f))
    (guard (e (%lost)) (ssh-sftp-write-all (%ref c 1) (first all) 0 (rest all)))))

; A request begun: (OUT . ID).
(def %request
  (fn (_ c type)
    (def id (%ref c 2))
    (%set c 2 (+ id 1))
    (def out (ssh-out))
    (ssh-put-byte out type)
    (ssh-put-uint32 out id)
    (pair out id)))

; The next reply: (TYPE ID IN).
(def %reply
  (fn (_ c)
    (def r (%ref c 0))
    (def head (ssh-sftp-take! r 4))
    (when (null? head) (%lost))
    (def len (ssh-get-uint32 (ssh-in head 0 4)))
    (def body (ssh-sftp-take! r len))
    (when (null? body) (%lost))
    (def in (ssh-in body 0 len))
    (def type (ssh-get-byte in))
    (list type (ssh-get-uint32 in) in)))

; One request sent and its reply read: (TYPE . IN).  A status other than
; OK raises, unless it is what want names.
(def %call!
  (fn (_ c req want)
    (%send! c (first req))
    (def r (%reply c))
    (unless (= (List ref 1 r) (rest req)) (Err raise 'sftp "Reply for a request not asked" ()))
    (def type (first r)) (def in (List ref 2 r))
    (when (if (= type %STATUS) (not (= type want)) #f)
      (do (def code (ssh-get-uint32 in))
          (unless (= code %OK) (%fail code))))
    (pair type in)))

(def %status-call!
  (fn (_ c req)
    (def r (%call! c req %STATUS))
    (when (= (first r) %STATUS)
      (do (def code (ssh-get-uint32 (rest r)))
          (unless (= code %OK) (%fail code))))
    ()))

(def %put-u64 ssh-sftp-put-u64)
(def %get-u64 ssh-sftp-get-u64)

; Attributes to send, from an alist of what is to be set.
(def %put-attrs
  (fn (_ out a)
    (def get (fn (_ k) (def p (List find (fn (_ p) (eq? (first p) k)) a)) (if (null? p) () (rest p))))
    (def flags (| (if (null? (get (lit size))) 0 %A-SIZE)
                  (| (if (null? (get (lit uid))) 0 %A-UIDGID)
                     (| (if (null? (get (lit perm))) 0 %A-PERMISSIONS)
                        (if (null? (get (lit mtime))) 0 %A-ACMODTIME)))))
    (ssh-put-uint32 out flags)
    (unless (null? (get (lit size))) (%put-u64 out (get (lit size))))
    (unless (null? (get (lit uid))) (do (ssh-put-uint32 out (get (lit uid))) (ssh-put-uint32 out (get (lit gid)))))
    (unless (null? (get (lit perm))) (ssh-put-uint32 out (get (lit perm))))
    (unless (null? (get (lit mtime))) (do (ssh-put-uint32 out (get (lit atime))) (ssh-put-uint32 out (get (lit mtime)))))))

(def %attr (fn (_ a k) (def p (List find (fn (_ p) (eq? (first p) k)) a)) (if (null? p) () (rest p))))

; --- the requests --------------------------------------------------------------

(def %path-call!
  (fn (_ c type path)
    (def req (%request c type))
    (ssh-put-text (first req) path)
    req))

(def %stat
  (fn (_ c path)
    (def r (%call! c (%path-call! c %STAT path) ()))
    (ssh-sftp-get-attrs (rest r))))

(def %lstat
  (fn (_ c path)
    (def r (%call! c (%path-call! c %LSTAT path) ()))
    (ssh-sftp-get-attrs (rest r))))

(def %stat? (fn (_ c path) (guard (e ()) (%stat c path))))

(def %names
  (fn (_ in)
    ((fn (self n acc)
       (if (= n 0) (List reverse acc)
         (do (def name (ssh-get-text in))
             (def long (ssh-get-text in))
             (def a (ssh-sftp-get-attrs in))
             (self (- n 1) (pair (list name long a) acc)))))
     (ssh-get-uint32 in) ())))

(def %realpath
  (fn (_ c path)
    (def r (%call! c (%path-call! c %REALPATH path) ()))
    (first (first (%names (rest r))))))

; A handle is bytes, NULs among them as OpenSSH makes them: (BYTES . LEN).
(def %handle-of
  (fn (_ r) (def in (rest r)) (def s (ssh-get-string in)) (pair (ssh-copy (ssh-in-buf in) (first s) (rest s)) (rest s))))
(def %put-handle (fn (_ out h) (ssh-put-string out (first h) 0 (rest h))))

(def %open
  (fn (_ c path pflags a)
    (def req (%path-call! c %OPEN path))
    (ssh-put-uint32 (first req) pflags)
    (%put-attrs (first req) a)
    (%handle-of (%call! c req ()))))

(def %close
  (fn (_ c h)
    (def req (%request c %CLOSE))
    (%put-handle (first req) h)
    (%status-call! c req)))

; A directory's names, each (NAME LONGNAME ATTRS).
(def %readdir
  (fn (_ c path)
    (def h (%handle-of (%call! c (%path-call! c %OPENDIR path) ())))
    (def all
      ((fn (self acc)
         (def req (%request c %READDIR))
         (%put-handle (first req) h)
         (%send! c (first req))
         (def r (%reply c))
         (def in (List ref 2 r))
         (if (= (first r) %STATUS)
           (do (def code (ssh-get-uint32 in))
               (if (= code %EOF) acc (do (guard (e ()) (%close c h)) (%fail code))))
           (self (List append acc (%names in)))))
       ()))
    (%close c h)
    all))

(def %setstat
  (fn (_ c path a)
    (def req (%path-call! c %SETSTAT path))
    (%put-attrs (first req) a)
    (%status-call! c req)))

(def %extension? (fn (_ c name) (not (null? (List find (fn (_ p) (str=? (first p) name)) (%ref c 4))))))

(def %two-paths!
  (fn (_ c req a b)
    (ssh-put-text (first req) a)
    (ssh-put-text (first req) b)
    (%status-call! c req)))

(def %extended
  (fn (_ c name)
    (def req (%request c %EXTENDED))
    (ssh-put-text (first req) name)
    req))

; --- paths ---------------------------------------------------------------------

(def %absolute? (fn (_ p) (if (> (Str8 length p) 0) (= (%char p 0) 47) #f)))

; A remote path made absolute against the working directory.
(def %remote-path
  (fn (_ c p)
    (match
      ((%absolute? p) p)
      ; scp's connection has no cwd: a path goes as given, the server's
      ; own directory the empty one's
      ((null? (%ref c 3)) (if (str=? p "") "." p))
      ((str=? p "") (%ref c 3))
      ((str=? (%ref c 3) "/") (Str8 append "/" p))
      (#t (Str8 append (%ref c 3) "/" p)))))

(def %base
  (fn (_ p)
    (def n (Str8 length p))
    (def stripped ((fn (self k) (if (if (> k 1) (= (%char p (- k 1)) 47) #f) (self (- k 1)) k)) n))
    (def cut ((fn (self i) (if (< i 0) () (if (= (%char p i) 47) i (self (- i 1))))) (- stripped 1)))
    (if (null? cut) (Str8 sub 0 stripped p) (Str8 sub (+ cut 1) (- stripped cut 1) p))))

(def %dir-part
  (fn (_ p)
    (def cut ((fn (self i) (if (< i 0) () (if (= (%char p i) 47) i (self (- i 1))))) (- (Str8 length p) 1)))
    (match ((null? cut) ".") ((= cut 0) "/") (#t (Str8 sub 0 cut p)))))

(def %slash? (fn (_ p) (if (> (Str8 length p) 0) (= (%char p (- (Str8 length p) 1)) 47) #f)))
(def %join (fn (_ d n) (if (%slash? d) (Str8 append d n) (Str8 append d "/" n))))

; A shell pattern's match: * any run, ? any one, [...] one of a set.
(def %match?
  (fn (self pat pi s si)
    (def pn (Str8 length pat)) (def sn (Str8 length s))
    (match
      ((= pi pn) (= si sn))
      ((= (%char pat pi) 42)
        (if (self pat (+ pi 1) s si) #t (if (< si sn) (self pat pi s (+ si 1)) #f)))
      ((= si sn) #f)
      ((= (%char pat pi) 63) (self pat (+ pi 1) s (+ si 1)))
      ((= (%char pat pi) 91)
        (do (def close ((fn (loop k) (match ((>= k pn) ()) ((= (%char pat k) 93) k) (#t (loop (+ k 1))))) (+ pi 2)))
            (if (null? close)
              (if (= (%char s si) 91) (self pat (+ pi 1) s (+ si 1)) #f)
              (do (def neg (if (= (%char pat (+ pi 1)) 33) #t (= (%char pat (+ pi 1)) 94)))
                  (def from (if neg (+ pi 2) (+ pi 1)))
                  (def ch (%char s si))
                  (def hit ((fn (loop k)
                              (match ((>= k close) #f)
                                     ((if (< (+ k 2) close) (= (%char pat (+ k 1)) 45) #f)
                                       (if (if (>= ch (%char pat k)) (<= ch (%char pat (+ k 2))) #f) #t (loop (+ k 3))))
                                     ((= (%char pat k) ch) #t)
                                     (#t (loop (+ k 1)))))
                            from))
                  (if (if neg (not hit) hit) (self pat (+ close 1) s (+ si 1)) #f)))))
      (#t (if (= (%char pat pi) (%char s si)) (self pat (+ pi 1) s (+ si 1)) #f)))))

(def %pattern?
  (fn (_ p) (List any? (fn (_ c) (not (null? (Str8 index-of c p)))) (list "*" "?" "["))))

; The remote paths a name stands for: itself, or the names in its
; directory its last part matches, dot files only when the pattern starts
; with a dot.  () when a pattern matches nothing.
(def %remote-glob
  (fn (_ c p)
    (def path (%remote-path c p))
    (if (not (%pattern? (%base path))) (list path)
      (do (def dir (%dir-part path))
          (def pat (%base path))
          (List map (fn (_ n) (%join dir n))
            (List sort (fn (_ a b) (Str8 <? a b))
              (List filter (fn (_ n) (if (str=? n ".") #f (if (str=? n "..") #f
                                       (if (if (= (%char n 0) 46) (not (= (%char pat 0) 46)) #f) #f
                                         (%match? pat 0 n 0)))))
                (List map first (%readdir c dir)))))))))

(def %local-glob
  (fn (_ p)
    (if (not (%pattern? (%base p))) (list p)
      (do (def dir (%dir-part p))
          (def pat (%base p))
          (def names (guard (e ()) (File list-dir dir)))
          (List map (fn (_ n) (if (str=? dir ".") (if (= (%char p 0) 46) (%join dir n) n) (%join dir n)))
            (List sort (fn (_ a b) (Str8 <? a b))
              (List filter (fn (_ n) (if (if (= (%char n 0) 46) (not (= (%char pat 0) 46)) #f) #f (%match? pat 0 n 0)))
                names)))))))

; --- transfers -----------------------------------------------------------------

(def %dir? (fn (_ a) (= (& (%attr a (lit perm)) 61440) 16384)))
(def %regular? (fn (_ a) (= (& (%attr a (lit perm)) 61440) 32768)))

; A remote file into a local one, -R's reads of -B's bytes in flight: each
; reply written where its read began; a short read asks again for the
; rest; an end of file stops new reads.
; A failed call's reason, as strerror says it: errno is read before
; anything else can change it.
(def %errno-text
  (fn (_ r op)
    (def m (guard (x "Failure") ((Err from-errno (Err errno-of r) op ()) msg)))
    (def cut (Str8 index-of ": " m))
    (if (null? cut) m (Str8 sub (+ cut 2) (- (Str8 length m) cut 2) m))))

; A local file that would not open: the sftp's message, and its reason
; as (local . REASON) for scp's.
(def %local-fail
  (fn (_ text why) (Err raise 'sftp (Str8 append text why) (list (pair (lit local) why)))))

; An open remote file read to its end, -R's reads of -B's bytes in
; flight, each block handed to write! as (OFFSET BUF START LEN), in
; whatever order the replies come; answers the failure, or ().
(def %read-all!
  (fn (_ c h write!)
    (def chunk (%ref c 5))
    (def most (%ref c 6))
    ; in flight: an alist of id to (OFFSET . LEN)
    (def state (Vector make 3 ()))
    (%set state 0 0) (%set state 1 ()) (%set state 2 #f)
    (def ask!
      (fn (_ offset len)
        (def req (%request c %READ))
        (%put-handle (first req) h)
        (%put-u64 (first req) offset)
        (ssh-put-uint32 (first req) len)
        (%send! c (first req))
        (%set state 1 (pair (pair (rest req) (pair offset len)) (%ref state 1)))))
    (def failure
      (guard (e e)
        ((fn (self)
           ; more asked while there is room and no end seen
           ((fn (fill) (when (if (not (%ref state 2)) (< (List length (%ref state 1)) most) #f)
                         (do (ask! (%ref state 0) chunk) (%set state 0 (+ (%ref state 0) chunk)) (fill))))
            )
           (unless (null? (%ref state 1))
             (do (def r (%reply c))
                 (def id (List ref 1 r)) (def in (List ref 2 r))
                 (def at (List find (fn (_ p) (= (first p) id)) (%ref state 1)))
                 (when (null? at) (Err raise 'sftp "Reply for a request not asked" ()))
                 (%set state 1 (List filter (fn (_ p) (not (= (first p) id))) (%ref state 1)))
                 (def offset (first (rest at))) (def len (rest (rest at)))
                 (match
                   ((= (first r) %DATA)
                     (do (def d (ssh-get-string in))
                         (write! offset (ssh-in-buf in) (first d) (rest d))
                         (when (< (rest d) len) (ask! (+ offset (rest d)) (- len (rest d))))))
                   ((= (first r) %STATUS)
                     (do (def code (ssh-get-uint32 in))
                         (if (= code %EOF) (%set state 2 #t) (%fail code))))
                   (#t (Err raise 'sftp "Unexpected reply to a read" ())))
                 (when (= (& id 31) 0) (Heap collect))
                 (self)))))
        ()))
    failure))

(def %download!
  (fn (_ c remote local a preserve)
    (def perm (if (null? (%attr a (lit perm))) 438 (& (%attr a (lit perm)) 511)))
    (def h (%open c remote %F-READ ()))
    (def fd (File open local (list (lit wronly) (lit creat) (lit trunc)) perm))
    (when (< fd 0) (def why (%errno-text fd (lit open)))
      (do (guard (e ()) (%close c h))
          (%local-fail (Str8 append "Couldn't open local file \"" local "\" for writing: ") why)))
    (def failure
      (%read-all! c h (fn (_ offset buf start len)
                        (File seek fd offset)
                        (ssh-sftp-write-all fd (ssh-copy buf start len) 0 len))))
    (File close fd)
    (guard (e ()) (%close c h))
    (unless (null? failure) (error failure))
    (when preserve
      (unless (null? (%attr a (lit mtime))) (guard (e ()) (File set-times local (%attr a (lit atime)) (%attr a (lit mtime)))))
      (guard (e ()) (File chmod local perm)))))

; A remote file of one server written into another's, the reads in
; flight as a download keeps them, each block written as it comes;
; -p's times and permissions set after.  A source that will not open
; raises with (from . #t) in its data, for scp's words.
(def %crossload!
  (fn (_ c from-c from to a preserve)
    (def perm (if (null? (%attr a (lit perm))) 438 (& (%attr a (lit perm)) 511)))
    (def h (guard (e (Err raise 'sftp (%message e) (list (pair (lit from) #t)))) (%open from-c from %F-READ ())))
    (def out (guard (e (do (guard (x ()) (%close from-c h)) (error e)))
               (%open c to (| %F-WRITE (| %F-CREAT %F-TRUNC)) (list (pair (lit perm) perm)))))
    (def failure
      (%read-all! from-c h (fn (_ offset buf start len)
                             (def req (%request c %WRITE))
                             (%put-handle (first req) out)
                             (%put-u64 (first req) offset)
                             (ssh-put-string (first req) buf start len)
                             (%status-call! c req))))
    (guard (e ()) (%close from-c h))
    (guard (e ()) (%close c out))
    (unless (null? failure) (error failure))
    (when preserve
      (%setstat c to (List append (list (pair (lit perm) perm))
                       (if (null? (%attr a (lit mtime))) ()
                         (list (pair (lit atime) (%attr a (lit atime))) (pair (lit mtime) (%attr a (lit mtime))))))))))

; A local file into a remote one, -R's writes of -B's bytes in flight;
; -p's times (and permissions) set after.
(def %upload!
  (fn (_ c local remote preserve)
    (def s (File stat local))
    (def perm (& (Assoc get (lit mode) s) 511))
    (def fd (File open local (lit rdonly)))
    (when (< fd 0) (%local-fail (Str8 append "Couldn't open local file \"" local "\" for reading: ") (%errno-text fd (lit open))))
    (def h (guard (e (do (File close fd) (error e)))
             (%open c remote (| %F-WRITE (| %F-CREAT %F-TRUNC)) (list (pair (lit perm) perm)))))
    (def chunk (%ref c 5))
    (def most (%ref c 6))
    (def buf (%make-str chunk))
    (def state (Vector make 3 ()))
    (%set state 0 0) (%set state 1 0) (%set state 2 #f)
    (def failure
      (guard (e e)
        ((fn (self)
           ((fn (fill)
              (when (if (not (%ref state 2)) (< (%ref state 1) most) #f)
                (do (def n (File read fd buf chunk))
                    (if (< n 1) (%set state 2 #t)
                      (do (def req (%request c %WRITE))
                          (%put-handle (first req) h)
                          (%put-u64 (first req) (%ref state 0))
                          (ssh-put-string (first req) buf 0 n)
                          (%send! c (first req))
                          (%set state 0 (+ (%ref state 0) n))
                          (%set state 1 (+ (%ref state 1) 1))
                          (fill))))))
            )
           (when (> (%ref state 1) 0)
             (do (def r (%reply c))
                 (%set state 1 (- (%ref state 1) 1))
                 (def code (if (= (first r) %STATUS) (ssh-get-uint32 (List ref 2 r)) 4))
                 (unless (= code %OK) (%fail code))
                 (when (= (& (List ref 1 r) 31) 0) (Heap collect))
                 (self)))))
        ()))
    (File close fd)
    (guard (e ()) (%close c h))
    (unless (null? failure) (error failure))
    (when preserve
      (%setstat c remote (list (pair (lit perm) perm)
                               (pair (lit atime) (Assoc get (lit atime) s)) (pair (lit mtime) (Assoc get (lit mtime) s)))))))

; get: each remote name a pattern stands for, into local (a directory takes
; each by its own name); -r walks directories.
(def %get!
  (fn (self c remote local preserve recursive)
    (def a (%stat c remote))
    (match
      ((%dir? a)
        (if (not recursive)
          (Err raise 'sftp (Str8 append "Cannot download non-regular file: " remote) ())
          (do (%out (Str8 append "Retrieving " remote "\n"))
              (when (null? (File type local)) (File mkdir local (& (%attr a (lit perm)) 511)))
              (List for-each
                (fn (_ e)
                  (def n (first e))
                  (unless (if (str=? n ".") #t (str=? n ".."))
                    (do (def sub (List ref 2 e))
                        (if (if (%dir? sub) #t (%regular? sub))
                          (self c (%join remote n) (%join local n) preserve recursive)
                          (%err (Str8 append "download \"" (%join remote n) "\": not a regular file\n"))))))
                (%readdir c remote))
              (when preserve
                (guard (e ()) (File set-times local (%attr a (lit atime)) (%attr a (lit mtime))))))))
      ((not (%regular? a)) (Err raise 'sftp (Str8 append "Cannot download non-regular file: " remote) ()))
      (#t (do (%info c (Str8 append "Fetching " remote " to " local "\n"))
              (%download! c remote local a preserve))))))

(def %put!
  (fn (self c local remote preserve recursive)
    (def kind (File type local))
    (match
      ((null? kind) (Err raise 'sftp (Str8 append "stat " local ": No such file or directory") ()))
      ((eq? kind (lit dir))
        (if (not recursive)
          (Err raise 'sftp (Str8 append "Cannot upload non-regular file: " local) ())
          (do (%out (Str8 append "Entering " local "\n"))
              (def s (File stat local))
              (when (null? (%stat? c remote))
                (do (def req (%path-call! c %MKDIR remote))
                    (%put-attrs (first req) (list (pair (lit perm) (& (Assoc get (lit mode) s) 511))))
                    (%status-call! c req)))
              (List for-each
                (fn (_ n) (self c (%join local n) (%join remote n) preserve recursive))
                (List sort (fn (_ a b) (Str8 <? a b)) (File list-dir local)))
              (when preserve
                (%setstat c remote (list (pair (lit atime) (Assoc get (lit atime) s)) (pair (lit mtime) (Assoc get (lit mtime) s))))))))
      ((not (eq? kind (lit file))) (Err raise 'sftp (Str8 append "Cannot upload non-regular file: " local) ()))
      (#t (do (%info c (Str8 append "Uploading " local " to " remote "\n"))
              (%upload! c local remote preserve))))))

; --- ls and df -----------------------------------------------------------------

(def %pad-left
  (fn (_ t w) (def n (Str8 length t)) (if (>= n w) t (Str8 append (Str8 repeat (- w n) " ") t))))
(def %pad-right
  (fn (_ t w) (def n (Str8 length t)) (if (>= n w) t (Str8 append t (Str8 repeat (- w n) " ")))))

(def %months (list "Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"))

; The names the server gives ids, asked once each through
; users-groups-by-id@openssh.com: each list a string of uint32s, each
; answer a string of strings, an empty one for an id with no name.
(def %ids-named!
  (fn (_ c uids gids)
    (def fresh
      (fn (_ ids cache)
        (List fold (fn (_ acc i) (if (if (null? i) #t (if (List any? (fn (_ x) (= x i)) acc) #t
                                       (not (null? (List find (fn (_ p) (= (first p) i)) cache))))) acc (List append acc (list i))))
          () ids)))
    (def us (fresh uids (%ref c 9)))
    (def gs (fresh gids (%ref c 10)))
    (unless (if (null? us) (null? gs) #f)
      (do (def req (%extended c "users-groups-by-id@openssh.com"))
          (def pack (fn (_ ids) (def o (ssh-out)) (List for-each (fn (_ i) (ssh-put-uint32 o i)) ids) (ssh-out-run o)))
          (def pu (pack us)) (def pg (pack gs))
          (ssh-put-string (first req) (first pu) 0 (rest pu))
          (ssh-put-string (first req) (first pg) 0 (rest pg))
          (def in (rest (%call! c req ())))
          (def names
            (fn (_ ids)
              (def r (ssh-get-string in))
              (def sub (ssh-in (ssh-in-buf in) (first r) (rest r)))
              (List map (fn (_ i) (pair i (ssh-get-text sub))) ids)))
          (%set c 9 (List append (%ref c 9) (names us)))
          (%set c 10 (List append (%ref c 10) (names gs)))))))

(def %id-name
  (fn (_ cache id)
    (def p (List find (fn (_ p) (= (first p) id)) cache))
    (if (if (null? p) #t (= (Str8 length (rest p)) 0)) (%num id) (rest p))))

; ls -l's line, made here as OpenSSH's sftp makes it: the link count is
; not carried; the owner by the names the server gave, or its numbers.
(def %long-of
  (fn (_ c name a named)
    (def mtime (if (null? (%attr a (lit mtime))) 0 (%attr a (lit mtime))))
    (def d (Date local mtime))
    (def now (Sys now))
    (def two (fn (_ n) (%pad-left (%num n) 2)))
    (def zero (fn (_ n) (Str8 replace " " "0" (two n))))
    (def uid (if (null? (%attr a (lit uid))) 0 (%attr a (lit uid))))
    (def gid (if (null? (%attr a (lit gid))) 0 (%attr a (lit gid))))
    (Str8 append (ssh-sftp-mode-text (if (null? (%attr a (lit perm))) 0 (%attr a (lit perm)))) "    ? "
      (%pad-right (if named (%id-name (%ref c 9) uid) (%num uid)) 8) " "
      (%pad-right (if named (%id-name (%ref c 10) gid) (%num gid)) 8) " "
      (%pad-left (%num (if (null? (%attr a (lit size))) 0 (%attr a (lit size)))) 8) " "
      (List ref (- (Assoc get (lit month) d) 1) %months) " " (two (Assoc get (lit day) d)) " "
      (if (if (> mtime (- now 15768000)) (<= mtime now) #f)
        (Str8 append (zero (Assoc get (lit hour) d)) ":" (zero (Assoc get (lit minute) d)))
        (Str8 append " " (%num (Assoc get (lit year) d))))
      " " name)))

(def %width
  (fn (_) (def w (%int (guard (e "") (Sys getenv "COLUMNS")) 10)) (if (if (null? w) #t (< w 1)) 80 w)))

; The names in rows, as OpenSSH's sftp sets them: as many columns of the
; longest name and two as the width holds.
(def %columns!
  (fn (_ names)
    (unless (null? names)
      (do (def m (List fold (fn (_ acc n) (if (> (Str8 length n) acc) (Str8 length n) acc)) 0 names))
          (def cols ((fn (_ k) (if (< k 1) 1 k)) (/ (%width) (+ m 2))))
          (def space (/ (%width) cols))
          ((fn (self ns k)
             (unless (null? ns)
               (do (%out (if (= k cols) (Str8 append (first ns) "\n") (%pad-right (first ns) space)))
                   (self (rest ns) (if (= k cols) 1 (+ k 1))))))
           names 1)
          (unless (= 0 (% (List length names) cols)) (%out "\n"))))))

; ls [-1alrSt] [path]: a directory's names, or the names a pattern stands
; for; dot files under -a; by name, -t time, -S size, -r reversed.
(def %ls!
  (fn (_ c flags paths)
    (def on? (fn (_ f) (not (null? (Str8 index-of f flags)))))
    (def order
      (fn (_ entries)
        (def by (match
                  ((on? "f") ())
                  ((on? "t") (fn (_ a b) (> (%attr (List ref 2 a) (lit mtime)) (%attr (List ref 2 b) (lit mtime)))))
                  ((on? "S") (fn (_ a b) (> (%attr (List ref 2 a) (lit size)) (%attr (List ref 2 b) (lit size)))))
                  (#t (fn (_ a b) (Str8 <? (first a) (first b))))))
        (def sorted (if (null? by) entries (List sort by entries)))
        (if (on? "r") (List reverse sorted) sorted)))
    (def show
      (fn (_ entries)
        (if (if (on? "l") #t (on? "n"))
          ; formatted here, owners by the names the server gives their
          ; ids, as OpenSSH's sftp does where users-groups-by-id is served;
          ; else the server's own line, or the numbers under -n
          (do (def named (if (on? "n") #f (%extension? c "users-groups-by-id@openssh.com")))
              (when named
                (%ids-named! c (List map (fn (_ e) (%attr (List ref 2 e) (lit uid))) entries)
                               (List map (fn (_ e) (%attr (List ref 2 e) (lit gid))) entries)))
              (List for-each
                (fn (_ e) (%out (Str8 append (if (if named #t (if (on? "n") #t (null? (List ref 1 e))))
                                               (%long-of c (first e) (List ref 2 e) named)
                                               (List ref 1 e)) "\n")))
                entries))
          (if (on? "1")
            (List for-each (fn (_ e) (%out (Str8 append (first e) "\n"))) entries)
            (%columns! (List map first entries))))))
    (def target (if (null? paths) (%ref c 3) (first paths)))
    (def full (%remote-path c target))
    (def a (if (%pattern? (%base full)) () (%stat c full)))
    ; a directory: each name under the path it was given as, or bare
    (def listing
      (fn (_ dir given)
        (show (order (List map (fn (_ e) (if (null? given) e (pair (%join given (first e)) (rest e))))
                       (List filter (fn (_ e) (if (on? "a") #t (not (= (%char (first e) 0) 46)))) (%readdir c dir)))))))
    (def shown-as
      (fn (_ p)
        (match
          ((null? paths) (%base p))
          ((%absolute? (first paths)) p)
          ((not (%pattern? (%base target))) target)
          ((null? (Str8 index-of "/" target)) (%base p))
          (#t (%join (%dir-part target) (%base p))))))
    (if (if (null? a) #f (%dir? a))
      (listing full (if (null? paths) () (first paths)))
      (do (def names (%remote-glob c target))
          (when (null? names) (Err raise 'sftp (Str8 append "Can't ls: \"" full "\" not found") ()))
          (def one (if (null? (rest names)) (%stat? c (first names)) ()))
          ; a pattern matching one directory lists it, as OpenSSH's does
          (if (if (null? one) #f (%dir? one))
            (listing (first names) (shown-as (first names)))
            (show (order (List map (fn (_ p) (list (shown-as p) () (%lstat c p))) names))))))))

; A size scaled as df -h shows it: under ten with a decimal, then a unit.
(def %scaled
  (fn (_ n)
    ((fn (self v units)
       (if (if (>= v 1024) (not (null? (rest units))) #f) (self (/ v 1024) (rest units))
         (do (def whole (/ (* v 10) 10))
             (Str8 append (if (< v 10)
                            (Str8 append (%num (/ (* v 10) 10)) "." (%num (% (/ (* v 10) 1) 10)))
                            (%num whole))
                          (first units)))))
     n (list "B" "KB" "MB" "GB" "TB" "PB" "EB"))))

(def %df!
  (fn (_ c human path)
    (unless (%extension? c "statvfs@openssh.com")
      (Err raise 'sftp "Server does not support the statvfs@openssh.com extension" ()))
    (def req (%extended c "statvfs@openssh.com"))
    (ssh-put-text (first req) path)
    (def in (rest (%call! c req ())))
    (def v (List map (fn (_ i) (%get-u64 in)) (list 0 1 2 3 4 5 6 7 8 9 10)))
    (def frsize (List ref 1 v))
    (def total (* frsize (List ref 2 v)))
    (def free (* frsize (List ref 3 v)))
    (def avail (* frsize (List ref 4 v)))
    (def used (- total free))
    (def capacity (if (= total 0) 0 (/ (* 100 used) total)))
    (if human
      (do (%out (Str8 append (%pad-left "Size" 8) (%pad-left "Used" 9) (%pad-left "Avail" 9) (%pad-left "(root)" 9) (%pad-left "%Capacity" 13) "\n"))
          (%out (Str8 append (%pad-left (%scaled total) 8) (%pad-left (%scaled used) 9) (%pad-left (%scaled avail) 9)
                             (%pad-left (%scaled free) 9) (%pad-left (Str8 append (%num capacity) "%") 13) "\n")))
      (do (%out (Str8 append (%pad-left "Size" 10) (%pad-left "Used" 10) (%pad-left "Avail" 10) (%pad-left "(root)" 10) (%pad-left "%Capacity" 10) "\n"))
          (%out (Str8 append (%pad-left (%num (/ total 1024)) 10) (%pad-left (%num (/ used 1024)) 10) (%pad-left (%num (/ avail 1024)) 10)
                             (%pad-left (%num (/ free 1024)) 10) (%pad-left (Str8 append (%num capacity) "%") 10) "\n"))))))

; --- commands ------------------------------------------------------------------

; A command line's words: blanks split them; quotes and a backslash keep
; what they hold.
(def %words
  (fn (_ line)
    (def n (Str8 length line))
    ((fn (self i word quote words)
       (match
         ((= i n) (List reverse (if (null? word) words (pair word words))))
         (#t
           (do (def ch (%char line i))
               (def t (Str8 sub i 1 line))
               (match
                 ((not (null? quote))
                   (if (= ch quote) (self (+ i 1) (if (null? word) "" word) () words)
                     (self (+ i 1) (Str8 append (if (null? word) "" word) t) quote words)))
                 ((if (= ch 92) (< (+ i 1) n) #f) (self (+ i 2) (Str8 append (if (null? word) "" word) (Str8 sub (+ i 1) 1 line)) () words))
                 ((if (= ch 34) #t (= ch 39)) (self (+ i 1) (if (null? word) "" word) ch words))
                 ((if (= ch 32) #t (= ch 9)) (self (+ i 1) () () (if (null? word) words (pair word words))))
                 (#t (self (+ i 1) (Str8 append (if (null? word) "" word) t) () words)))))))
     0 () () ())))

; A command's flags and operands: (FLAGS . OPERANDS), FLAGS the letters
; of every leading -word.
(def %flags
  (fn (_ words)
    ((fn (self ws flags)
       (if (if (null? ws) #f (if (> (Str8 length (first ws)) 1) (= (%char (first ws) 0) 45) #f))
         (self (rest ws) (Str8 append flags (Str8 sub 1 (- (Str8 length (first ws)) 1) (first ws))))
         (pair flags ws)))
     words "")))

(def %help
  (Str8 join "\n"
    (list "Available commands:"
          "bye                                Quit sftp"
          "cd path                            Change remote directory to 'path'"
          "chgrp grp path                     Change group of file 'path' to 'grp'"
          "chmod mode path                    Change permissions of file 'path' to 'mode'"
          "chown own path                     Change owner of file 'path' to 'own'"
          "df [-h] [path]                     Display statistics for current directory or"
          "                                   filesystem containing 'path'"
          "exit                               Quit sftp"
          "get [-pr] remote [local]           Download file"
          "help                               Display this help text"
          "lcd path                           Change local directory to 'path'"
          "lls [ls-options [path]]            Display local directory listing"
          "lmkdir path                        Create local directory"
          "ln [-s] oldpath newpath            Link remote file (-s for symlink)"
          "lpwd                               Print local working directory"
          "ls [-1alnrSt] [path]               Display remote directory listing"
          "mkdir path                         Create remote directory"
          "put [-pr] local [remote]           Upload file"
          "pwd                                Display remote working directory"
          "quit                               Quit sftp"
          "rename oldpath newpath             Rename remote file"
          "rm path                            Delete remote file"
          "rmdir path                         Remove remote directory"
          "symlink oldpath newpath            Symlink remote file"
          "version                            Show SFTP version"
          "!command                           Execute 'command' in local shell"
          "!                                  Escape to local shell"
          "?                                  Synonym for help"
          "")))

; A local command under /bin/sh, its status.
(def %shell
  (fn (_ command)
    (def pid (Sys fork))
    (when (= pid 0)
      (Sys dup2 %stdin 0)
      (Sys exec "/bin/sh" (if (null? command) () (list "-c" command)))
      (Sys exit 127))
    (Sys wait pid)))

(def %one-arg
  (fn (_ cmd ops)
    (when (null? ops) (Err raise 'sftp (Str8 append "You must specify a path after a " cmd " command.") ()))
    (first ops)))

(def %two-args
  (fn (_ cmd ops)
    (when (< (List length ops) 2) (Err raise 'sftp (Str8 append "You must specify two paths after a " cmd " command.") ()))
    ops))

; Each remote name a pattern stands for, done; one that matches nothing is
; refused as OpenSSH's sftp refuses it.
(def %each-remote!
  (fn (_ c pattern f)
    (def names (%remote-glob c pattern))
    (when (null? names) (Err raise 'sftp (Str8 append "File \"" (%remote-path c pattern) "\" not found.") ()))
    (List for-each f names)))

; One command: () to go on, or the word to stop.
(def %command!
  (fn (_ c line opts)
    (def preserve (first opts)) (def recursive (List ref 1 opts))
    (def words (%words line))
    (def cmd (if (null? words) "" (first words)))
    (def fo (%flags (if (null? words) () (rest words))))
    (def flags (first fo)) (def ops (rest fo))
    (def has? (fn (_ f) (not (null? (Str8 index-of f flags)))))
    (match
      ((null? words) ())
      ((= (%char cmd 0) 33)
        (do (def rest-line (Str8 sub 1 (- (Str8 length line) 1) line))
            (%shell (if (= (Str8 length (Str8 trim rest-line)) 0) () rest-line))
            ()))
      ((if (str=? cmd "bye") #t (if (str=? cmd "exit") #t (str=? cmd "quit"))) (lit stop))
      ((if (str=? cmd "help") #t (str=? cmd "?")) (do (%out %help) ()))
      ((str=? cmd "version") (do (%out "SFTP protocol version 3\n") ()))
      ((str=? cmd "pwd") (do (%out (Str8 append "Remote working directory: " (%ref c 3) "\n")) ()))
      ((str=? cmd "lpwd") (do (%out (Str8 append "Local working directory: " (Sys getcwd) "\n")) ()))
      ((str=? cmd "progress") (do (%out "Progress meter disabled\n") ()))
      ((str=? cmd "cd")
        (do (def path (%realpath c (%remote-path c (if (null? ops) "" (first ops)))))
            (def a (guard (e (Err raise 'sftp (Str8 append "stat remote: " (e msg)) ())) (%stat c path)))
            (unless (%dir? a) (Err raise 'sftp (Str8 append "Can't change directory: \"" path "\" is not a directory") ()))
            (%set c 3 path)
            ()))
      ((str=? cmd "lcd")
        (do (def path (if (null? ops) (Sys getenv "HOME") (first ops)))
            (when (< (Sys chdir path) 0)
              (Err raise 'sftp (Str8 append "Couldn't change local directory to \"" path "\": No such file or directory") ()))
            ()))
      ((str=? cmd "lmkdir")
        (do (def path (%one-arg cmd ops))
            (guard (e (Err raise 'sftp (Str8 append "Couldn't create local directory \"" path "\": " (%after-op (e msg))) ()))
              (File mkdir path 511))
            ()))
      ((str=? cmd "lls")
        (do (%shell (Str8 join " " (pair "ls" (if (null? words) () (rest words))))) ()))
      ((str=? cmd "ls") (do (%ls! c flags ops) ()))
      ((str=? cmd "mkdir")
        (do (def path (%remote-path c (%one-arg cmd ops)))
            (def req (%path-call! c %MKDIR path))
            (%put-attrs (first req) (list (pair (lit perm) 511)))
            (guard (e (Err raise 'sftp (Str8 append "remote mkdir \"" path "\": " (e msg)) ())) (%status-call! c req))
            ()))
      ((str=? cmd "rmdir")
        (do (def path (%remote-path c (%one-arg cmd ops)))
            (guard (e (Err raise 'sftp (Str8 append "remote rmdir \"" path "\": " (e msg)) ()))
              (%status-call! c (%path-call! c %RMDIR path)))
            ()))
      ((str=? cmd "rm")
        (do (%each-remote! c (%one-arg cmd ops)
              (fn (_ p)
                (%info c (Str8 append "Removing " p "\n"))
                (guard (e (Err raise 'sftp (Str8 append "remote delete " p ": " (e msg)) ()))
                  (%status-call! c (%path-call! c %REMOVE p)))))
            ()))
      ((str=? cmd "rename")
        (do (def two (%two-args cmd ops))
            (def from (%remote-path c (first two))) (def to (%remote-path c (List ref 1 two)))
            (guard (e (Err raise 'sftp (Str8 append "remote rename \"" from "\" to \"" to "\": " (e msg)) ()))
              (if (%extension? c "posix-rename@openssh.com")
                (%two-paths! c (%extended c "posix-rename@openssh.com") from to)
                (%two-paths! c (%request c %RENAME) from to)))
            ()))
      ((if (str=? cmd "symlink") #t (if (str=? cmd "ln") (has? "s") #f))
        (do (def two (%two-args cmd ops))
            ; OpenSSH's order: the target as written, then the link
            (def link (%remote-path c (List ref 1 two)))
            (guard (e (Err raise 'sftp (Str8 append "remote symlink file \"" (first two) "\" to \"" link "\": " (e msg)) ()))
              (%two-paths! c (%request c %SYMLINK) (first two) link))
            ()))
      ((str=? cmd "ln")
        (do (def two (%two-args cmd ops))
            (def from (%remote-path c (first two))) (def to (%remote-path c (List ref 1 two)))
            (unless (%extension? c "hardlink@openssh.com")
              (Err raise 'sftp "Server does not support the hardlink@openssh.com extension" ()))
            (guard (e (Err raise 'sftp (Str8 append "remote link \"" from "\" to \"" to "\": " (e msg)) ()))
              (%two-paths! c (%extended c "hardlink@openssh.com") from to))
            ()))
      ((if (str=? cmd "chmod") #t (if (str=? cmd "chown") #t (str=? cmd "chgrp")))
        (do (def two (%two-args cmd ops))
            (def n (%int (first two) (if (str=? cmd "chmod") 8 10)))
            (when (null? n) (Err raise 'sftp (Str8 append "You must supply a numeric " (if (str=? cmd "chmod") "mode" (if (str=? cmd "chown") "user id" "group id")) ".") ()))
            (%each-remote! c (List ref 1 two)
              (fn (_ p)
                (def a (if (str=? cmd "chmod") (list (pair (lit perm) (& n 4095)))
                         (do (def at (%stat c p))
                             (if (str=? cmd "chown") (list (pair (lit uid) n) (pair (lit gid) (%attr at (lit gid))))
                               (list (pair (lit uid) (%attr at (lit uid))) (pair (lit gid) n))))))
                (%info c (Str8 append "Changing " (if (str=? cmd "chmod") "mode" (if (str=? cmd "chown") "owner" "group")) " on " p "\n"))
                (guard (e (Err raise 'sftp (Str8 append "remote setstat \"" p "\": " (e msg)) ()))
                  (%setstat c p a))))
            ()))
      ; a df that fails says nothing, as OpenSSH's asks quietly
      ((str=? cmd "df") (do (guard (e (Err raise 'sftp "" ())) (%df! c (has? "h") (%remote-path c (if (null? ops) "" (first ops))))) ()))
      ((str=? cmd "get")
        (do (def from (%one-arg cmd ops))
            (def names (%remote-glob c from))
            (when (null? names) (Err raise 'sftp (Str8 append "File \"" (%remote-path c from) "\" not found.") ()))
            (def to (if (null? (rest ops)) () (List ref 1 ops)))
            (def into? (if (null? to) #t (if (> (List length names) 1) #t (eq? (File type to) (lit dir)))))
            (List for-each
              (fn (_ p)
                (def local (if (null? to) (%base p) (if into? (%join to (%base p)) to)))
                (guard (e (Err raise 'sftp (if (str=? (e msg) "No such file or directory") (Str8 append "File \"" p "\" not found.") (e msg)) ()))
                  (%get! c p local (if preserve #t (has? "p")) (if recursive #t (has? "r")))))
              names)
            ()))
      ((str=? cmd "put")
        (do (def from (%one-arg cmd ops))
            (def names (%local-glob from))
            (when (null? names) (Err raise 'sftp (Str8 append "File \"" from "\" not found.") ()))
            (def to (if (null? (rest ops)) () (%remote-path c (List ref 1 ops))))
            (def into? (if (null? to) #t (if (> (List length names) 1) #t
                                           ((fn (_ a) (if (null? a) #f (%dir? a))) (%stat? c to)))))
            (List for-each
              (fn (_ p)
                (def remote (if (null? to) (%remote-path c (%base p)) (if into? (%join to (%base p)) to)))
                (guard (e (Err raise 'sftp (if (str=? (e msg) "Permission denied") (Str8 append "dest open \"" remote "\": Permission denied") (e msg)) ()))
                  ; a directory as OpenSSH's glob marks it, its own slash after
                  (def r (if recursive #t (has? "r")))
                  (def marked (if (if r (if (eq? (File type p) (lit dir)) (not (%slash? p)) #f) #f) (Str8 append p "/") p))
                  (%put! c marked remote (if preserve #t (has? "p")) r)))
              names)
            ()))
      (#t (Err raise 'sftp "Invalid command." ())))))

; --- the session ---------------------------------------------------------------

(def %message
  (fn (_ e) (guard (x "an internal error") (if (Err engine? e) (Str8 append (Err %str (Err code-of e)) ": " (Err %str (Err subject-of e))) (e msg)))))

; A line of input from fd, or () at its end.
(def %read-line
  (fn (_ fd)
    (def b (%make-str 1))
    ((fn (self acc)
       (def n (File read fd b 1))
       (match
         ((< n 1) (if (= (Str8 length acc) 0) () acc))
         ((= (%char b 0) 10) acc)
         (#t (self (Str8 append acc (Str8 sub 0 1 b))))))
     "")))

; The commands of a batch file or the terminal, until bye or the end: 0,
; or 1 when a batch line failed.
(def %commands!
  (fn (_ c fd batch opts)
    ((fn (self)
       (unless batch (%out "sftp> "))
       (def raw (%read-line fd))
       (match
         ((null? raw) (do (unless batch (%out "\n")) 0))
         (#t
           (do (def trimmed (Str8 trim raw))
               (def ignore (if (> (Str8 length trimmed) 0) (= (%char trimmed 0) 45) #f))
               (def quiet (if (> (Str8 length trimmed) 0) (= (%char trimmed 0) 64) #f))
               (def line (if (if ignore #t quiet) (Str8 sub 1 (- (Str8 length trimmed) 1) trimmed) trimmed))
               (when (if batch (not quiet) #f) (%out (Str8 append "sftp> " trimmed "\n")))
               (def outcome
                 (if (if (= (Str8 length line) 0) #t (= (%char line 0) 35)) ()
                   ; a failure said as OpenSSH's error() says it, \r\n, or not at all
                   (guard (e (do (unless (str=? (%message e) "") (%err (Str8 append (%message e) "\r\n"))) (lit failed)))
                     (%command! c line opts))))
               (match
                 ((eq? outcome (lit stop)) 0)
                 ((if (eq? outcome (lit failed)) (if batch (not ignore) #f) #f) 1)
                 (#t (self))))))))))


; The child: the ssh program asking for the subsystem, or -D's command.
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

; [user@]host[:path] or sftp://[user@]host[:port][/path]: (USER HOST PORT
; PATH).  A host in brackets, [::1], is an address with colons in it.
(def ssh-sftp-destination
  (fn (_ d)
    (def url (if (> (Str8 length d) 7) (str=? (Str8 sub 0 7 d) "sftp://") #f))
    (def body (if url (Str8 sub 7 (- (Str8 length d) 7) d) d))
    (def at ((fn (self i) (if (< i 0) () (if (= (%char body i) 64) i (self (- i 1)))))
             (- ((fn (self i) (if (if (< i (Str8 length body)) (not (= (%char body i) (if url 47 58))) #f) (self (+ i 1)) i)) 0) 1)))
    (def user (if (null? at) () (Str8 sub 0 at body)))
    (def rest-text (if (null? at) body (Str8 sub (+ at 1) (- (Str8 length body) at 1) body)))
    (def close (if (if (> (Str8 length rest-text) 0) (= (%char rest-text 0) 91) #f) (Str8 index-of "]" rest-text) ()))
    (def skip (if (null? close) 0 (+ close 1)))
    (def found (Str8 index-of (if url "/" ":") (Str8 sub skip (- (Str8 length rest-text) skip) rest-text)))
    (def cut (if (null? found) () (+ found skip)))
    (def hostport (if (null? cut) rest-text (Str8 sub 0 cut rest-text)))
    (def path (if (null? cut) () (Str8 sub (+ cut 1) (- (Str8 length rest-text) cut 1) rest-text)))
    (def found2 (if url (Str8 index-of ":" (Str8 sub skip (- (Str8 length hostport) skip) hostport)) ()))
    (def colon (if (null? found2) () (+ found2 skip)))
    (def host (if (null? colon) hostport (Str8 sub 0 colon hostport)))
    (list user (if (null? close) host (Str8 sub 1 (- close 1) host))
          (if (null? colon) () (Str8 sub (+ colon 1) (- (Str8 length hostport) colon 1) hostport))
          (if (if (null? path) #f (> (Str8 length path) 0)) path ()))))

; The version exchanged, the server's extensions kept.
(def %hello!
  (fn (_ c)
    (def init (ssh-out))
    (ssh-put-byte init %INIT)
    (ssh-put-uint32 init 3)
    (%send! c init)
    (def r (%reply c))
    (unless (= (first r) %VERSION) (Err raise 'sftp "Invalid packet back from SSH2_FXP_INIT" ()))
    (def in (List ref 2 r))
    (%set c 4 ((fn (self acc)
                 (if (< (ssh-in-left in) 4) (List reverse acc)
                   (do (def k (ssh-get-text in)) (self (pair (pair k (ssh-get-text in)) acc)))))
               ()))))

; sftp: the child started, the version exchanged, the destination's path
; gone to (a directory) or fetched (a file), then the commands.
;   argv      the child's argv
;   path      the destination's path, or ()
;   batch     -b's file, "-" standard input, or () for the terminal
;   opts      (PRESERVE RECURSIVE QUIET), -p's, -r's and -q's
;   buffer    -B's bytes a request
;   requests  -R's requests in flight
(def ssh-sftp-client
  (fn (_ argv path batch opts buffer requests)
    (def kid (%spawn argv))
    (def c (%connection (List ref 2 kid) (List ref 1 kid) buffer requests (first kid)))
    (%set c 8 (if (null? batch) (List ref 2 opts) #t))
    (def status
      (guard (e (do (%err (Str8 append (if (str=? (%message e) "Connection closed") "Connection closed" (%message e)) "\n")) 255))
        (%hello! c)
        (%set c 3 (%realpath c "."))
        (def go
          (if (null? path) ()
            (do (def full (%remote-path c path))
                (def a (%stat? c full))
                (if (if (null? a) #f (%dir? a))
                  (do (%set c 3 (%realpath c full)) ())
                  (guard (e (do (%err (Str8 append (%message e) "\r\n")) 1))
                    (%command! c (Str8 append "get \"" full "\"") opts) 0)))))
        (match
          ((not (null? go)) go)
          ((null? batch)
            (%commands! c %stdin #f opts))
          ((str=? batch "-") (%commands! c %stdin #t opts))
          (#t
            (do (def fd (File open batch (lit rdonly)))
                (if (< fd 0)
                  (do (%err (Str8 append batch ": No such file or directory\n")) 1)
                  (do (def s (%commands! c fd #t opts)) (File close fd) s)))))))
    (guard (e ()) (Sys close (%ref c 1)))
    (guard (e ()) (Sys close (List ref 2 kid)))
    (Sys wait (first kid))
    status))


; --- scp's SFTP mode -------------------------------------------------------------
;
; OpenSSH's scp speaks SFTP unless told -O: the same subsystem, a path
; sent as given, so the server's own directory is a relative one's, and
; each failure said as OpenSSH's scp says it.  A file that fails is said
; and the copy goes on; a local source not there stops it.

; OpenSSH's scp ends its own lines as a terminal would, \r\n.
(def %scp-say (fn (_ t) (%err (Str8 append "scp: " t "\r\n"))))
(def %local-why (fn (_ e) (guard (x ()) (Assoc get (lit local) (e data)))))
(def %why (fn (_ e) (def l (%local-why e)) (if (null? l) (%message e) l)))
(def %after-op (fn (_ m) (def cut (Str8 index-of ": " m)) (if (null? cut) m (Str8 sub (+ cut 2) (- (Str8 length m) cut 2) m))))

; One local path sent to remote: a file, or a directory under -r;
; answers how many failed.
(def %scp-up-one
  (fn (_ c local remote preserve recursive)
    (def kind (File type local))
    (match
      ((if (eq? kind (lit dir)) recursive #f) (%scp-up-dir c local remote preserve))
      ((eq? kind (lit file))
        (guard (e (do (%scp-say (if (null? (%local-why e))
                                  (Str8 append "dest open \"" remote "\": " (%why e))
                                  (Str8 append "local open \"" local "\": " (%why e)))) 1))
          (%upload! c local remote preserve) 0))
      (#t (do (%scp-say (Str8 append "local \"" local "\" is not a regular file")) 1)))))

; A directory sent: made at the far end when it is not there, its
; entries sent, its times set under -p.
(def %scp-up-dir
  (fn (_ c local remote preserve)
    (def s (File stat local))
    (def a (%stat? c remote))
    (match
      ((if (null? a) #f (not (%dir? a)))
        (do (%scp-say (Str8 append "\"" (guard (e remote) (%realpath c remote)) "\" exists but is not a directory")) 1))
      ((null? (guard (e (do (%scp-say (Str8 append "remote mkdir \"" remote "\": " (%why e))) ()))
                (when (null? a)
                  (do (def req (%path-call! c %MKDIR remote))
                      (%put-attrs (first req) (list (pair (lit perm) (& (Assoc get (lit mode) s) 511))))
                      (%status-call! c req)))
                #t))
        1)
      (#t
        (do (def errs (List fold (fn (_ n name) (+ n (%scp-up-one c (%join local name) (%join remote name) preserve #t))) 0
                        (List sort (fn (_ x y) (Str8 <? x y)) (File list-dir local))))
            (when preserve
              (guard (e ()) (%setstat c remote (list (pair (lit atime) (Assoc get (lit atime) s)) (pair (lit mtime) (Assoc get (lit mtime) s))))))
            errs)))))

; Local sources up to the target: into it when it is a directory, or
; when there are several, as a directory made for them.
(def %scp-put
  (fn (_ c sources target preserve recursive)
    (def tgt (if (str=? target "") "." target))
    (def ta (%stat? c tgt))
    (def multi (> (List length sources) 1))
    (when (if multi (if (null? ta) #t (not (%dir? ta))) #f)
      (do (def req (%path-call! c %MKDIR tgt))
          (%put-attrs (first req) (list (pair (lit perm) 511)))
          (guard (e (Err raise 'sftp (Str8 append "remote mkdir \"" tgt "\": " (%why e)) ())) (%status-call! c req))))
    (def into (if multi #t (if (null? ta) #f (%dir? ta))))
    (List fold
      (fn (_ n src)
        (def kind (File type src))
        (when (null? kind) (Err raise 'sftp (Str8 append "stat local \"" src "\": No such file or directory") ()))
        (def f (%scp-up-one c src (if into (%join tgt (%base src)) tgt) preserve recursive))
        (when (> f 0)
          (%scp-say (Str8 append "failed to upload " (if (if recursive (eq? kind (lit dir)) #f) "directory " "file ") src " to " target)))
        (+ n f))
      0 sources)))

; One remote path fetched: a file, or a directory under -r.
(def %scp-down-one
  (fn (_ c remote local a preserve recursive)
    (match
      ((if (%dir? a) recursive #f) (%scp-down-dir c remote local a preserve))
      ((%regular? a)
        (guard (e (do (%scp-say (if (null? (%local-why e))
                                  (Str8 append "remote open \"" remote "\": " (%why e))
                                  (Str8 append "open local \"" local "\": " (%why e)))) 1))
          (%download! c remote local a preserve) 0))
      (#t (do (%scp-say (Str8 append "download " (if (if (%dir? a) (not (%slash? remote)) #f) (Str8 append remote "/") remote)
                                     ": not a regular file")) 1)))))

(def %scp-down-dir
  (fn (_ c remote local a preserve)
    (def made (if (not (null? (File type local))) #t
                (guard (e (do (%scp-say (Str8 append "mkdir " local ": " (%after-op (%message e)))) #f))
                  (File mkdir local (& (%attr a (lit perm)) 511)) #t)))
    (if (not made) 1
      (do (def errs (List fold
                      (fn (_ n e)
                        (def name (first e))
                        (if (if (str=? name ".") #t (str=? name "..")) n
                          (+ n (%scp-down-one c (%join remote name) (%join local name) (List ref 2 e) preserve #t))))
                      0 (%readdir c remote)))
          (when preserve (guard (e ()) (File set-times local (%attr a (lit atime)) (%attr a (lit mtime)))))
          errs))))

; Remote sources, globs among them, down to the local target: into it
; when it is a directory, which several sources need it to be.
(def %scp-get
  (fn (_ c sources target preserve recursive)
    (def kind (File type target))
    (def into (eq? kind (lit dir)))
    (if (if (> (List length sources) 1) (not into) #f)
      (do (%err (Str8 append target ": " (if (null? kind) "No such file or directory" "Not a directory") "\n")) 1)
      (List fold
        (fn (_ n src)
          (def found (List filter (fn (_ f) (not (null? (rest f))))
                       (List map (fn (_ p) (pair p (%stat? c p))) (guard (e ()) (%remote-glob c src)))))
          (if (null? found)
            (do (%scp-say (Str8 append (if (str=? src "") "." src) ": No such file or directory")) (+ n 1))
            (List fold (fn (_ k f) (+ k (%scp-down-one c (first f) (if into (%join target (%base (first f))) target) (rest f) preserve recursive)))
              n found)))
        0 sources))))

; One remote path of one server copied into another's: a file, or a
; directory under -r.
(def %scp-cross-one
  (fn (_ c from-c from to a preserve recursive)
    (match
      ((if (%dir? a) recursive #f) (%scp-cross-dir c from-c from to a preserve))
      ((%regular? a)
        (guard (e (do (%scp-say (if (null? (guard (x ()) (Assoc get (lit from) (e data))))
                                  (Str8 append "dest open \"" to "\": " (%why e))
                                  (Str8 append "remote open \"" from "\": " (%why e)))) 1))
          (%crossload! c from-c from to a preserve) 0))
      (#t (do (%scp-say (Str8 append "download \"" (if (if (%dir? a) (not (%slash? from)) #f) (Str8 append from "/") from)
                                     "\": not a regular file")) 1)))))

(def %scp-cross-dir
  (fn (_ c from-c from to a preserve)
    (def ta (%stat? c to))
    (match
      ((if (null? ta) #f (not (%dir? ta)))
        (do (%scp-say (Str8 append "\"" (guard (e to) (%realpath c to)) "\" exists but is not a directory")) 1))
      ((null? (guard (e (do (%scp-say (Str8 append "remote mkdir \"" to "\": " (%why e))) ()))
                (when (null? ta)
                  (do (def req (%path-call! c %MKDIR to))
                      (%put-attrs (first req) (list (pair (lit perm) (& (%attr a (lit perm)) 511))))
                      (%status-call! c req)))
                #t))
        1)
      (#t
        (do (def errs (List fold
                        (fn (_ n e)
                          (def name (first e))
                          (if (if (str=? name ".") #t (str=? name "..")) n
                            (+ n (%scp-cross-one c from-c (%join from name) (%join to name) (List ref 2 e) preserve #t))))
                        0 (List sort (fn (_ x y) (Str8 <? (first x) (first y))) (%readdir from-c from))))
            (when preserve
              (guard (e ()) (%setstat c to (list (pair (lit atime) (%attr a (lit atime))) (pair (lit mtime) (%attr a (lit mtime)))))))
            errs)))))

; A connection to the server argv's child serves, the version exchanged:
; (C . KID), KID the child's (PID TO FROM).
(def %scp-open
  (fn (_ argv)
    (def kid (%spawn argv))
    (def c (%connection (List ref 2 kid) (List ref 1 kid) 32768 64 (first kid)))
    (%set c 8 #t)
    (%hello! c)
    (pair c kid)))

(def %scp-close
  (fn (_ ck)
    (guard (e ()) (Sys close (List ref 1 (rest ck))))
    (guard (e ()) (Sys close (List ref 2 (rest ck))))
    (Sys wait (first (rest ck)))))

; scp's copy over SFTP: the child spawned on argv, the sources sent up to
; target's remote path when upload, else fetched down into the local
; target; 0, 1 when a file failed, 255 when the copy stopped.
(def ssh-sftp-scp
  (fn (_ argv sources target upload preserve recursive)
    (def cell (Vector make 1 ()))
    (def status
      (guard (e (do (%scp-say (%message e)) 255))
        (%set cell 0 (%scp-open argv))
        (def c (first (%ref cell 0)))
        (if (= 0 (if upload (%scp-put c sources target preserve recursive) (%scp-get c sources target preserve recursive))) 0 1)))
    (unless (null? (%ref cell 0)) (%scp-close (%ref cell 0)))
    status))

; scp between two remote hosts, through this one, as OpenSSH's does by
; default: argv's server the target's, each source (ARGV . PATH), ARGV
; its server's child, or () for a local path, which is sent up.  A
; source's server stays open while the next source is on it too.
; Several sources need the target to be a directory already.
(def ssh-sftp-scp3
  (fn (_ argv sources target preserve recursive)
    (def cells (Vector make 3 ()))
    (def status
      (guard (e (do (%scp-say (%message e)) 255))
        (%set cells 0 (%scp-open argv))
        (def c (first (%ref cells 0)))
        (def tgt (if (str=? target "") "." target))
        (def ta (%stat? c tgt))
        (def into (if (null? ta) #f (%dir? ta)))
        (def multi (> (List length sources) 1))
        (def errs
          (List fold
            (fn (_ n s)
              (match
                ((if multi (not into) #f) (do (%scp-say (Str8 append tgt ": destination is not a directory")) (+ n 1)))
                ((null? (first s))
                  (do (when (null? (File type (rest s))) (Err raise 'sftp (Str8 append "stat local \"" (rest s) "\": No such file or directory") ()))
                      (+ n (%scp-up-one c (rest s) (if into (%join tgt (%base (rest s))) tgt) preserve recursive))))
                (#t
                  (do (unless (if (null? (%ref cells 1)) #f (str=? (%ref cells 2) (Str8 join " " (first s))))
                        (do (unless (null? (%ref cells 1)) (%scp-close (%ref cells 1)))
                            (%set cells 1 ()) (%set cells 1 (%scp-open (first s))) (%set cells 2 (Str8 join " " (first s)))))
                      (def from-c (first (%ref cells 1)))
                      (def src (rest s))
                      (def found (List filter (fn (_ f) (not (null? (rest f))))
                                   (List map (fn (_ p) (pair p (%stat? from-c p))) (guard (e ()) (%remote-glob from-c src)))))
                      (if (null? found)
                        (do (%scp-say (Str8 append (if (str=? src "") "." src) ": No such file or directory")) (+ n 1))
                        (List fold (fn (_ k f) (+ k (%scp-cross-one c from-c (first f) (if into (%join tgt (%base (first f))) tgt) (rest f) preserve recursive)))
                          n found))))))
            0 sources))
        (if (= errs 0) 0 1)))
    (unless (null? (%ref cells 1)) (%scp-close (%ref cells 1)))
    (unless (null? (%ref cells 0)) (%scp-close (%ref cells 0)))
    status))

(provide ssh/sftp-client ssh-sftp-client ssh-sftp-destination ssh-sftp-scp ssh-sftp-scp3)
