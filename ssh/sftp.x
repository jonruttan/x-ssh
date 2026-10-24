; # x-ssh -- SSH on x-lang
;
; ## ssh/sftp.x -- SFTP, the server's end
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; The SSH file transfer protocol, version 3 (draft-ietf-secsh-filexfer-02),
; as OpenSSH's sftp-server serves it, with the OpenSSH extensions its sftp
; and scp ask for.  A packet is a uint32 count, a type byte and the
; payload; every request but INIT carries an id its reply repeats.  A
; request is answered before the next is read, in the order they came.
;
; Requests are served over two descriptors: sftp-server's standard input
; (fd 3, where the platform keeps it) and output, or a pipe pair when
; sshd serves "internal-sftp" in a child of its own.  A file or directory
; open is a handle, the decimal text of a number; a failure is a STATUS
; whose code is the errno's (no such file, permission denied) or FAILURE.

(module ssh/sftp)

(import x/sys/file)
(import x/sys/posix)
(import x/sys/gc)
(import x/sys/date Date)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-put-bytes ssh-put-string ssh-put-text ssh-out-run
  ssh-in ssh-in-left ssh-in-buf ssh-get-byte ssh-get-uint32 ssh-get-string ssh-get-text ssh-copy)

(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %ptr->int (prim-ref (lit ptr) (lit ->int)))
(def %int->ptr (prim-ref (lit int) (lit ->ptr)))
(def %mem-copy (prim-ref (lit mem) (lit copy)))
(def %cvt (prim-ref (lit convert) (lit to)))

(def %oref (prim-ref (lit obj) (lit ref)))
(def %oset! (prim-ref (lit obj) (lit set!)))

; A record's field i, counted from 0.
(def %ref (fn (_ v i) (%oref v (+ i 1))))
(def %set (fn (_ v i x) (%oset! v (+ i 1) x)))

(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))
(def %min (fn (_ a b) (if (< a b) a b)))

; n bytes of from at from-off into to at to-off, by one copy.
(def %move
  (fn (_ to to-off from from-off n)
    (when (> n 0)
      (%mem-copy (%int->ptr (+ (%ptr->int (%str->ptr to)) to-off))
                 (%int->ptr (+ (%ptr->int (%str->ptr from)) from-off)) n))))

; --- the protocol's numbers --------------------------------------------------

(def %INIT 1) (def %VERSION 2) (def %OPEN 3) (def %CLOSE 4) (def %READ 5) (def %WRITE 6)
(def %LSTAT 7) (def %FSTAT 8) (def %SETSTAT 9) (def %FSETSTAT 10) (def %OPENDIR 11)
(def %READDIR 12) (def %REMOVE 13) (def %MKDIR 14) (def %RMDIR 15) (def %REALPATH 16)
(def %STAT 17) (def %RENAME 18) (def %READLINK 19) (def %SYMLINK 20)
(def %STATUS 101) (def %HANDLE 102) (def %DATA 103) (def %NAME 104) (def %ATTRS 105)
(def %EXTENDED 200) (def %EXTENDED-REPLY 201)

(def %OK 0) (def %EOF 1) (def %NO-SUCH-FILE 2) (def %PERMISSION-DENIED 3) (def %FAILURE 4)
(def %BAD-MESSAGE 5) (def %OP-UNSUPPORTED 8)

(def %texts
  (list "Success" "End of file" "No such file" "Permission denied" "Failure"
        "Bad message" "No connection" "Connection lost" "Operation unsupported"))

; attribute flags
(def %A-SIZE 1) (def %A-UIDGID 2) (def %A-PERMISSIONS 4) (def %A-ACMODTIME 8)
(def %A-EXTENDED 2147483648)

; open flags
(def %F-READ 1) (def %F-WRITE 2) (def %F-APPEND 4) (def %F-CREAT 8) (def %F-TRUNC 16) (def %F-EXCL 32)

; What a packet may hold, as OpenSSH's limits@openssh.com states it: a
; read or write leaves room for its header.
(def %max-packet 262144)
(def %max-io 261120)
(def %dir-batch 100)
(def %collect-every 32)

(def %extensions
  (list (pair "posix-rename@openssh.com" "1") (pair "statvfs@openssh.com" "2")
        (pair "fstatvfs@openssh.com" "2") (pair "hardlink@openssh.com" "1")
        (pair "fsync@openssh.com" "1") (pair "limits@openssh.com" "1")
        (pair "expand-path@openssh.com" "1") (pair "copy-data" "1")
        (pair "home-directory" "1") (pair "users-groups-by-id@openssh.com" "1")))

; --- the descriptors -----------------------------------------------------------

; A reader: (FD BUF POS END), BUF what the last read brought.
(def %reader
  (fn (_ fd)
    (def r (Vector make 4 ()))
    (%set r 0 fd) (%set r 1 (%make-str 65536)) (%set r 2 0) (%set r 3 0)
    r))

; n bytes as a fresh string, or () when the input ends first.
(def %take!
  (fn (_ r n)
    (def out (%make-str (if (= n 0) 1 n)))
    ((fn (self got)
       (match
         ((= got n) out)
         ((< (%ref r 2) (%ref r 3))
           (do (def k (%min (- n got) (- (%ref r 3) (%ref r 2))))
               (%move out got (%ref r 1) (%ref r 2) k)
               (%set r 2 (+ (%ref r 2) k))
               (self (+ got k))))
         (#t
           (do (def m (File read (%ref r 0) (%ref r 1) 65536))
               (if (< m 1) ()
                 (do (%set r 2 0) (%set r 3 m) (self got)))))))
     0)))

(def %write-all
  (fn (self fd s start n)
    (when (> n 0)
      (do (def w (File write fd (if (= start 0) s (ssh-copy s start n)) n))
          (when (< w 1) (Err raise 'io "sftp: the client is gone" ()))
          (when (< w n) (self fd s (+ start w) (- n w)))))))

; --- the session ---------------------------------------------------------------
;
; (READER OUT-FD HANDLES NEXT READ-ONLY USERS GROUPS SERVED): HANDLES an alist of
; handle text to (KIND FD-OR-NAMES PATH), KIND file or dir; SERVED the
; requests since the last collect.
(def %session
  (fn (_ in out read-only)
    (def st (Vector make 8 ()))
    (%set st 0 (%reader in)) (%set st 1 out) (%set st 2 ())
    (%set st 3 0) (%set st 4 read-only) (%set st 7 0)
    st))

(def %send!
  (fn (_ st body)
    (def run (ssh-out-run body))
    (def f (ssh-out))
    (ssh-put-uint32 f (rest run))
    (ssh-put-bytes f (first run) 0 (rest run))
    (def all (ssh-out-run f))
    (%write-all (%ref st 1) (first all) 0 (rest all))))

(def %reply
  (fn (_ type id)
    (def out (ssh-out))
    (ssh-put-byte out type)
    (ssh-put-uint32 out id)
    out))

(def %put-u64
  (fn (_ out n) (ssh-put-uint32 out (>> n 32)) (ssh-put-uint32 out n)))

(def %get-u64
  (fn (_ in) (def hi (ssh-get-uint32 in)) (+ (<< hi 32) (ssh-get-uint32 in))))

(def %status!
  (fn (_ st id code)
    (def out (%reply %STATUS id))
    (ssh-put-uint32 out code)
    (ssh-put-text out (List ref code %texts))
    (ssh-put-text out "")
    (%send! st out)))

; An error's status: the errno an Err carries, read as the protocol's.
(def %code-of
  (fn (_ e)
    (def sym (guard (_ ()) (Assoc get (lit sym) (e data))))
    (match
      ((eq? sym (lit enoent)) %NO-SUCH-FILE)
      ((eq? sym (lit enotdir)) %NO-SUCH-FILE)
      ((eq? sym (lit eacces)) %PERMISSION-DENIED)
      ((eq? sym (lit eperm)) %PERMISSION-DENIED)
      ((eq? sym (lit erofs)) %PERMISSION-DENIED)
      (#t %FAILURE))))

; A raw call's result, raised as its errno when it failed.
(def %check
  (fn (_ r op path) (if (< r 0) (error (Err from-errno r op path)) r)))

(def %refuse (fn (_) (Err raise 'io "sftp: refused" (list (pair (lit sym) (lit eacces))))))

; --- handles -------------------------------------------------------------------

(def %handle-new!
  (fn (_ st kind what path)
    (def h (%num (%ref st 3)))
    (%set st 3 (+ (%ref st 3) 1))
    (def e (Vector make 3 ()))
    (%set e 0 kind) (%set e 1 what) (%set e 2 path)
    (%set st 2 (pair (pair h e) (%ref st 2)))
    h))

(def %handle
  (fn (_ st h kind)
    (def p (List find (fn (_ p) (str=? (first p) h)) (%ref st 2)))
    (if (if (null? p) #f (if (null? kind) #t (eq? (%ref (rest p) 0) kind))) (rest p)
      (Err raise 'io "sftp: no such handle" (list (pair (lit sym) (lit ebadf)))))))

(def %handle-drop!
  (fn (_ st h)
    (%set st 2 (List filter (fn (_ p) (not (str=? (first p) h))) (%ref st 2)))))

; --- attributes ----------------------------------------------------------------

(def %put-attrs
  (fn (_ out s)
    (ssh-put-uint32 out (| %A-SIZE (| %A-UIDGID (| %A-PERMISSIONS %A-ACMODTIME))))
    (%put-u64 out (Assoc get (lit size) s))
    (ssh-put-uint32 out (Assoc get (lit uid) s))
    (ssh-put-uint32 out (Assoc get (lit gid) s))
    (ssh-put-uint32 out (Assoc get (lit mode) s))
    (ssh-put-uint32 out (Assoc get (lit atime) s))
    (ssh-put-uint32 out (Assoc get (lit mtime) s))))

; The attributes a request carries, as an alist of what was given.
(def %get-attrs
  (fn (_ in)
    (def flags (ssh-get-uint32 in))
    (def size (if (= 0 (& flags %A-SIZE)) () (list (pair (lit size) (%get-u64 in)))))
    (def owner (if (= 0 (& flags %A-UIDGID)) ()
                 (do (def u (ssh-get-uint32 in)) (list (pair (lit uid) u) (pair (lit gid) (ssh-get-uint32 in))))))
    (def perm (if (= 0 (& flags %A-PERMISSIONS)) () (list (pair (lit perm) (ssh-get-uint32 in)))))
    (def times (if (= 0 (& flags %A-ACMODTIME)) ()
                 (do (def a (ssh-get-uint32 in)) (list (pair (lit atime) a) (pair (lit mtime) (ssh-get-uint32 in))))))
    (unless (= 0 (& flags %A-EXTENDED))
      ((fn (self n) (when (> n 0) (do (ssh-get-string in) (ssh-get-string in) (self (- n 1)))))
       (ssh-get-uint32 in)))
    (List append size owner perm times)))

(def %attr (fn (_ a k) (def p (List find (fn (_ p) (eq? (first p) k)) a)) (if (null? p) () (rest p))))

; Attributes set on a path, or through fd when it is open: the size, the
; permissions, the times, then the owner, as OpenSSH's sftp-server sets them.
(def %set-attrs!
  (fn (_ path fd a)
    (def size (%attr a (lit size)))
    (unless (null? size)
      (if (null? fd)
        (do (def f (%check (File open path (lit wronly)) (lit open) path))
            (def r (File truncate f size))
            (File close f)
            (%check r (lit truncate) path))
        (%check (File truncate fd size) (lit truncate) path)))
    (def perm (%attr a (lit perm)))
    (unless (null? perm) (File chmod path (& perm 4095)))
    (def mtime (%attr a (lit mtime)))
    (unless (null? mtime) (File set-times path (%attr a (lit atime)) mtime))
    (def uid (%attr a (lit uid)))
    (unless (null? uid) (File chown path uid (%attr a (lit gid))))))

; --- names ---------------------------------------------------------------------

(def %table
  (fn (_ path)
    (List filter (fn (_ fs) (> (List length fs) 2))
      (List map (fn (_ l) (Str8 split ":" l)) (Str8 split "\n" (guard (e "") (File read-all path)))))))

; The name /etc/passwd or /etc/group gives an id, or the id's digits; ""
; for none where empty says so.
(def %name-of
  (fn (_ st slot path id . empty)
    (when (null? (%ref st slot)) (%set st slot (%table path)))
    (def row (List find (fn (_ fs) (str=? (List ref 2 fs) (%num id))) (%ref st slot)))
    (if (null? row) (if (null? empty) (%num id) "") (first row))))

(def %pad-left
  (fn (_ t w) (def n (Str8 length t)) (if (>= n w) t (Str8 append (Str8 repeat (- w n) " ") t))))
(def %pad-right
  (fn (_ t w) (def n (Str8 length t)) (if (>= n w) t (Str8 append t (Str8 repeat (- w n) " ")))))

(def %months (list "Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"))

; ls -l's mode: the type, then three rwx triples with the set-id and
; sticky bits.
(def %mode-text
  (fn (_ mode)
    (def fmt (& mode 61440))
    (def bit (fn (_ b c) (if (= 0 (& mode b)) "-" c)))
    (def x (fn (_ b special lower upper)
             (if (= 0 (& mode special)) (bit b "x") (if (= 0 (& mode b)) upper lower))))
    (Str8 append
      (match ((= fmt 16384) "d") ((= fmt 40960) "l") ((= fmt 8192) "c") ((= fmt 24576) "b")
             ((= fmt 4096) "p") ((= fmt 49152) "s") (#t "-"))
      (bit 256 "r") (bit 128 "w") (x 64 2048 "s" "S")
      (bit 32 "r") (bit 16 "w") (x 8 1024 "s" "S")
      (bit 4 "r") (bit 2 "w") (x 1 512 "t" "T"))))

; The line an `ls -l` in sftp shows for a name, as OpenSSH's sftp-server
; writes it: the time of day within half a year past, else the year.
(def %longname
  (fn (_ st name s)
    (def mtime (Assoc get (lit mtime) s))
    (def d (Date local mtime))
    (def now (Sys now))
    (def two (fn (_ n) (%pad-left (%num n) 2)))
    (def when-text
      (Str8 append (List ref (- (Assoc get (lit month) d) 1) %months) " " (two (Assoc get (lit day) d)) " "
        (if (if (> mtime (- now 15768000)) (<= mtime now) #f)
          (Str8 append (Str8 replace " " "0" (two (Assoc get (lit hour) d))) ":"
                       (Str8 replace " " "0" (two (Assoc get (lit minute) d))))
          (Str8 append " " (%num (Assoc get (lit year) d))))))
    (def user (%name-of st 5 "/etc/passwd" (Assoc get (lit uid) s)))
    (def group (%name-of st 6 "/etc/group" (Assoc get (lit gid) s)))
    (Str8 append (%mode-text (Assoc get (lit mode) s)) " "
      (%pad-left (%num (Assoc get (lit nlink) s)) 4) " "
      (%pad-right user 8) " " (%pad-right group 8) " "
      (%pad-left (%num (Assoc get (lit size) s)) 8) " " when-text " " name)))

; --- paths ---------------------------------------------------------------------

(def %parts
  (fn (_ p) (List filter (fn (_ c) (not (if (str=? c "") #t (str=? c ".")))) (Str8 split "/" p))))

(def %joined
  (fn (_ done) (if (null? done) "/" (Str8 append "/" (Str8 join "/" (List reverse done))))))

; An absolute path with no ".", ".." or symbolic link in it: a relative one
; is taken from the working directory.  What does not exist is kept as
; written, so a name about to be made has a path too.
(def %canonical
  (fn (_ path)
    (def abs (if (if (> (Str8 length path) 0) (str=? (Str8 sub 0 1 path) "/") #f) path
               (Str8 append (Sys getcwd) "/" path)))
    ((fn (self done todo links)
       (match
         ((null? todo) (%joined done))
         ((str=? (first todo) "..") (self (if (null? done) () (rest done)) (rest todo) links))
         (#t
           (do (def here (%joined (pair (first todo) done)))
               (def kind (File ltype here))
               (match
                 ((null? kind)
                   (self (pair (first todo) done) (rest todo) 40))
                 ((if (eq? kind (lit link)) (< links 40) #f)
                   (do (def target (File readlink here))
                       (self (if (str=? (Str8 sub 0 1 target) "/") () done)
                             (List append (%parts target) (rest todo)) (+ links 1))))
                 (#t (self (pair (first todo) done) (rest todo) links)))))))
     () (%parts abs) 0)))

(def %me
  (fn (_)
    (def u (Sys getenv "USER"))
    (if (if (null? u) #f (> (Str8 length u) 0)) u
      ((fn (_ row) (if (null? row) "" (first row)))
        (List find (fn (_ fs) (str=? (List ref 2 fs) (%num (Sys getuid)))) (%table "/etc/passwd"))))))

(def %home-of
  (fn (_ user)
    (def row (List find (fn (_ fs) (str=? (first fs) user)) (%table "/etc/passwd")))
    (match
      ((if (null? row) #f (> (List length row) 5)) (List ref 5 row))
      ((str=? user (%me)) (Sys getenv "HOME"))
      (#t (Err raise 'io "sftp: no such user" (list (pair (lit sym) (lit enoent))))))))

; ~ and ~user at a path's start, as expand-path@openssh.com reads them.
(def %expand
  (fn (_ path)
    (match
      ((not (if (> (Str8 length path) 0) (str=? (Str8 sub 0 1 path) "~") #f)) path)
      (#t
        (do (def slash ((fn (self i) (if (if (< i (Str8 length path)) (not (str=? (Str8 sub i 1 path) "/")) #f) (self (+ i 1)) i)) 1))
            (def user (if (= slash 1) (%me) (Str8 sub 1 (- slash 1) path)))
            (Str8 append (%home-of user) (Str8 sub slash (- (Str8 length path) slash) path)))))))

; --- the requests --------------------------------------------------------------

(def %one-name!
  (fn (_ st id name)
    (def out (%reply %NAME id))
    (ssh-put-uint32 out 1)
    (ssh-put-text out name)
    (ssh-put-text out name)
    (ssh-put-uint32 out 0)
    (%send! st out)))

(def %attrs!
  (fn (_ st id s)
    (def out (%reply %ATTRS id))
    (%put-attrs out s)
    (%send! st out)))

(def %writes?
  (fn (_ pflags) (not (= 0 (& pflags (| %F-WRITE (| %F-APPEND (| %F-CREAT %F-TRUNC))))))))

(def %open!
  (fn (_ st id in)
    (def path (ssh-get-text in))
    (def pflags (ssh-get-uint32 in))
    (def a (%get-attrs in))
    (when (if (%ref st 4) (%writes? pflags) #f) (%refuse))
    (def rw (match
              ((if (= 0 (& pflags %F-READ)) #f (not (= 0 (& pflags %F-WRITE)))) (lit rdwr))
              ((not (= 0 (& pflags (| %F-WRITE %F-APPEND)))) (lit wronly))
              (#t (lit rdonly))))
    (def mode (List append (list rw)
                (if (= 0 (& pflags %F-APPEND)) () (list (lit append)))
                (if (= 0 (& pflags %F-CREAT)) () (list (lit creat)))
                (if (= 0 (& pflags %F-TRUNC)) () (list (lit trunc)))
                (if (= 0 (& pflags %F-EXCL)) () (list (lit excl)))))
    (def perm (%attr a (lit perm)))
    (def fd (%check (File open path mode (if (null? perm) 438 (& perm 4095))) (lit open) path))
    (def out (%reply %HANDLE id))
    (ssh-put-text out (%handle-new! st (lit file) fd path))
    (%send! st out)))

(def %close!
  (fn (_ st id in)
    (def h (ssh-get-text in))
    (def e (%handle st h ()))
    (%handle-drop! st h)
    (when (eq? (%ref e 0) (lit file)) (%check (File close (%ref e 1)) (lit close) (%ref e 2)))
    (%status! st id %OK)))

(def %read!
  (fn (_ st id in)
    (def e (%handle st (ssh-get-text in) (lit file)))
    (def offset (%get-u64 in))
    (def len (%min (ssh-get-uint32 in) %max-io))
    (def fd (%ref e 1))
    (%check (File seek fd offset) (lit seek) (%ref e 2))
    (def buf (%make-str (if (= len 0) 1 len)))
    (def n (%check (File read fd buf len) (lit read) (%ref e 2)))
    (if (= n 0)
      (%status! st id %EOF)
      (do (def out (%reply %DATA id))
          (ssh-put-string out buf 0 n)
          (%send! st out)))))

(def %write!
  (fn (_ st id in)
    (def e (%handle st (ssh-get-text in) (lit file)))
    (def offset (%get-u64 in))
    (def r (ssh-get-string in))
    (def fd (%ref e 1))
    (%check (File seek fd offset) (lit seek) (%ref e 2))
    (def data (ssh-copy (ssh-in-buf in) (first r) (rest r)))
    ((fn (self start)
       (when (< start (rest r))
         (do (def n (- (rest r) start))
             (def w (%check (File write fd (if (= start 0) data (ssh-copy data start n)) n) (lit write) (%ref e 2)))
             (self (+ start w)))))
     0)
    (%status! st id %OK)))

(def %opendir!
  (fn (_ st id in)
    (def path (ssh-get-text in))
    (def names (File list-dir path))
    (def out (%reply %HANDLE id))
    (ssh-put-text out (%handle-new! st (lit dir) (List append (list "." "..") names) path))
    (%send! st out)))

(def %readdir!
  (fn (_ st id in)
    (def e (%handle st (ssh-get-text in) (lit dir)))
    (def dir (%ref e 2))
    ; a batch of names with their attributes; one gone since the
    ; listing is passed over
    (def batch
      ((fn (self names n acc)
         (if (if (null? names) #t (= n 0)) (pair names (List reverse acc))
           (do (def name (first names))
               (def s (guard (_ ()) (File lstat (Str8 append dir "/" name))))
               (self (rest names) (- n 1) (if (null? s) acc (pair (pair name s) acc))))))
       (%ref e 1) %dir-batch ()))
    (%set e 1 (first batch))
    (if (null? (rest batch))
      (%status! st id %EOF)
      (do (def out (%reply %NAME id))
          (ssh-put-uint32 out (List length (rest batch)))
          (List for-each
            (fn (_ p)
              (ssh-put-text out (first p))
              (ssh-put-text out (%longname st (first p) (rest p)))
              (%put-attrs out (rest p)))
            (rest batch))
          (%send! st out)))))

(def %statvfs!
  (fn (_ st id path)
    (def f (File statfs path))
    (def out (%reply %EXTENDED-REPLY id))
    (List for-each (fn (_ n) (%put-u64 out n))
      (list (Assoc get (lit bsize) f) (Assoc get (lit bsize) f) (Assoc get (lit blocks) f)
            (Assoc get (lit bfree) f) (Assoc get (lit bavail) f) (Assoc get (lit files) f)
            (Assoc get (lit ffree) f) (Assoc get (lit ffree) f) 0 0 255))
    (%send! st out)))

; copy-data: len bytes of one handle at an offset written into another at
; an offset; a len of 0 copies to the end.
(def %copy-data!
  (fn (_ st id in)
    (def from (%handle st (ssh-get-text in) (lit file)))
    (def from-off (%get-u64 in))
    (def len (%get-u64 in))
    (def to (%handle st (ssh-get-text in) (lit file)))
    (def to-off (%get-u64 in))
    (%check (File seek (%ref from 1) from-off) (lit seek) (%ref from 2))
    (%check (File seek (%ref to 1) to-off) (lit seek) (%ref to 2))
    (def buf (%make-str 65536))
    ((fn (self left)
       (def want (if (= len 0) 65536 (%min left 65536)))
       (when (> want 0)
         (do (def n (%check (File read (%ref from 1) buf want) (lit read) (%ref from 2)))
             (when (> n 0)
               (do (%write-all (%ref to 1) buf 0 n)
                   (self (- left n)))))))
     len)
    (%status! st id %OK)))

(def %extended!
  (fn (_ st id in)
    (def name (ssh-get-text in))
    (def ro (%ref st 4))
    (match
      ((str=? name "posix-rename@openssh.com")
        (do (def from (ssh-get-text in)) (def to (ssh-get-text in))
            (when ro (%refuse))
            (File rename from to)
            (%status! st id %OK)))
      ((str=? name "hardlink@openssh.com")
        (do (def from (ssh-get-text in)) (def to (ssh-get-text in))
            (when ro (%refuse))
            (File link from to)
            (%status! st id %OK)))
      ((str=? name "statvfs@openssh.com") (%statvfs! st id (ssh-get-text in)))
      ((str=? name "fstatvfs@openssh.com") (%statvfs! st id (%ref (%handle st (ssh-get-text in) ()) 2)))
      ((str=? name "fsync@openssh.com")
        (do (def e (%handle st (ssh-get-text in) (lit file)))
            (%check (Sys fsync (%ref e 1)) (lit fsync) (%ref e 2))
            (%status! st id %OK)))
      ((str=? name "limits@openssh.com")
        (do (def out (%reply %EXTENDED-REPLY id))
            (%put-u64 out %max-packet) (%put-u64 out %max-io) (%put-u64 out %max-io) (%put-u64 out 0)
            (%send! st out)))
      ((str=? name "expand-path@openssh.com") (%one-name! st id (%canonical (%expand (ssh-get-text in)))))
      ((str=? name "home-directory") (%one-name! st id (%canonical (%home-of (ssh-get-text in)))))
      ((str=? name "copy-data") (do (when ro (%refuse)) (%copy-data! st id in)))
      ; each id list a string of uint32s, each answer a string of the
      ; names, empty for an id with none
      ((str=? name "users-groups-by-id@openssh.com")
        (do (def ids (fn (_ r) (def sub (ssh-in (ssh-in-buf in) (first r) (rest r)))
                       ((fn (self acc) (if (< (ssh-in-left sub) 4) (List reverse acc) (self (pair (ssh-get-uint32 sub) acc)))) ())))
            (def us (ids (ssh-get-string in)))
            (def gs (ids (ssh-get-string in)))
            (def names (fn (_ slot path l) (def o (ssh-out)) (List for-each (fn (_ i) (ssh-put-text o (%name-of st slot path i #t))) l) (ssh-out-run o)))
            (def out (%reply %EXTENDED-REPLY id))
            (def nu (names 5 "/etc/passwd" us)) (def ng (names 6 "/etc/group" gs))
            (ssh-put-string out (first nu) 0 (rest nu))
            (ssh-put-string out (first ng) 0 (rest ng))
            (%send! st out)))
      (#t (%status! st id %OP-UNSUPPORTED)))))

; One request served.
(def %serve!
  (fn (_ st type id in)
    (def ro (%ref st 4))
    (match
      ((= type %OPEN) (%open! st id in))
      ((= type %CLOSE) (%close! st id in))
      ((= type %READ) (%read! st id in))
      ((= type %WRITE) (do (when ro (%refuse)) (%write! st id in)))
      ((= type %LSTAT) (%attrs! st id (File lstat (ssh-get-text in))))
      ((= type %STAT) (%attrs! st id (File stat (ssh-get-text in))))
      ((= type %FSTAT) (%attrs! st id (File stat (%ref (%handle st (ssh-get-text in) ()) 2))))
      ((= type %SETSTAT)
        (do (def path (ssh-get-text in))
            (def a (%get-attrs in))
            (when ro (%refuse))
            (%set-attrs! path () a)
            (%status! st id %OK)))
      ((= type %FSETSTAT)
        (do (def e (%handle st (ssh-get-text in) ()))
            (def a (%get-attrs in))
            (when ro (%refuse))
            (%set-attrs! (%ref e 2) (if (eq? (%ref e 0) (lit file)) (%ref e 1) ()) a)
            (%status! st id %OK)))
      ((= type %OPENDIR) (%opendir! st id in))
      ((= type %READDIR) (%readdir! st id in))
      ((= type %REMOVE) (do (def path (ssh-get-text in)) (when ro (%refuse)) (File unlink path) (%status! st id %OK)))
      ((= type %MKDIR)
        (do (def path (ssh-get-text in))
            (def perm (%attr (%get-attrs in) (lit perm)))
            (when ro (%refuse))
            (File mkdir path (if (null? perm) 511 (& perm 4095)))
            (%status! st id %OK)))
      ((= type %RMDIR) (do (def path (ssh-get-text in)) (when ro (%refuse)) (File rmdir path) (%status! st id %OK)))
      ((= type %REALPATH) (%one-name! st id (%canonical (ssh-get-text in))))
      ; a rename onto a name that exists is refused, as the draft says;
      ; posix-rename@openssh.com is the one that replaces it
      ((= type %RENAME)
        (do (def from (ssh-get-text in)) (def to (ssh-get-text in))
            (when ro (%refuse))
            (if (null? (File ltype to))
              (do (File rename from to) (%status! st id %OK))
              (%status! st id %FAILURE))))
      ((= type %READLINK) (%one-name! st id (File readlink (ssh-get-text in))))
      ; OpenSSH's order: the link's target first, then the link
      ((= type %SYMLINK)
        (do (def target (ssh-get-text in)) (def link (ssh-get-text in))
            (when ro (%refuse))
            (File symlink target link)
            (%status! st id %OK)))
      ((= type %EXTENDED) (%extended! st id in))
      (#t (%status! st id %OP-UNSUPPORTED)))))

(def %version!
  (fn (_ st)
    (def out (ssh-out))
    (ssh-put-byte out %VERSION)
    (ssh-put-uint32 out 3)
    (List for-each (fn (_ p) (ssh-put-text out (first p)) (ssh-put-text out (rest p))) %extensions)
    (%send! st out)))

; Requests served from in, replies written to out, until the input ends:
; 0, or 1 when a packet is malformed past answering.  Under read-only every
; request that would change a file is refused.
(def ssh-sftp-server
  (fn (_ in out read-only)
    (def st (%session in out read-only))
    (def r (%ref st 0))
    ((fn (self)
       (def head (%take! r 4))
       (if (null? head) 0
         (do (def hin (ssh-in head 0 4))
             (def len (ssh-get-uint32 hin))
             (def body (if (if (> len 0) (<= len %max-packet) #f) (%take! r len) ()))
             (if (null? body) 1
               (do (def in (ssh-in body 0 len))
                   (def type (ssh-get-byte in))
                   (if (= type %INIT)
                     (%version! st)
                     (if (< (ssh-in-left in) 4) ()
                       (do (def id (ssh-get-uint32 in))
                           (guard (e (%status! st id (%code-of e)))
                             (%serve! st type id in)))))
                   ; a request is a packet's worth of garbage, up to a
                   ; read's or a write's data: collected every so many
                   (%set st 7 (+ (%ref st 7) 1))
                   (when (>= (%ref st 7) %collect-every) (do (Heap collect) (%set st 7 0)))
                   (self)))))))))


; The server as sftp-server's options start it: -d's directory, %d the
; home directory and %u the user, then requests served.  A directory it
; cannot enter ends it with 255, as OpenSSH's ends.
(def ssh-sftp-main
  (fn (_ dir read-only in out)
    (def path (if (null? dir) ()
                (Str8 replace "%%" "%"
                  (Str8 replace "%u" (%me)
                    (Str8 replace "%d" (guard (e "") (%home-of (%me))) dir)))))
    (if (if (null? path) #f (< (Sys chdir path) 0))
      (do (def t (Str8 append "sftp-server: chdir to \"" path "\" failed\n"))
          (File write 2 t (%byte-len t))
          255)
      (ssh-sftp-server in out read-only))))

; internal-sftp's arguments, as sshd_config's Subsystem line gives them:
; (DIR READ-ONLY), or a text saying what is not served.
(def ssh-sftp-options
  (fn (self args)
    ((fn (loop as dir ro)
       (match
         ((null? as) (list dir ro))
         ((str=? (first as) "-R") (loop (rest as) dir #t))
         ((str=? (first as) "-e") (loop (rest as) dir ro))
         ((if (null? (rest as)) #f (str=? (first as) "-d")) (loop (rest (rest as)) (first (rest as)) ro))
         ((if (null? (rest as)) #f (if (str=? (first as) "-f") #t (str=? (first as) "-l")))
           (loop (rest (rest as)) dir ro))
         (#t (Str8 append "internal-sftp: " (first as) " is not served"))))
     args () #f)))

; The pieces the client shares: the reader and its take, the writer, the
; 64-bit numbers, the attributes a packet carries, and ls -l's mode.
(def ssh-sftp-reader %reader)
(def ssh-sftp-take! %take!)
(def ssh-sftp-write-all %write-all)
(def ssh-sftp-put-u64 %put-u64)
(def ssh-sftp-get-u64 %get-u64)
(def ssh-sftp-get-attrs %get-attrs)
(def ssh-sftp-mode-text %mode-text)

(provide ssh/sftp ssh-sftp-server ssh-sftp-main ssh-sftp-options
  ssh-sftp-reader ssh-sftp-take! ssh-sftp-write-all ssh-sftp-put-u64 ssh-sftp-get-u64 ssh-sftp-get-attrs ssh-sftp-mode-text)
