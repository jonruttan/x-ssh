; # x-ssh -- SSH on x-lang
;
; ## ssh/sys.x -- the process: who it runs as, its children, its errors
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What more than one program asks of the system the same way: the user
; this process runs as, a child on pipes, and the system's words in a
; failed call's message.

(module ssh/sys)

(import x/sys/file)
(import x/sys/posix)
(import x/platform/syscall os-darwin?)
(import x/core/doors ffi-dlopen ffi-dlsym ptr-call ptr-ref ptr-set! str-make str->ptr str-byte-ref char->int int/ int%)

(def %num (fn (_ n) ((prim-ref (lit convert) (lit to)) n (Type named STRING) 10)))

(def %libc (ffi-dlopen () 1))
(def %c-socketpair (ffi-dlsym %libc "socketpair"))
(def %c-socket (ffi-dlsym %libc "socket"))
(def %c-bind (ffi-dlsym %libc "bind"))
(def %c-connect (ffi-dlsym %libc "connect"))
(def %c-close (ffi-dlsym %libc "close"))

; A dotted quad's four numbers.
(def %quad
  (fn (_ q)
    (List map (fn (_ t) ((fn (self i n) (if (= i (Str8 length t)) n (self (+ i 1) (+ (* n 10) (- (char->int (str-byte-ref t i)) 48))))) 0 0))
      (Str8 split "." q))))

; An IPv4 socket address in a GC-owned region, as the system lays it
; out: Darwin leads with its length and a one-byte family, Linux with a
; two-byte family; the port is in network order.
(def %sockaddr
  (fn (_ quad port)
    (def s (str-make 16))
    (def p (str->ptr s))
    ((fn (self i) (when (< i 16) (ptr-set! p i 0 1) (self (+ i 1)))) 0)
    (if os-darwin? (do (ptr-set! p 0 16 1) (ptr-set! p 1 2 1)) (ptr-set! p 0 2 1))
    (ptr-set! p 2 (int/ port 256) 1) (ptr-set! p 3 (int% port 256) 1)
    ((fn (self os i) (unless (null? os) (ptr-set! p i (first os) 1) (self (rest os) (+ i 1)))) (%quad quad) 4)
    s))

; A TCP connection to quad:port, from the local address bind when it is
; not (), as BindAddress makes one: the descriptor, or a label 'io Err
; whose message is the call's and the system's words, `bind: ...` or
; `connect: ...`.
(def ssh-sys-connect
  (fn (_ quad port bind)
    (def fd (Sys %sign-fold (ptr-call %c-socket 2 1 0)))
    (when (< fd 0) (error (Err from-errno (Err errno-of fd) 'socket port)))
    (def fail (fn (_ r op) (def en (Err errno-of r)) (ptr-call %c-close fd) (error (Err from-errno en op port))))
    (unless (null? bind)
      (do (def local (%sockaddr bind 0))
          (def r (Sys %sign-fold (ptr-call %c-bind fd (str->ptr local) 16)))
          (when (< r 0) (fail r 'bind))))
    (def remote (%sockaddr quad port))
    (def r (Sys %sign-fold (ptr-call %c-connect fd (str->ptr remote) 16)))
    (when (< r 0) (fail r 'connect))
    fd))

; A connected pair of unix-domain stream sockets, (A . B), or () when
; the system refuses one.  AF_UNIX and SOCK_STREAM are 1 on Linux and
; Darwin alike; the two descriptors land in a GC-owned region, as
; Sys pipe's do.
(def %socketpair
  (fn (_)
    (let ((s (str-make 8)))
      (let ((buf (str->ptr s)))
        (if (< (Sys %sign-fold (ptr-call %c-socketpair 1 1 0 buf)) 0) ()
          (pair (ptr-ref buf 0 4) (ptr-ref buf 4 4)))))))

; ProxyCommand's command run as OpenSSH runs it, `exec COMMAND` under the
; user's shell, its standard input and output one end of a socket pair:
; (PID . FD), FD the other end, the connection; () when it could not be
; started.
(def ssh-sys-proxy
  (fn (_ command)
    (def sp (%socketpair))
    (if (null? sp) ()
      (do (def pid (Sys fork))
          (when (= pid 0)
            (Sys dup2 (rest sp) 0) (Sys dup2 (rest sp) 1)
            (Sys close (first sp)) (Sys close (rest sp))
            (def shell ((fn (_ s) (if (if (null? s) #t (= (Str8 length s) 0)) "/bin/sh" s)) (Sys getenv "SHELL")))
            (Sys exec shell (list "-c" (Str8 append "exec " command)))
            (Sys exit 127))
          (Sys close (rest sp))
          (if (< pid 0) (do (Sys close (first sp)) ()) (pair pid (first sp)))))))

; The user this process runs as: USER, or the passwd entry of its uid.
(def ssh-sys-me
  (fn (_)
    (def u (Sys getenv "USER"))
    (if (if (null? u) #f (> (Str8 length u) 0)) u
      ((fn (_ e) (if (null? e) "" (first e)))
        (List find (fn (_ fs) (if (> (List length fs) 2) (str=? (List ref 2 fs) (%num (Sys getuid))) #f))
          (List map (fn (_ l) (Str8 split ":" l))
            (Str8 split "\n" (guard (e "") (File read-all "/etc/passwd")))))))))

; PROGRAM run with its stdin and stdout on pipes: (PID TO FROM), TO the
; end we write, FROM the end we read.
(def ssh-sys-spawn
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

; PROGRAM run with nothing on its standard input: (STATUS . OUTPUT), its
; exit status and what it wrote to its standard output.
(def ssh-sys-output
  (fn (_ argv)
    (def p (ssh-sys-spawn argv))
    (Sys close (List ref 1 p))
    (def buf (str-make 4096))
    (def text
      ((fn (self acc)
         (def n (File read (List ref 2 p) buf 4096))
         (if (< n 1) (Str8 join "" (List reverse acc)) (self (pair (Str8 sub 0 n buf) acc))))
       ()))
    (Sys close (List ref 2 p))
    (pair (Sys wait (first p)) text)))

; A failed call's message after its "OP: ", the system's own words.
(def ssh-sys-after-op
  (fn (_ m) (def cut (Str8 index-of ": " m)) (if (null? cut) m (Str8 sub (+ cut 2) (- (Str8 length m) cut 2) m))))

(provide ssh/sys ssh-sys-me ssh-sys-spawn ssh-sys-proxy ssh-sys-connect ssh-sys-output ssh-sys-after-op)
