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

(def %num (fn (_ n) ((prim-ref (lit convert) (lit to)) n (Type named STRING) 10)))

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

; A failed call's message after its "OP: ", the system's own words.
(def ssh-sys-after-op
  (fn (_ m) (def cut (Str8 index-of ": " m)) (if (null? cut) m (Str8 sub (+ cut 2) (- (Str8 length m) cut 2) m))))

(provide ssh/sys ssh-sys-me ssh-sys-spawn ssh-sys-after-op)
