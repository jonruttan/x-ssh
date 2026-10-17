; # x-ssh -- SSH on x-lang
;
; ## ssh/pty.x -- pseudo-terminals
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What a server gives a session that asks for a terminal: a pseudo-
; terminal pair from libc's posix_openpt, grantpt, unlockpt and ptsname
; -- fixed-signature calls, so the ffi door carries them -- and ioctls by
; syscall-door, as x-lang's Term reads a window: ioctl is variadic, and on
; Apple arm64 a variadic argument never reaches the kernel through the
; fixed-signature door.  The requests differ by OS, Darwin encoding the
; direction and size into the number.  Not in x-lang yet: a Pty class
; there is where this belongs once it settles.

(module ssh/pty)

(import x/sys/file)
(import x/sys/posix)
(import x/platform/syscall)

(def %dlopen (prim-ref (lit ffi) (lit dlopen)))
(def %dlsym (prim-ref (lit ffi) (lit dlsym)))
(def %ptr-call (prim-ref (lit ptr) (lit call)))
(def %cvt (prim-ref (lit convert) (lit to)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %str->ptr (prim-ref (lit str) (lit ->ptr)))
(def %pset (prim-ref (lit ptr) (lit set!)))

(def %libc (fn (_ name) (%dlsym (%dlopen () 1) name)))

; A call's int answer as a signed 32-bit result: -1 is an error.
(def %int (fn (_ r) (if (> r 2147483647) (- r 4294967296) r)))

(def %o-rdwr 2)
(def %o-noctty (if os-darwin? 131072 256))
(def %tiocswinsz (if os-darwin? 2148037735 21524))
(def %tiocsctty (if os-darwin? 536900705 21518))

(def %ioctl
  (fn (_ fd request arg)
    (%int ((syscall-door (lit ioctl)) fd request arg))))

; A pseudo-terminal: (MASTER . SLAVE-PATH), or () when libc gives none.
; Its window is set from the child once the slave is its terminal:
; Darwin keeps no window on a master whose slave no one has open.
(def ssh-pty-open
  (fn (_)
    (def m (%int (%ptr-call (%libc "posix_openpt") (+ %o-rdwr %o-noctty))))
    (if (< m 0) ()
      (if (if (< (%int (%ptr-call (%libc "grantpt") m)) 0) #t (< (%int (%ptr-call (%libc "unlockpt") m)) 0))
        (do (File close m) ())
        ((fn (_ p) (if (= p 0) (do (File close m) ()) (pair m (%cvt (%cvt p (Type named POINTER)) (Type named STRING)))))
         (%ptr-call (%libc "ptsname") m))))))

; The terminal's window set: struct winsize, rows then columns then the
; two pixel sizes, four unsigned shorts.
(def ssh-pty-window!
  (fn (_ fd cols rows)
    (def w (%make-str 9))
    (def p (%str->ptr w))
    (%pset p 0 rows 2) (%pset p 2 cols 2) (%pset p 4 0 2) (%pset p 6 0 2)
    (%ioctl fd %tiocswinsz w)))

; In a forked child: a session of its own, the slave opened as its
; controlling terminal with its window set, and made its standard input,
; output and error.
(def ssh-pty-attach!
  (fn (_ slave cols rows)
    (%ptr-call (%libc "setsid"))
    (def fd (File open slave (lit rdwr)))
    (%ioctl fd %tiocsctty 0)
    (ssh-pty-window! fd cols rows)
    (Sys dup2 fd 0) (Sys dup2 fd 1) (Sys dup2 fd 2)
    (when (> fd 2) (File close fd))))

(provide ssh/pty ssh-pty-open ssh-pty-window! ssh-pty-attach!)
