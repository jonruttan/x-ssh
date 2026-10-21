; # x-ssh -- SSH on x-lang
;
; ## ssh/ask.x -- secrets and answers asked of the user
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; OpenSSH's read_passphrase: a secret asked at the terminal, or of the
; SSH_ASKPASS program.  The program is allowed when DISPLAY or
; WAYLAND_DISPLAY is set; SSH_ASKPASS_REQUIRE force uses it whatever
; they say, prefer uses it when it is allowed, never never does.
; Otherwise the terminal, and the program when there is none -- or, for
; ssh-keygen, which takes a secret from its standard input too, when
; that input is not a terminal.  Without a terminal readpassphrase reads
; standard input, its prompt on standard error; the client requires the
; terminal.

(module ssh/ask)

(import x/sys/file)
(import x/sys/posix)
(import x/repl/term)

(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %make-str (prim-ref (lit str) (lit make)))
(def %char->int (prim-ref (lit char) (lit ->int)))

; The caller's standard input: the platform keeps it on fd 3, fd 0
; carrying x's own program text.
(def %stdin 3)

; Bytes read from fd to a carriage return or newline, a backspace or
; delete taking back a byte: the line, or () at end of input.
(def %line
  (fn (_ fd)
    (def one (%make-str 1))
    (guard (e ())
      ((fn (self acc)
         (if (< (File read fd one 1) 1) (if (null? acc) () (Str8 join "" (List reverse acc)))
           (do (def b (%char->int (%byte-ref one 0)))
               (match
                 ((if (= b 13) #t (= b 10)) (Str8 join "" (List reverse acc)))
                 ((if (= b 127) #t (= b 8)) (self (if (null? acc) () (rest acc))))
                 (#t (self (pair (Str8 sub 0 1 one) acc)))))))
       ()))))

; A line typed at the terminal, or () when there is no terminal or at end
; of input.  A secret is read as getpass reads it: the terminal made raw
; with its signal keys still signalling, then the prompt written -- in
; that order, or a password typed at once is echoed -- and the terminal
; put back as it was.
(def ssh-ask-tty
  (fn (_ text secret)
    (def fd (guard (e -1) (File open "/dev/tty" (lit rdwr))))
    (if (< fd 0) ()
      (do (def saved (if secret (Term raw-with-signals! fd) ()))
          (File write fd text (%byte-len text))
          (def line (%line fd))
          (when secret
            (do (Term restore! fd saved)
                (File write fd "\r\n" 2)))
          (File close fd)
          line))))

(def ssh-ask-tty? (fn (_) (def fd (guard (e -1) (File open "/dev/tty" (lit rdwr)))) (if (< fd 0) #f (do (File close fd) #t))))

(def %set? (fn (_ name) ((fn (_ v) (if (null? v) #f (> (Str8 length v) 0))) (Sys getenv name))))

; A secret asked of SSH_ASKPASS: the program run with the prompt, its
; output's first line the answer; () when it fails.
(def ssh-askpass
  (fn (_ text)
    (def program (if (%set? "SSH_ASKPASS") (Sys getenv "SSH_ASKPASS") "/usr/X11R6/bin/ssh-askpass"))
    (def p (Sys pipe))
    (def pid (Sys fork))
    (when (= pid 0)
      (Sys dup2 (rest p) 1)
      (Sys close (first p)) (Sys close (rest p))
      (Sys exec program (list text))
      (unless (File exists? program)
        ((fn (_ m) (File write 2 m (%byte-len m)))
         (Str8 append "ssh_askpass: exec(" program "): No such file or directory\n")))
      (Sys exit 127))
    (Sys close (rest p))
    (def buf (%make-str 1024))
    (def out
      ((fn (self acc)
         (def n (File read (first p) buf 1024))
         (if (< n 1) (Str8 join "" (List reverse acc)) (self (pair (Str8 sub 0 n buf) acc))))
       ()))
    (Sys close (first p))
    (if (= (Sys wait pid) 0) (first (Str8 split "\n" (first (Str8 split "\r" out)))) ())))

; A secret as read_passphrase asks for it: the answer, or () for none.
; With stdin, standard input that is not a terminal sends the question
; to the askpass program, and with no terminal the answer is read from
; standard input.
(def ssh-ask-secret
  (fn (_ text stdin)
    (def req (Sys getenv "SSH_ASKPASS_REQUIRE"))
    (def is (fn (_ v) (if (null? req) #f (str=? (Str8 downcase req) v))))
    (def allow (match ((is "force") #t) ((is "never") #f) (#t (if (%set? "DISPLAY") #t (%set? "WAYLAND_DISPLAY")))))
    (def use (match ((is "force") #t)
                    ((if (is "prefer") allow #f) #t)
                    (stdin (not (guard (e #f) (Sys isatty %stdin))))
                    (#t (not (ssh-ask-tty?)))))
    (match
      ((if use allow #f) (ssh-askpass text))
      ((ssh-ask-tty?) (ssh-ask-tty text #t))
      (stdin (do (File write 2 text (%byte-len text)) (%line %stdin)))
      (#t ()))))

(provide ssh/ask ssh-ask-tty ssh-ask-tty? ssh-askpass ssh-ask-secret)
