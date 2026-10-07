; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/cli.x -- the command line
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; x -l ssh -- PROGRAM [ARGS] runs PROGRAM, as `dropbearmulti PROGRAM ARGS`
; does: the server, the client, the key generator, the key converter or
; scp, each by Dropbear's names.  ssh-plan turns a line into what to do,
; with no side effects; ssh-main does it.

(provide ssh/cli ssh-argv ssh-plan ssh-program ssh-main)

(def %ssh-byte-len (prim-ref (lit str) (lit byte-len)))

(def %ssh-engine-flag?
  (fn (_ s)
    (if (str=? s "--batch") #t
      (if (str=? s "--no-color") #t (str=? s "--verbose")))))

; The operands the launcher hands the entry: its own flags dropped, and the
; "--" that ends x's options.
(def ssh-argv
  (fn (_ raw)
    (def ops
      (List filter (fn (_ a) (not (%ssh-engine-flag? a)))
        (if (pair? raw) (rest raw) ())))
    (if (if (pair? ops) (str=? (first ops) "--") #f) (rest ops) ops)))

; Dropbear's program names, each to the program it runs; () for any other.
(def ssh-program
  (fn (_ name)
    (match
      ((str=? name "dropbear") (lit server))
      ((if (str=? name "dbclient") #t (str=? name "ssh")) (lit client))
      ((if (str=? name "dropbearkey") #t (str=? name "ssh-keygen")) (lit keygen))
      ((str=? name "dropbearconvert") (lit convert))
      ((str=? name "scp") (lit scp))
      (#t ()))))

(def %ssh-multi
  (fn (_)
    (Str8 append "x-ssh multi-purpose v"
      (Str8 append ssh-version
        (Str8 append "\nRun 'x -l ssh -- <command>' with one of the following commands.\n"
          (Str8 append "'dropbear' - the server\n"
            (Str8 append "'dbclient' or 'ssh' - the client\n"
              (Str8 append "'dropbearkey' or 'ssh-keygen' - the key generator\n"
                (Str8 append "'dropbearconvert' - the key converter\n"
                  "'scp' - secure copy\n")))))))))

; A line to (PROGRAM TEXT STATUS): the program it names (() for none), what
; to print on standard error, and the exit status.  Dropbear prints its
; version and the multi-purpose list on standard error too.
(def ssh-plan
  (fn (_ ops)
    (def prog (if (null? ops) () (ssh-program (first ops))))
    (match
      ((null? prog) (list () (%ssh-multi) 1))
      ((if (pair? (rest ops)) (str=? (first (rest ops)) "-V") #f)
        (list prog (Str8 append "x-ssh v" (Str8 append ssh-version "\n")) 0))
      (#t
        (list prog (Str8 append (first ops) ": not served yet\n") 1)))))

(def ssh-main
  (fn (_ raw)
    (def plan (ssh-plan (ssh-argv raw)))
    (def text (first (rest plan)))
    (File write 2 text (%ssh-byte-len text))
    (Sys exit (first (rest (rest plan))))))
