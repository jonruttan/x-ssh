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
; scp, each by Dropbear's names.  Each program's options are declared once,
; in ssh-programs: the declaration is what --help prints and what its line
; is parsed against.  ssh-plan turns a line into what to do, with no side
; effects; ssh-main does it.  Like Dropbear, everything goes to standard
; error.

(import x/sys/opts)

(provide ssh/cli ssh-argv ssh-programs ssh-program ssh-plan ssh-main)

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

(def %ssh-version-row (Opts flag "-V" "Print the version"))

; One row a program: (LABEL NAMES WHAT DECLARATION) -- the names Dropbear
; answers to, the first the one it lists, and what the program is.
(def %ssh-row
  (fn (_ label names what synopsis rows)
    (list label names what (Opts declare (first names) synopsis () rows))))

(def ssh-programs
  (list
    (%ssh-row (lit server) (list "dropbear") "the server" "[options]"
      (list %ssh-version-row))
    (%ssh-row (lit client) (list "dbclient" "ssh") "the client"
      "[options] [user@]host[/port] [command]" (list %ssh-version-row))
    (%ssh-row (lit keygen) (list "dropbearkey" "ssh-keygen") "the key generator"
      "-t type -f filename [-s bits]" ())
    (%ssh-row (lit convert) (list "dropbearconvert") "the key converter"
      "<inputtype> <outputtype> <inputfile> <outputfile>" ())
    (%ssh-row (lit scp) (list "scp") "secure copy" "[options] source ... target" ())))

; The program row a name answers to, or ().
(def ssh-program
  (fn (_ name)
    (List find (fn (_ p) (List any? (fn (_ n) (str=? n name)) (first (rest p))))
      ssh-programs)))

(def %ssh-multi
  (fn (_)
    (Str8 join "\n"
      (List append
        (list (Str8 append "x-ssh multi-purpose v" ssh-version)
              "Run 'x -l ssh -- <command>' with one of the following commands.")
        (List map
          (fn (_ p)
            (Str8 append
              (Str8 join " or " (List map (fn (_ n) (Str8 append "'" n "'")) (first (rest p))))
              " - " (first (rest (rest p)))))
          ssh-programs)
        (list "")))))

; A line to (PROGRAM TEXT STATUS): the program's label (() for none), what
; to print, and the exit status.
(def ssh-plan
  (fn (_ ops)
    (def p (if (null? ops) () (ssh-program (first ops))))
    (def decl (if (null? p) () (first (rest (rest (rest p))))))
    (def o (if (null? p) () (Opts parse decl (rest ops))))
    (match
      ((null? p) (list () (%ssh-multi) 1))
      ((Opts help? decl (rest ops)) (list (first p) (Opts usage decl) 0))
      ((not (null? (Opts unknown o)))
        (list (first p) (Str8 append "Invalid option " (Opts unknown o) "\n" (Opts usage decl)) 1))
      ((Opts on? o "-V") (list (first p) (Str8 append "x-ssh v" ssh-version "\n") 0))
      (#t (list (first p) (Str8 append (first ops) ": not served yet\n") 1)))))

(def ssh-main
  (fn (_ raw)
    (def plan (ssh-plan (ssh-argv raw)))
    (def text (first (rest plan)))
    (File write 2 text (%ssh-byte-len text))
    (Sys exit (first (rest (rest plan))))))
