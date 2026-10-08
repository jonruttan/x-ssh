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

(module ssh/cli)

(import x/sys/opts Opts)
(import x/sys/file File)
(import ssh/client ssh-client-run)

(def %byte-len (prim-ref (lit str) (lit byte-len)))

(def %version-row (Opts flag "-V" "Print the version"))

; One row a program: (LABEL NAMES WHAT DECLARATION) -- the names Dropbear
; answers to, the first the one it lists, and what the program is.
(def %row
  (fn (_ label names what synopsis rows)
    (list label names what (Opts declare (first names) synopsis () rows))))

(def ssh-programs
  (list
    (%row (lit server) (list "dropbear") "the server" "[options]"
      (list %version-row))
    (%row (lit client) (list "dbclient" "ssh") "the client"
      "[options] [user@]host[/port] [command]"
      (list (Opts arg "-p" "port" "Remote port")
            (Opts arg "-i" "keyfile" "The ssh-ed25519 key to authenticate with (OpenSSH format)")
            (Opts arg "-l" "user" "The user to log in as")
            (Opts flag "-y" "Accept the host key without asking")
            (Opts flag "-v" "Trace the connection on standard error")
            %version-row))
    (%row (lit keygen) (list "dropbearkey" "ssh-keygen") "the key generator"
      "-t type -f filename [-s bits]" ())
    (%row (lit convert) (list "dropbearconvert") "the key converter"
      "<inputtype> <outputtype> <inputfile> <outputfile>" ())
    (%row (lit scp) (list "scp") "secure copy" "[options] source ... target" ())))

; The program row a name answers to, or ().
(def ssh-program
  (fn (_ name)
    (List find (fn (_ p) (List any? (fn (_ n) (str=? n name)) (first (rest p))))
      ssh-programs)))

(def %multi
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
      ((null? p) (list () (%multi) 1))
      ((Opts help? decl (rest ops)) (list (first p) (Opts usage decl) 0))
      ((not (null? (Opts unknown o)))
        (list (first p) (Str8 append "Invalid option " (Opts unknown o) "\n" (Opts usage decl)) 1))
      ((Opts on? o "-V") (list (first p) (Str8 append "x-ssh v" ssh-version "\n") 0))
      ((if (eq? (first p) (lit client)) (not (null? (Opts operands o))) #f)
        (%client-plan o))
      (#t (list (first p) (Str8 append (first ops) ": not served yet\n") 1)))))

; The client's line as what to do: (client (exec HOST PORT USER KEY COMMAND
; TRACE) 0), the host operand's [user@]host[/port] split, -l and -p
; winning over it, the command the operands after it joined by spaces.
(def %client-plan
  (fn (_ o)
    (def target (first (Opts operands o)))
    (def at (Str8 index-of "@" target))
    (def host-port (if (null? at) target (Str8 sub (+ at 1) (- (Str8 length target) at 1) target)))
    (def slash (Str8 index-of "/" host-port))
    (def host (if (null? slash) host-port (Str8 sub 0 slash host-port)))
    (def port-text (if (null? slash) () (Str8 sub (+ slash 1) (- (Str8 length host-port) slash 1) host-port)))
    (def user (match ((Opts on? o "-l") (Opts value o "-l"))
                     ((null? at) (Sys getenv "USER"))
                     (#t (Str8 sub 0 at target))))
    (def port (match ((Opts on? o "-p") (%int (Opts value o "-p")))
                     ((null? port-text) 22)
                     (#t (%int port-text))))
    (def key (if (Opts on? o "-i") (Opts value o "-i") ()))
    (def command (Str8 join " " (rest (Opts operands o))))
    (match
      ((null? key) (list (lit client) "x-ssh: -i keyfile is required; no agent or password yet\n" 1))
      ((= (Str8 length command) 0) (list (lit client) "x-ssh: a command is required; no shell yet\n" 1))
      (#t (list (lit client) (list (lit exec) host port user key command (Opts on? o "-v")) 0)))))

(def %int (fn (_ t) ((prim-ref (lit convert) (lit to)) t (Type named INTEGER) 10)))

; A plan done: text to standard error and the status, or the client run.
(def ssh-main
  (fn (_ ops)
    (def plan (ssh-plan ops))
    (def what (first (rest plan)))
    (if (pair? what)
      (Sys exit (ssh-client-run (List ref 1 what) (List ref 2 what) (List ref 3 what)
                                (List ref 4 what) (List ref 5 what) (List ref 6 what)))
      (do (File write 2 what (%byte-len what))
          (Sys exit (first (rest (rest plan))))))))

(provide ssh/cli ssh-programs ssh-program ssh-plan ssh-main)
