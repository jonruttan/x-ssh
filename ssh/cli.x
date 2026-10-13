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
(import ssh/keygen ssh-keygen-generate ssh-keygen-print)
(import ssh/server ssh-serve)
(import ssh/scp ssh-scp-client ssh-scp-remote)
(import ssh/convert ssh-convert)

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
      (list (Opts arg "-r" "keyfile" "Specify the host key: ssh-ed25519, Dropbear's or OpenSSH's file")
            (Opts arg "-p" "[address:]port" "Listen on the address and port, default 22 on every address")
            (Opts arg "-D" "dir" "Directory containing the authorized_keys file, default ~/.ssh")
            (Opts flag "-R" "Create hostkeys as required")
            (Opts flag "-F" "Don't fork into background")
            (Opts flag "-E" "Log to stderr rather than syslog (x-ssh has no syslog: in the background its log goes nowhere)")
            (Opts arg "-P" "pidfile" "Create pid file PidFile, default /var/run/dropbear.pid")
            (Opts flag "-s" "Disable password logins (x-ssh has none)")
            %version-row))
    (%row (lit client) (list "dbclient" "ssh") "the client"
      "[options] [user@]host[/port] [command]"
      (list (Opts arg "-p" "port" "Remote port")
            (Opts arg "-i" "keyfile" "The ssh-ed25519 key to authenticate with (OpenSSH format)")
            (Opts arg "-l" "user" "The user to log in as")
            (Opts flag "-y" "Accept and record the key of a host not in known_hosts")
            (Opts flag "-v" "Trace the connection on standard error")
            %version-row))
    (%row (lit keygen) (list "dropbearkey" "ssh-keygen") "the key generator"
      "-t type -f filename [-s bits]"
      (list (Opts arg "-t" "type" "Type of key to generate: ed25519")
            (Opts arg "-f" "filename" "Use filename for the secret key")
            (Opts arg "-s" "bits" "Key size in bits; ed25519 has a fixed size of 256 bits")
            (Opts flag "-y" "Just print the public key and fingerprint for the private key in filename")
            (Opts arg "-C" "comment" "Specify the key comment")))
    (%row (lit convert) (list "dropbearconvert") "the key converter"
      "<inputtype> <outputtype> <inputfile> <outputfile>" ())
    (%row (lit scp) (list "scp") "secure copy" "[options] [[user@]host1:]file1 [...] [[user@]host2:]file2"
      (list (Opts arg "-P" "port" "Port to connect to on the remote host")
            (Opts arg "-i" "identity_file" "The key to authenticate with, passed to the ssh program")
            (Opts arg "-S" "program" "The program to connect with, default ssh")
            (Opts flag "-p" "Preserve modification times")
            (Opts flag "-r" "Copy directories recursively")
            (Opts flag "-q" "Quiet: no progress meter (x-ssh has none)")
            (Opts flag "-v" "Verbose")
            (Opts hidden (Opts flag "-d" "The target must be a directory (the remote end)"))
            (Opts hidden (Opts flag "-t" "Receive files (the remote end)"))
            (Opts hidden (Opts flag "-f" "Send files (the remote end)"))))))

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
      ((eq? (first p) (lit keygen)) (%keygen-plan o decl))
      ((eq? (first p) (lit server)) (%server-plan o))
      ((eq? (first p) (lit scp)) (%scp-plan o decl))
      (#t (%convert-plan o decl)))))

; dropbearconvert's line as what to do: (convert (convert IN-TYPE OUT-TYPE
; IN-FILE OUT-FILE) 0), or what Dropbear says of a bad line, status 1.
(def %convert-plan
  (fn (_ o decl)
    (def ops (Opts operands o))
    (def %type? (fn (_ t) (if (str=? t "openssh") #t (str=? t "dropbear"))))
    (match
      ((not (= (List length ops) 4))
        (list (lit convert) (Str8 append "All arguments must be specified\n" (Opts usage decl)) 1))
      ((not (%type? (first ops)))
        (list (lit convert) (Str8 append "Invalid input key type\n" (Opts usage decl)) 1))
      ((not (%type? (List ref 1 ops)))
        (list (lit convert) (Str8 append "Invalid output key type\n" (Opts usage decl)) 1))
      (#t (list (lit convert) (pair (lit convert) ops) 0)))))

; scp's line as what to do: (scp (to OPERANDS PRESERVE RECURSIVE) 0) or
; (scp (from OPERANDS PRESERVE RECURSIVE) 0) for the remote ends, (scp
; (copy OPERANDS PROGRAM PORT KEY PRESERVE RECURSIVE) 0) for a client, or
; what it says and its status.
(def %scp-plan
  (fn (_ o decl)
    (def ops (Opts operands o))
    (def preserve (Opts on? o "-p"))
    (def recursive (Opts on? o "-r"))
    (match
      ((Opts on? o "-t") (list (lit scp) (list (lit to) ops preserve recursive) 0))
      ((Opts on? o "-f") (list (lit scp) (list (lit from) ops preserve recursive) 0))
      ((< (List length ops) 2) (list (lit scp) (Opts usage decl) 1))
      (#t (list (lit scp)
                (list (lit copy) ops
                      (if (Opts on? o "-S") (Opts value o "-S") "ssh")
                      (if (Opts on? o "-P") (Opts value o "-P") ())
                      (if (Opts on? o "-i") (Opts value o "-i") ())
                      preserve recursive)
                0)))))

; The server's line as what to do: (server (serve KEYFILE ADDRESS PORT DIR
; MAKE-KEY BACKGROUND PIDFILE) 0), the address () for every one, the key
; and pidfile Dropbear's defaults unless given.
(def %server-plan
  (fn (_ o)
    (def key (if (Opts on? o "-r") (Opts value o "-r") "/etc/dropbear/dropbear_ed25519_host_key"))
    (def pidfile (if (Opts on? o "-P") (Opts value o "-P") "/var/run/dropbear.pid"))
    (def p (if (Opts on? o "-p") (Opts value o "-p") "22"))
    (def colon ((fn (self i) (if (< i 0) () (if (= ((prim-ref (lit str) (lit byte-ref)) p i) #\:) i (self (- i 1)))))
                (- (Str8 length p) 1)))
    (def addr (if (null? colon) () (Str8 sub 0 colon p)))
    (def port (%int-or-nil (if (null? colon) p (Str8 sub (+ colon 1) (- (Str8 length p) colon 1) p))))
    (def dir (if (Opts on? o "-D") (Opts value o "-D") (Str8 append (Sys getenv "HOME") "/.ssh")))
    (match
      ((null? port) (list (lit server) (Str8 append "Bad port '" p "'\n") 1))
      (#t (list (lit server)
                (list (lit serve) key addr port dir (Opts on? o "-R") (not (Opts on? o "-F")) pidfile)
                0)))))

; The key generator's line as what to do, in dropbearkey's order of
; checks: (keygen (generate FILE COMMENT) 0) or (keygen (print FILE
; COMMENT) 0), or what it says and its status.  The type defaults to
; ed25519, as Dropbear's does.
(def %keygen-plan
  (fn (_ o decl)
    (def file (if (Opts on? o "-f") (Opts value o "-f") ()))
    (def type (if (Opts on? o "-t") (Opts value o "-t") "ed25519"))
    (def comment (if (Opts on? o "-C") (Opts value o "-C") ()))
    (def bits (if (Opts on? o "-s") (%int-or-nil (Opts value o "-s")) 256))
    (match
      ((null? file) (list (lit keygen) (Str8 append "Must specify a key filename\n" (Opts usage decl)) 1))
      ((Opts on? o "-y") (list (lit keygen) (list (lit print) file comment) 0))
      ((List any? (fn (_ t) (str=? t type)) (list "rsa" "dss" "ecdsa"))
        (list (lit keygen) (Str8 append "x-ssh: key type '" type "' is not served yet\n") 1))
      ((not (str=? type "ed25519"))
        (list (lit keygen) (Str8 append "Unknown key type '" type "'\n" (Opts usage decl)) 1))
      ((null? bits) (list (lit keygen) "Bits must be an integer\n" 1))
      ((not (= bits 256)) (list (lit keygen) "Ed25519 keys have a fixed size of 256 bits\n" 1))
      (#t (list (lit keygen) (list (lit generate) file comment) 0)))))

; A decimal's value, or () when the text is not all digits.
(def %int-or-nil
  (fn (_ t)
    (def n (Str8 length t))
    (def digit?
      (fn (_ i)
        (def c ((prim-ref (lit str) (lit byte-ref)) t i))
        (if (>= c #\0) (<= c #\9) #f)))
    (if (if (> n 0) ((fn (self i) (if (= i n) #t (if (digit? i) (self (+ i 1)) #f))) 0) #f)
      (%int t)
      ())))

; The client's line as what to do: (client (exec HOST PORT USER KEY COMMAND
; TRACE ACCEPT) 0), the host operand's [user@]host[/port] split, -l and -p
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
      (#t (list (lit client) (list (lit exec) host port user key command (Opts on? o "-v") (Opts on? o "-y")) 0)))))

(def %int (fn (_ t) ((prim-ref (lit convert) (lit to)) t (Type named INTEGER) 10)))

; A plan done: text to standard error and the status, or what it names
; run -- the client's exec, or the key generator's generate or print.
(def ssh-main
  (fn (_ ops)
    (def plan (ssh-plan ops))
    (def what (first (rest plan)))
    (if (pair? what)
      (Sys exit
        (match
          ((eq? (first what) (lit exec))
            (ssh-client-run (List ref 1 what) (List ref 2 what) (List ref 3 what)
                            (List ref 4 what) (List ref 5 what) (List ref 6 what) (List ref 7 what)))
          ((eq? (first what) (lit generate)) (ssh-keygen-generate (List ref 1 what) (List ref 2 what)))
          ((eq? (first what) (lit to)) (ssh-scp-remote #t (List ref 1 what) (List ref 2 what) (List ref 3 what)))
          ((eq? (first what) (lit from)) (ssh-scp-remote #f (List ref 1 what) (List ref 2 what) (List ref 3 what)))
          ((eq? (first what) (lit copy))
            (ssh-scp-client (List ref 1 what) (List ref 2 what) (List ref 3 what) (List ref 4 what)
                            (List ref 5 what) (List ref 6 what)))
          ((eq? (first what) (lit serve))
            (ssh-serve (List ref 1 what) (List ref 2 what) (List ref 3 what) (List ref 4 what)
                       (List ref 5 what) (List ref 6 what) (List ref 7 what)))
          ((eq? (first what) (lit convert))
            (ssh-convert (List ref 1 what) (List ref 2 what) (List ref 3 what) (List ref 4 what)))
          (#t (ssh-keygen-print (List ref 1 what) (List ref 2 what)))))
      (do (File write 2 what (%byte-len what))
          (Sys exit (first (rest (rest plan))))))))

(provide ssh/cli ssh-programs ssh-program ssh-plan ssh-main)
