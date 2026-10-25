; # x-ssh -- SSH on x-lang
;
; ## ssh/cli.x -- the command line
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; x -l ssh -- PROGRAM [ARGS] runs PROGRAM: the server, the client, the key
; generator or scp, each by OpenSSH's name and with OpenSSH's options.
; Each program's options are declared once, in ssh-programs: the
; declaration is what --help prints and what its line is parsed against.
; ssh-plan turns a line into what to do, with no side effects; ssh-main
; does it.  The client's and server's flags become the configuration
; lines they stand for, ahead of -o's and the files', so one reader
; settles them all.

(module ssh/cli)

(import x/sys/opts Opts)
(import x/sys/file File)
(import ssh/client ssh-client-main)
(import ssh/keygen ssh-keygen-main)
(import ssh/server ssh-server-main)
(import ssh/scp ssh-scp-client ssh-scp-remote)
(import ssh/sftp ssh-sftp-main)
(import ssh/sftp-client ssh-sftp-client ssh-sftp-destination)

(def %byte-len (prim-ref (lit str) (lit byte-len)))
(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %cvt (prim-ref (lit convert) (lit to)))

(def %version-row (Opts flag "-V" "Print the version"))

; One row a program: (LABEL NAME WHAT DECLARATION).
(def %row
  (fn (_ label name what synopsis rows)
    (list label name what (Opts declare name synopsis () rows))))

(def ssh-programs
  (list
    (%row (lit server) "sshd" "the server" "[options]"
      (list (Opts flag "-D" "Do not detach and become a daemon")
            (Opts flag "-d" "Debug mode: one connection, not forked, the log on standard error")
            (Opts flag "-e" "Write the log to standard error instead of the system log")
            (Opts arg "-E" "log_file" "Append the log to log_file instead of the system log")
            (Opts arg "-f" "config_file" "The configuration file, default /etc/ssh/sshd_config")
            (Opts arg "-h" "host_key_file" "A host key file, read before the configuration's")
            (Opts arg "-o" "option" "An option in the configuration file's form, before the file's")
            (Opts arg "-p" "port" "Listen on port, in place of the configuration's")
            (Opts flag "-q" "Quiet: nothing is logged")
            (Opts flag "-t" "Test the configuration and the host keys")
            (Opts flag "-T" "Test the configuration and print the settings in force")
            %version-row))
    (%row (lit client) "ssh" "the client" "[options] destination [command]"
      (list (Opts flag "-C" "Ask for compression (none is served)")
            (Opts arg "-F" "configfile" "The user configuration file, default ~/.ssh/config")
            (Opts flag "-G" "Print the configuration in force for destination and exit")
            (Opts flag "-g" "Allow remote hosts to connect to local forwarded ports")
            (Opts arg "-i" "identity_file" "A key to authenticate with, before the configuration's")
            (Opts arg "-L" "address" "Local forwarding: [bind_address:]port:host:hostport")
            (Opts arg "-l" "login_name" "The user to log in as")
            (Opts flag "-N" "Do not run a remote command")
            (Opts flag "-n" "Read standard input from /dev/null")
            (Opts arg "-o" "option" "An option in the configuration file's form, before the files'")
            (Opts arg "-p" "port" "The port to connect to")
            (Opts flag "-q" "Quiet: warnings and diagnostics suppressed")
            (Opts arg "-R" "address" "Remote forwarding: [bind_address:]port:host:hostport")
            (Opts flag "-s" "Ask for a subsystem, the command naming it, as SessionType subsystem")
            (Opts flag "-T" "Do not ask for a terminal")
            (Opts flag "-t" "Ask for a terminal, as RequestTTY yes: for a command too, when standard input is one")
            (Opts flag "-v" "Verbose: trace the connection on standard error")
            (Opts arg "-W" "host:port" "Carry standard input and output to host:port through the server")
            (Opts flag "-x" "Disable X11 forwarding (none is served)")
            %version-row))
    (%row (lit keygen) "ssh-keygen" "the key tool" "[options]"
      (list (Opts flag "-A" "Make each missing host key in /etc/ssh, or under -f's prefix")
            (Opts arg "-a" "rounds" "Rounds of bcrypt-pbkdf sealing a key under a passphrase (default 16)")
            (Opts arg "-b" "bits" "Key size in bits; an ed25519 key's is fixed")
            (Opts arg "-C" "comment" "The key's comment")
            (Opts arg "-F" "hostname" "Find hostname in known_hosts")
            (Opts arg "-f" "filename" "The key file")
            (Opts flag "-l" "Show the key's fingerprint")
            (Opts arg "-N" "new_passphrase" "The new passphrase")
            (Opts arg "-P" "passphrase" "The old passphrase")
            (Opts flag "-p" "Change the passphrase, rewriting the file in OpenSSH's format")
            (Opts flag "-q" "Quiet")
            (Opts arg "-R" "hostname" "Remove hostname's keys from known_hosts")
            (Opts arg "-t" "type" "The type of key to make: ed25519")
            (Opts flag "-v" "Verbose: with -l, the key's randomart too")
            (Opts flag "-y" "Print the public key of a private key file")))
    (%row (lit scp) "scp" "secure copy" "[options] source ... target"
      (list (Opts arg "-F" "ssh_config" "The configuration file, passed to ssh")
            (Opts arg "-i" "identity_file" "The key to authenticate with, passed to ssh")
            (Opts flag "-O" "The original scp protocol, in place of SFTP")
            (Opts arg "-o" "ssh_option" "An option passed to ssh")
            (Opts arg "-P" "port" "The port to connect to on the remote host")
            (Opts flag "-p" "Preserve modification times")
            (Opts flag "-q" "Quiet: no progress meter (x-ssh has none)")
            (Opts flag "-r" "Copy directories recursively")
            (Opts arg "-S" "program" "The program to connect with, default ssh")
            (Opts flag "-s" "The SFTP protocol, the default")
            (Opts flag "-v" "Verbose, passed to ssh")
            (Opts hidden (Opts flag "-d" "The target must be a directory (the remote end)"))
            (Opts hidden (Opts flag "-t" "Receive files (the remote end)"))
            (Opts hidden (Opts flag "-f" "Send files (the remote end)"))))
    (%row (lit sftp) "sftp" "secure file transfer" "[options] destination"
      (list (Opts arg "-B" "buffer_size" "Bytes a read or write asks for (default 32768)")
            (Opts arg "-b" "batchfile" "Commands from batchfile, - for standard input; a failure ends it")
            (Opts arg "-D" "sftp_server_command" "Run this command as the server, in place of ssh")
            (Opts arg "-F" "ssh_config" "The configuration file, passed to ssh")
            (Opts arg "-i" "identity_file" "The key to authenticate with, passed to ssh")
            (Opts arg "-o" "ssh_option" "An option passed to ssh")
            (Opts arg "-P" "port" "The port to connect to on the remote host")
            (Opts flag "-p" "Preserve modification times, access times and modes")
            (Opts flag "-q" "Quiet: no progress meter (x-ssh has none)")
            (Opts arg "-R" "num_requests" "Requests in flight a transfer keeps (default 64)")
            (Opts flag "-r" "Copy directories recursively")
            (Opts arg "-S" "program" "The program to connect with, default ssh")
            (Opts arg "-s" "subsystem" "The subsystem asked for, default sftp")
            (Opts flag "-v" "Verbose, passed to ssh")))
    (%row (lit sftp-server) "sftp-server" "the SFTP server" "[options]"
      (list (Opts arg "-d" "start_directory" "The directory to start in: %d the home directory, %u the user")
            (Opts flag "-e" "Log to standard error (nothing is logged)")
            (Opts arg "-f" "log_facility" "The syslog facility (nothing is logged)")
            (Opts arg "-l" "log_level" "The log level (nothing is logged)")
            (Opts flag "-R" "Read-only: every request that would change a file is refused")))))

; The program row a name answers to, or ().
(def ssh-program
  (fn (_ name) (List find (fn (_ p) (str=? (first (rest p)) name)) ssh-programs)))

(def %programs
  (fn (_)
    (Str8 join "\n"
      (List append
        (list (Str8 append "x-ssh v" ssh-version)
              "Run 'x -l ssh -- <program>' with one of these programs:")
        (List map (fn (_ p) (Str8 append "'" (first (rest p)) "' - " (first (rest (rest p))))) ssh-programs)
        (list "")))))

; A line to (PROGRAM WHAT STATUS): the program's label (() for none), and
; what to do -- a list naming it -- or the text to print with the status.
(def ssh-plan
  (fn (_ ops)
    (def p (if (null? ops) () (ssh-program (first ops))))
    (def decl (if (null? p) () (List ref 3 p)))
    (def o (if (null? p) () (Opts parse decl (rest ops))))
    (match
      ((null? p) (list () (%programs) 1))
      ((Opts help? decl (rest ops)) (list (first p) (Opts usage decl) 0))
      ((not (null? (Opts unknown o)))
        (list (first p) (Str8 append "Invalid option " (Opts unknown o) "\n" (Opts usage decl)) 1))
      ((Opts on? o "-V") (list (first p) (Str8 append "x-ssh v" ssh-version "\n") 0))
      ((eq? (first p) (lit client)) (%client-plan o decl))
      ((eq? (first p) (lit keygen)) (%keygen-plan o decl))
      ((eq? (first p) (lit server)) (%server-plan o decl))
      ((eq? (first p) (lit sftp)) (%sftp-plan o decl))
      ((eq? (first p) (lit sftp-server))
        (if (null? (Opts operands o))
          (list (lit sftp-server) (list (lit serve) (%value o "-d") (Opts on? o "-R")) 0)
          (list (lit sftp-server) (Opts usage decl) 1)))
      (#t (%scp-plan o decl)))))

(def %value (fn (_ o flag) (if (Opts on? o flag) (Opts value o flag) ())))

; The server's line: (server (serve CONFIG OPTIONS MODE) 0).  OPTIONS are
; configuration lines, -q's and -d's log level, -o's, -h's host keys and
; -p's ports, ahead of the file's; MODE is (FOREGROUND DEBUG STDERR
; LOGFILE TEST PRINT).
(def %server-plan
  (fn (_ o decl)
    (def debug (Opts on? o "-d"))
    (if (not (null? (Opts operands o)))
      (list (lit server) (Str8 append "Extra argument " (first (Opts operands o)) ".\n" (Opts usage decl)) 1)
      (list (lit server)
            (list (lit serve)
                  (if (Opts on? o "-f") (Opts value o "-f") "/etc/ssh/sshd_config")
                  (List append
                    (if (Opts on? o "-q") (list "LogLevel QUIET") ())
                    (if debug (list "LogLevel DEBUG1") ())
                    (Opts values o "-o")
                    (List map (fn (_ h) (Str8 append "HostKey \"" h "\"")) (Opts values o "-h"))
                    (List map (fn (_ p) (Str8 append "Port " p)) (Opts values o "-p")))
                  (list (if debug #t (Opts on? o "-D")) debug (if debug #t (Opts on? o "-e")) (%value o "-E")
                        (Opts on? o "-t") (Opts on? o "-T")))
            0))))

; A destination, [user@]host or ssh://[user@]host[:port], as (USER HOST
; PORT), the absent parts ().
(def ssh-destination
  (fn (_ d)
    (def url (if (> (Str8 length d) 6) (str=? (Str8 sub 0 6 d) "ssh://") #f))
    (def rest-of (fn (_ s i) (Str8 sub i (- (Str8 length s) i) s)))
    (def s (if url (rest-of d 6) d))
    (def at ((fn (self i) (if (< i 0) () (if (= (%byte-ref s i) #\@) i (self (- i 1))))) (- (Str8 length s) 1)))
    (def user (if (null? at) () (Str8 sub 0 at s)))
    (def hp (if (null? at) s (rest-of s (+ at 1))))
    (def colon (if url (Str8 index-of ":" hp) ()))
    (list user (if (null? colon) hp (Str8 sub 0 colon hp)) (if (null? colon) () (rest-of hp (+ colon 1))))))

; The client's line: (client (exec HOST COMMAND OPTIONS CONFIG STDIO
; PRINT) 0), OPTIONS the configuration lines its flags stand for, then
; -o's, then the destination's user and port; COMMAND () for none; STDIO
; -W's host:port or ().
(def %client-plan
  (fn (_ o decl)
    (def ops (Opts operands o))
    (def q (fn (_ s) (Str8 append "\"" s "\"")))
    (if (null? ops)
      (list (lit client) (Opts usage decl) 255)
      (do (def dest (ssh-destination (first ops)))
          (list (lit client)
                (list (lit exec) (List ref 1 dest)
                      (if (null? (rest ops)) () (Str8 join " " (rest ops)))
                      (List append
                        (if (Opts on? o "-l") (list (Str8 append "User " (q (Opts value o "-l")))) ())
                        (if (Opts on? o "-p") (list (Str8 append "Port " (Opts value o "-p"))) ())
                        (List map (fn (_ i) (Str8 append "IdentityFile " (q i))) (Opts values o "-i"))
                        (List map (fn (_ f) (Str8 append "LocalForward " f)) (Opts values o "-L"))
                        (List map (fn (_ f) (Str8 append "RemoteForward " f)) (Opts values o "-R"))
                        (if (Opts on? o "-g") (list "GatewayPorts yes") ())
                        (if (Opts on? o "-N") (list "SessionType none") ())
                        (if (Opts on? o "-s") (list "SessionType subsystem") ())
                        (if (Opts on? o "-n") (list "StdinNull yes") ())
                        (if (Opts on? o "-t") (list "RequestTTY yes") ())
                        (if (Opts on? o "-T") (list "RequestTTY no") ())
                        (if (Opts on? o "-x") (list "ForwardX11 no") ())
                        (if (Opts on? o "-C") (list "Compression yes") ())
                        (if (Opts on? o "-q") (list "LogLevel QUIET") ())
                        (if (Opts on? o "-v") (list "LogLevel DEBUG1") ())
                        (Opts values o "-o")
                        (if (null? (first dest)) () (list (Str8 append "User " (q (first dest)))))
                        (if (null? (List ref 2 dest)) () (list (Str8 append "Port " (List ref 2 dest)))))
                      (%value o "-F")
                      (%value o "-W")
                      (Opts on? o "-G"))
                0)))))

; A count's digits as a number: () when they are not all digits.
(def %count
  (fn (_ a)
    (def n (Str8 length a))
    (def digits? ((fn (self i) (if (= i n) (> n 0) (if (if (>= (%byte-ref a i) #\0) (<= (%byte-ref a i) #\9) #f) (self (+ i 1)) #f))) 0))
    (if digits? (%cvt a (Type named INTEGER) 10) ())))

; The key tool's line, as what to do: (keygen (ACTION ...) 0), the file
; () when none is named, for the tool to ask.  A key made is ed25519's,
; ecdsa's on -b 256, the default, 384 or 521, or rsa's of -b 1024 to
; 16384 bits, 3072 by default, as OpenSSH's ssh-keygen allows them.
(def %keygen-plan
  (fn (_ o decl)
    (def file (%value o "-f"))
    (def type (if (Opts on? o "-t") (Str8 downcase (Opts value o "-t")) "ed25519"))
    (def plan (fn (_ what) (list (lit keygen) what 0)))
    (def a (%value o "-a"))
    (def rounds (if (null? a) 16 (%count a)))
    (def b (%value o "-b"))
    (def bits (match ((str=? type "ed25519") 256) ((not (null? b)) (%count b)) ((str=? type "rsa") 3072) (#t 256)))
    (match
      ((null? rounds) (list (lit keygen) (Str8 append "Invalid number: " a " (invalid)\n") 255))
      ((< rounds 1) (list (lit keygen) (Str8 append "Invalid number: " a " (too small)\n") 255))
      ((Opts on? o "-A") (plan (list (lit hosts) file)))
      ((Opts on? o "-R") (plan (list (lit remove) (Opts value o "-R") file)))
      ((Opts on? o "-F") (plan (list (lit find) (Opts value o "-F") file)))
      ((Opts on? o "-y") (plan (list (lit public) file (%value o "-P"))))
      ((Opts on? o "-l") (plan (list (lit fingerprint) file (Opts on? o "-v"))))
      ((Opts on? o "-p") (plan (list (lit passphrase) file (%value o "-P") (%value o "-N") rounds)))
      ((List any? (fn (_ t) (str=? t type)) (list "dsa" "ecdsa-sk" "ed25519-sk"))
        (list (lit keygen) (Str8 append "x-ssh: key type " type " is not served yet\n") 1))
      ((not (List any? (fn (_ t) (str=? t type)) (list "ed25519" "ecdsa" "rsa")))
        (list (lit keygen) (Str8 append "unknown key type " type "\n") 1))
      ((null? bits) (list (lit keygen) (Str8 append "Bits has bad value " b " (invalid)\r\n") 255))
      ((if (str=? type "rsa") (< bits 1024) #f) (list (lit keygen) "Invalid RSA key length: minimum is 1024 bits\r\n" 255))
      ((if (str=? type "rsa") (> bits 16384) #f) (list (lit keygen) "Invalid RSA key length: maximum is 16384 bits\r\n" 255))
      ((if (str=? type "ecdsa") (not (List any? (fn (_ n) (= n bits)) (list 256 384 521))) #f)
        (list (lit keygen) "Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits\r\n" 255))
      (#t (plan (list (lit generate) file (%value o "-C") (%value o "-N") (Opts on? o "-q") rounds type bits))))))

; sftp's line: (sftp (client ARGV PATH BATCH (PRESERVE RECURSIVE QUIET) BUFFER
; REQUESTS) 0), ARGV the ssh program's -- OpenSSH's set first, then what
; is passed on, -s and the host and subsystem -- or -D's command under
; /bin/sh; or what it says and its status.
(def %sftp-plan
  (fn (_ o decl)
    (def ops (Opts operands o))
    (def count (fn (_ flag default) (if (Opts on? o flag) (%count (Opts value o flag)) default)))
    (def buffer (count "-B" 32768))
    (def requests (count "-R" 64))
    (def dest (if (null? ops) () (ssh-sftp-destination (first ops))))
    (match
      ((> (List length ops) 1) (list (lit sftp) (Opts usage decl) 1))
      ((if (null? dest) (not (Opts on? o "-D")) #f) (list (lit sftp) (Opts usage decl) 1))
      ((if (null? buffer) #t (< buffer 1)) (list (lit sftp) (Str8 append "Invalid buffer size \"" (Opts value o "-B") "\"\n") 1))
      ((if (null? requests) #t (< requests 1)) (list (lit sftp) (Str8 append "Invalid number of requests \"" (Opts value o "-R") "\"\n") 1))
      (#t
        (list (lit sftp)
          (list (lit client)
                (if (Opts on? o "-D")
                  (list "/bin/sh" "-c" (Opts value o "-D"))
                  (List append
                    (list (if (Opts on? o "-S") (Opts value o "-S") "ssh")
                          "-x" "-oPermitLocalCommand=no" "-oClearAllForwardings=yes" "-oForwardAgent=no")
                    (if (Opts on? o "-v") (list "-v") ())
                    (if (Opts on? o "-F") (list "-F" (Opts value o "-F")) ())
                    (List flat-map (fn (_ v) (list "-o" v)) (Opts values o "-o"))
                    (if (Opts on? o "-P") (list "-p" (Opts value o "-P")) (if (null? (List ref 2 dest)) () (list "-p" (List ref 2 dest))))
                    (if (Opts on? o "-i") (list "-i" (Opts value o "-i")) ())
                    (if (null? (first dest)) () (list "-l" (first dest)))
                    (list "-s" "--" (List ref 1 dest) (if (Opts on? o "-s") (Opts value o "-s") "sftp"))))
                (if (null? dest) () (List ref 3 dest))
                (if (Opts on? o "-b") (Opts value o "-b") ())
                (list (Opts on? o "-p") (Opts on? o "-r") (Opts on? o "-q"))
                buffer requests)
          0)))))

; scp's line: (scp (to OPERANDS PRESERVE RECURSIVE) 0) or (scp (from
; OPERANDS PRESERVE RECURSIVE) 0) for the remote ends, (scp (copy
; OPERANDS PROGRAM ARGS PRESERVE RECURSIVE SFTP) 0) for a client, ARGS what
; the ssh program is given before the host, or what it says and its
; status.  SFTP is OpenSSH's default; -O is the original protocol.
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
                      (List append
                        (list "-x" "-oPermitLocalCommand=no" "-oClearAllForwardings=yes" "-oRemoteCommand=none"
                              "-oRequestTTY=no" "-oForwardAgent=no")
                        (if (Opts on? o "-v") (list "-v") ())
                        (if (Opts on? o "-F") (list "-F" (Opts value o "-F")) ())
                        (List flat-map (fn (_ v) (list "-o" v)) (Opts values o "-o"))
                        (if (Opts on? o "-P") (list "-p" (Opts value o "-P")) ())
                        (if (Opts on? o "-i") (list "-i" (Opts value o "-i")) ()))
                      preserve recursive (if (Opts on? o "-s") #t (not (Opts on? o "-O"))))
                0)))))

; A plan done: text to standard error and the status, or what it names
; run.
(def ssh-main
  (fn (_ ops)
    (def plan (ssh-plan ops))
    (def what (first (rest plan)))
    (if (pair? what)
      (Sys exit
        (match
          ((eq? (first plan) (lit client)) (ssh-client-main (rest what)))
          ((eq? (first plan) (lit server)) (ssh-server-main (rest what)))
          ((eq? (first plan) (lit keygen)) (ssh-keygen-main what))
          ; sftp-server's requests on standard input, which the platform keeps on fd 3
          ((eq? (first plan) (lit sftp-server)) (ssh-sftp-main (List ref 1 what) (List ref 2 what) 3 1))
          ((eq? (first plan) (lit sftp))
            (ssh-sftp-client (List ref 1 what) (List ref 2 what) (List ref 3 what) (List ref 4 what) (List ref 5 what) (List ref 6 what)))
          ((eq? (first what) (lit to)) (ssh-scp-remote #t (List ref 1 what) (List ref 2 what) (List ref 3 what)))
          ((eq? (first what) (lit from)) (ssh-scp-remote #f (List ref 1 what) (List ref 2 what) (List ref 3 what)))
          (#t (ssh-scp-client (List ref 1 what) (List ref 2 what) (List ref 3 what) (List ref 4 what) (List ref 5 what) (List ref 6 what)))))
      (do (File write 2 what (%byte-len what))
          (Sys exit (first (rest (rest plan))))))))

(provide ssh/cli ssh-programs ssh-program ssh-plan ssh-main ssh-destination)
