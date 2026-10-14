# @weight 1

The command line.  As Dropbear's multi-purpose binary, the first operand
names the program.  Each program's options are one declaration: what
--help prints and what its line is parsed against.  ssh-plan turns a line
into (PROGRAM TEXT STATUS) without doing it.

## programs

### Dropbear's names, and their aliases

```ssh
(write (List map (fn (_ n) (if (null? (ssh-program n)) () (first (ssh-program n))))
  (list "dropbear" "dbclient" "ssh" "dropbearkey" "ssh-keygen" "dropbearconvert" "scp" "sshd")))
```
---
    ('server 'client 'client 'keygen 'keygen 'convert 'scp ())

### no program lists the programs, status 1

```ssh
(display (first (rest (ssh-plan ()))))
```
---
```output
x-ssh multi-purpose v0.1.0
Run 'x -l ssh -- <command>' with one of the following commands.
'dropbear' - the server
'dbclient' or 'ssh' - the client
'dropbearkey' or 'ssh-keygen' - the key generator
'dropbearconvert' - the key converter
'scp' - secure copy
```

### an unknown program lists them too

```ssh
(write (List map (fn (_ l) (first (rest (rest (ssh-plan l))))) (list () (list "sshd"))))
```
---
    (1 1)

## plan

### --help prints the program's declaration, status 0

```ssh
(display (first (rest (ssh-plan (list "dbclient" "--help")))))
```
---
```output
Usage: dbclient [options] [user@]host[/port] [command]

	-p port		Remote port
	-i keyfile	The ssh-ed25519 key to authenticate with (OpenSSH format)
	-l user		The user to log in as
	-y		Accept and record the key of a host not in known_hosts
	-L forward	Local port forwarding: [listenaddress:]listenport:remotehost:remoteport
	-R forward	Remote port forwarding: [listenaddress:]listenport:remotehost:remoteport
	-N		Don't run a remote command
	-g		Allow remote hosts to connect to forwarded ports
	-v		Trace the connection on standard error
	-V		Print the version
```

### -L forwards ride in the plan, -N drops the command; a bad forward is refused, status 1

```ssh
(write (list (first (rest (ssh-plan (list "dbclient" "-i" "k" "-N" "-L" "2222:h:22" "-L" "127.0.0.1:3333:h:80" "me@host"))))
             (List ref 8 (first (rest (ssh-plan (list "dbclient" "-i" "k" "-g" "-L" "2222:h:22" "me@host" "true")))))
             (List take 2 (ssh-plan (list "dbclient" "-i" "k" "-L" "2222:h" "host" "true")))))
```
---
    (('exec "host" 22 "me" "k" () #f #f (("localhost" 2222 "h" 22) ("127.0.0.1" 3333 "h" 80)) ()) ((() 2222 "h" 22)) ('client "Bad TCP forward '2222:h'\n"))

### -V names the version, status 0

```ssh
(write (ssh-plan (list "dbclient" "-V")))
```
---
    ('client "x-ssh v0.1.0\n" 0)

### an option the program does not declare is refused, status 1

```ssh
(def %sp (ssh-plan (list "dropbear" "-Q")))
(write (list (first %sp) (Str8 sub 0 17 (first (rest %sp))) (first (rest (rest %sp)))))
```
---
    ('server "Invalid option -Q" 1)

### scp's line plans a copy: the operands, the ssh program, its port and key

```ssh
(write (ssh-plan (list "scp" "-p" "-P" "2222" "-i" "k" "a" "b" "h:dir")))
```
---
    ('scp ('copy ("a" "b" "h:dir") "ssh" "2222" "k" #t #f) 0)

### -t and -f are the remote ends; -r rides along to either

```ssh
(write (List map (fn (_ l) (first (rest (ssh-plan l))))
  (list (list "scp" "-t" "dir") (list "scp" "-rf" "a" "b") (list "scp" "-r" "d" "h:e"))))
```
---
    (('to ("dir") #f #f) ('from ("a" "b") #f #t) ('copy ("d" "h:e") "ssh" () () #f #t))

### dropbearconvert's line plans a conversion; a bad type says so, status 1

```ssh
(write (list (ssh-plan (list "dropbearconvert" "openssh" "dropbear" "a" "b"))
             (List take 2 (ssh-plan (list "dropbearconvert" "openssh" "pem" "a" "b")))
             (first (rest (rest (ssh-plan (list "dropbearconvert" "openssh" "dropbear" "a")))))))
```
---
    (('convert ('convert "openssh" "dropbear" "a" "b") 0) ('convert "Invalid output key type\nUsage: dropbearconvert <inputtype> <outputtype> <inputfile> <outputfile>\n") 1)

### -R forwards ride in the plan after the -L ones, with the same shape

```ssh
(write (List ref 9 (first (rest (ssh-plan (list "dbclient" "-i" "k" "-N" "-R" "8080:localhost:80" "-R" "0.0.0.0:2222:h:22" "me@host"))))))
```
---
    (("localhost" 8080 "localhost" 80) ("0.0.0.0" 2222 "h" 22))

## main

### what main writes and exits through is bound in its module

main exits the process, so a spec cannot call it; this holds the names it
reaches for, from inside the module, as main sees them.

```ssh
(write (List map (fn (_ s) (not (null? (eval s (module ssh/cli))))) (list (lit File) (lit Sys))))
```
---
    (#t #t)

