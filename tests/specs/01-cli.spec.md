# @weight 1

The command line.  The first operand names the program, by OpenSSH's
name.  Each program's options are one declaration: what --help prints
and what its line is parsed against.  ssh-plan turns a line into
(PROGRAM WHAT STATUS) without doing it.

## programs

### OpenSSH's names

```ssh
(write (List map (fn (_ n) (if (null? (ssh-program n)) () (first (ssh-program n))))
  (list "sshd" "ssh" "ssh-keygen" "scp" "sftp-server" "dropbear" "dbclient")))
```
---
    ('server 'client 'keygen 'scp 'sftp () ())

### no program lists the programs, status 1

```ssh
(display (first (rest (ssh-plan ()))))
```
---
```output
x-ssh v0.1.0
Run 'x -l ssh -- <program>' with one of these programs:
'sshd' - the server
'ssh' - the client
'ssh-keygen' - the key tool
'scp' - secure copy
'sftp-server' - the SFTP server
```

### an unknown program lists them too

```ssh
(write (List map (fn (_ l) (first (rest (rest (ssh-plan l))))) (list () (list "dropbear"))))
```
---
    (1 1)

## plan

### --help prints the program's declaration, status 0

```ssh
(def %hp (ssh-plan (list "ssh" "--help")))
(write (list (first (Str8 split "\n" (first (rest %hp)))) (first (rest (rest %hp)))))
```
---
    ("Usage: ssh [options] destination [command]" 0)

### -V names the version, status 0

```ssh
(write (ssh-plan (list "ssh" "-V")))
```
---
    ('client "x-ssh v0.1.0\n" 0)

### an option the program does not declare is refused, status 1

```ssh
(def %sp (ssh-plan (list "sshd" "-Q")))
(write (list (first %sp) (Str8 sub 0 17 (first (rest %sp))) (first (rest (rest %sp)))))
```
---
    ('server "Invalid option -Q" 1)

## the client

### its flags become the configuration lines they stand for, then -o's, then the destination's

```ssh
(write (first (rest (ssh-plan (list "ssh" "-p" "2222" "-i" "k" "-l" "me" "-N" "-g" "-L" "8080:h:80" "-R" "9:h:9"
                                    "-o" "ServerAliveInterval=5" "-v" "you@host")))))
```
---
    ('exec "host" () ("User \"me\"" "Port 2222" "IdentityFile \"k\"" "LocalForward 8080:h:80" "RemoteForward 9:h:9" "GatewayPorts yes" "SessionType none" "LogLevel DEBUG1" "ServerAliveInterval=5" "User \"you\"") () () #f)

### the command is the operands after the destination, joined

```ssh
(write (List take 2 (rest (first (rest (ssh-plan (list "ssh" "host" "echo" "hi" "there")))))))
```
---
    ("host" "echo hi there")

### an ssh:// destination carries its user and port; -W, -F and -G ride along

```ssh
(write (first (rest (ssh-plan (list "ssh" "-F" "none" "-W" "git.example:9418" "-G" "ssh://git@example.org:2200")))))
```
---
    ('exec "example.org" () ("User \"git\"" "Port 2200") "none" "git.example:9418" #t)

### no destination is the usage, status 255

```ssh
(write (first (rest (rest (ssh-plan (list "ssh" "-v"))))))
```
---
    255

## the server

### its flags become configuration lines ahead of the file's; -d is debug, foreground and standard error

```ssh
(write (first (rest (ssh-plan (list "sshd" "-d" "-f" "/dev/null" "-h" "hk" "-p" "2222" "-o" "PermitRootLogin=yes")))))
```
---
    ('serve "/dev/null" ("LogLevel DEBUG1" "PermitRootLogin=yes" "HostKey \"hk\"" "Port 2222") (#t #t #t () #f #f))

### the defaults: /etc/ssh/sshd_config, detached, syslog; -D -e -E -t -T

```ssh
(write (list (first (rest (ssh-plan (list "sshd"))))
             (List ref 3 (first (rest (ssh-plan (list "sshd" "-D" "-e" "-E" "log" "-t" "-T")))))))
```
---
    (('serve "/etc/ssh/sshd_config" () (#f #f #f () #f #f)) (#t #f #t "log" #t #t))

## scp

### a copy: the operands, the ssh program, and what it is given, OpenSSH's set first

```ssh
(write (ssh-plan (list "scp" "-p" "-P" "2222" "-i" "k" "-o" "BatchMode=yes" "a" "b" "h:dir")))
```
---
    ('scp ('copy ("a" "b" "h:dir") "ssh" ("-x" "-oPermitLocalCommand=no" "-oClearAllForwardings=yes" "-oRemoteCommand=none" "-oRequestTTY=no" "-oForwardAgent=no" "-o" "BatchMode=yes" "-p" "2222" "-i" "k") #t #f) 0)

### -t and -f are the remote ends; -r rides along to either; -s is refused

```ssh
(write (list (first (rest (ssh-plan (list "scp" "-t" "dir")))) (first (rest (ssh-plan (list "scp" "-rf" "a" "b"))))
             (first (rest (rest (ssh-plan (list "scp" "-s" "a" "h:b")))))))
```
---
    (('to ("dir") #f #f) ('from ("a" "b") #f #t) 1)

## sftp-server

### -d's directory and -R; the log's options are taken; an operand is the usage

```ssh
(write (List map (fn (_ l) (def p (ssh-plan (pair "sftp-server" l))) (if (pair? (first (rest p))) (first (rest p)) (first (rest (rest p)))))
  (list () (list "-d" "%d/up" "-R") (list "-e" "-f" "AUTH" "-l" "INFO") (list "extra"))))
```
---
    (('serve () #f) ('serve "%d/up" #t) ('serve () #f) 1)

## main

### what main writes and exits through is bound in its module

main exits the process, so a spec cannot call it; this holds the names it
reaches for, from inside the module, as main sees them.

```ssh
(write (List map (fn (_ s) (not (null? (eval s (module ssh/cli))))) (list (lit File) (lit Sys))))
```
---
    (#t #t)
