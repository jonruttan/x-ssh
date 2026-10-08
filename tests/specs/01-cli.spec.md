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
	-y		Accept the host key without asking
	-v		Trace the connection on standard error
	-V		Print the version
```

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

### a program not written yet says so, status 1

```ssh
(write (ssh-plan (list "scp" "a" "b")))
```
---
    ('scp "scp: not served yet\n" 1)

## main

### what main writes and exits through is bound in its module

main exits the process, so a spec cannot call it; this holds the names it
reaches for, from inside the module, as main sees them.

```ssh
(write (List map (fn (_ s) (not (null? (eval s (module ssh/cli))))) (list (lit File) (lit Sys))))
```
---
    (#t #t)
