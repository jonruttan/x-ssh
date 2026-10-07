# @weight 1

The command line.  As Dropbear's multi-purpose binary, the first operand
names the program; ssh-plan turns a line into (PROGRAM TEXT STATUS)
without doing it.

## programs

### Dropbear's names, and their aliases

```ssh
(display (List map (fn (_ n) (ssh-program n))
  (list "dropbear" "dbclient" "ssh" "dropbearkey" "ssh-keygen" "dropbearconvert" "scp" "sshd")))
```
---
    (server client client keygen keygen convert scp ())

## plan

### no program lists the programs, status 1

```ssh
(display (List map (fn (_ l) (first (rest (rest (ssh-plan l))))) (list () (list "sshd"))))
```
---
    (1 1)

### -V names the version, status 0

```ssh
(display (ssh-plan (list "dbclient" "-V")))
```
---
```output
(client x-ssh v0.1.0
 0)
```

### a program not written yet says so, status 1

```ssh
(display (ssh-plan (list "dropbear" "-F")))
```
---
```output
(server dropbear: not served yet
 1)
```

## argv

### the launcher's flags and the -- are dropped

```ssh
(display (ssh-argv (list "run.x" "--batch" "--" "dbclient" "-V")))
```
---
    (dbclient -V)
