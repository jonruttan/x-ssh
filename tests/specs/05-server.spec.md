# dropbear, the server
# @weight 2

The server's line as what to do.  Serving -- the key exchange from the
server's end, publickey authentication against authorized_keys, and a
command on three pipes -- is proven live by tests/oracle/server.sh, with
Dropbear's client, OpenSSH's and git as the oracles.

## the line

### the host key, the address and port, and the authorized_keys directory

```ssh
(write (first (rest (ssh-plan (list "dropbear" "-F" "-E" "-r" "hk" "-p" "127.0.0.1:2222" "-D" "/keys")))))
```
---
    ('serve "hk" "127.0.0.1" 2222 "/keys")

### a bare port listens on every address

```ssh
(write (List ref 2 (first (rest (ssh-plan (list "dropbear" "-r" "hk" "-p" "2222"))))))
```
---
    ()

### no host key, and a port that is no number, are refused

```ssh
(write (list (ssh-plan (list "dropbear" "-p" "2222"))
             (ssh-plan (list "dropbear" "-r" "hk" "-p" "ssh"))))
```
---
    (('server "x-ssh: -r keyfile is required; no default host keys yet\n" 1) ('server "Bad port 'ssh'\n" 1))
