# dropbear, the server
# @weight 2

The server's line as what to do.  Serving -- the key exchange from the
server's end, publickey authentication against authorized_keys, a
command on three pipes, the host key made under -R and the background --
is proven live by tests/oracle/server.sh, with Dropbear's client,
OpenSSH's and git as the oracles.

## the line

### the host key, the address and port, and the authorized_keys directory

```ssh
(write (first (rest (ssh-plan (list "dropbear" "-F" "-E" "-r" "hk" "-p" "127.0.0.1:2222" "-D" "/keys")))))
```
---
    ('serve "hk" "127.0.0.1" 2222 "/keys" #f #f "/var/run/dropbear.pid")

### a bare port listens on every address

```ssh
(write (List ref 2 (first (rest (ssh-plan (list "dropbear" "-r" "hk" "-p" "2222"))))))
```
---
    ()

### Dropbear's defaults: the key's path, the background, the pidfile; -R makes the key

```ssh
(write (first (rest (ssh-plan (list "dropbear" "-R" "-P" "/run/x.pid" "-D" "/keys")))))
```
---
    ('serve "/etc/dropbear/dropbear_ed25519_host_key" () 22 "/keys" #t #t "/run/x.pid")

### a port that is no number is refused

```ssh
(write (ssh-plan (list "dropbear" "-r" "hk" "-p" "ssh")))
```
---
    ('server "Bad port 'ssh'\n" 1)
