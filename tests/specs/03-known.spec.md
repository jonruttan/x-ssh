# known_hosts
# @weight 2

What ssh/known writes and matches: a host's name as OpenSSH and
Dropbear's client spell it, and an Ed25519 key's blob in base64 as
`dropbearkey` writes it in a `.pub` file.  Reading and recording the
file are proven live, by tests/oracle/dropbear.sh.

## names

### port 22 is the bare host, any other is bracketed with its port

```ssh
(import ssh/known ssh-known-name)
(write (list (ssh-known-name "example.org" 22) (ssh-known-name "127.0.0.1" 2222)))
```
---
    ("example.org" "[127.0.0.1]:2222")

## keys

### a key's blob is what dropbearkey writes for it

The 32 bytes are those of a key whose `.pub` line Dropbear wrote as
`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe`.

```ssh
(import x/codec/hex)
(def %kn-blob (eval (lit %blob64) (module ssh/known)))
(write (%kn-blob (Hex decode "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e")))
```
---
    "AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe"
