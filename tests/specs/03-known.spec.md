# known_hosts
# @weight 2

What ssh/known writes and matches: a host's name as OpenSSH spells it,
and an Ed25519 key's blob in base64 as a `.pub` line holds it.  Reading
and recording the files, and ssh-keygen -F and -R over them, are proven
live, by tests/oracle/client.sh.

## names

### port 22 is the bare host, any other is bracketed with its port

```ssh
(import ssh/known ssh-known-name)
(write (list (ssh-known-name "example.org" 22) (ssh-known-name "127.0.0.1" 2222)))
```
---
    ("example.org" "[127.0.0.1]:2222")

## keys

### a key's blob is what its .pub line holds

The 32 bytes are those of a key whose `.pub` line is
`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe`.

```ssh
(import x/codec/hex)
(import ssh/pubkey ssh-pubkey-of-line ssh-pubkey-base64)
(write (ssh-pubkey-base64 (ssh-pubkey-of-line "ssh-ed25519" "AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe")))
```
---
    "AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe"

### an entry names a host among its comma list; comments and markers do not

```ssh
(def %kn-entry (eval (lit %entry) (module ssh/known)))
(write (list (%kn-entry "a,[h]:2222 ssh-ed25519 AAAA" "[h]:2222") (%kn-entry "# h ssh-ed25519 AAAA" "h")
             (%kn-entry "@revoked h ssh-ed25519 AAAA" "h") (%kn-entry "other ssh-ed25519 AAAA" "h")))
```
---
    (("ssh-ed25519" "AAAA") () () ())
