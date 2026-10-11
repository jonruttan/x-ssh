# dropbearkey
# @weight 15
# @timeout-scale 4

The key generator's line, read in dropbearkey's order of checks, and a
key Dropbear wrote read back: its secret's public key, its public line
and its fingerprint as `dropbearkey -y` printed them.  Making and
writing a key is proven live, by tests/oracle/dropbear.sh.  A public key
from its secret costs seconds pure-x, so the file is weighted.

## the line

### without -f, the usage, status 1

```ssh
(write (rest (rest (ssh-plan (list "dropbearkey" "-t" "ed25519")))))
```
---
    (1)

### -y prints, ed25519 is the default type, and -C is carried

```ssh
(write (list (first (rest (ssh-plan (list "dropbearkey" "-y" "-f" "k"))))
             (first (rest (ssh-plan (list "dropbearkey" "-f" "k" "-C" "me@here"))))))
```
---
    (('print "k" ()) ('generate "k" "me@here"))

### types not served, unknown types and sizes are refused

```ssh
(write (List map (fn (_ args) (first (rest (ssh-plan (pair "dropbearkey" args)))))
  (list (list "-t" "rsa" "-f" "k") (list "-t" "ed25519" "-f" "k" "-s" "abc")
        (list "-t" "ed25519" "-f" "k" "-s" "512"))))
```
---
    ("x-ssh: key type 'rsa' is not served yet\n" "Bits must be an integer\n" "Ed25519 keys have a fixed size of 256 bits\n")

### an unknown type says so before its usage

```ssh
(display (Str8 sub 0 23 (first (rest (ssh-plan (list "dropbearkey" "-t" "frob" "-f" "k"))))))
```
---
    Unknown key type 'frob'

## a key Dropbear wrote

The file `dropbearkey -t ed25519` made, 83 bytes, and what `dropbearkey
-y` printed for it.

### the secret and public halves, and the public key the secret makes

```ssh
(import x/codec/hex)
(import x/codec/ed25519)
(import ssh/keys ssh-key-of-dropbear-bytes)
(def %kg-file (Hex decode "0000000b7373682d6564323535313900000040ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c31829489331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(def %kg-key (ssh-key-of-dropbear-bytes %kg-file 83))
(write (list (Hex encode (first %kg-key)) (Hex encode (rest %kg-key))
             (str=? (Hex encode (Ed25519 public (first %kg-key))) (Hex encode (rest %kg-key)))))
```
---
    ("ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948" "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e" #t)

### its public line and fingerprint are dropbearkey's

```ssh
(import x/codec/hex)
(import ssh/keygen ssh-key-public-line ssh-key-fingerprint)
(def %kg-pub (Hex decode "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(display (ssh-key-public-line %kg-pub "jon@Mac"))
(newline)
(display (ssh-key-fingerprint %kg-pub))
```
---
```output
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe jon@Mac
SHA256:iQ82DeYUuKnMx3err1yzUY3TNC8WAD1NdlQ2piigmCQ
```
