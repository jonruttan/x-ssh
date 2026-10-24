# ssh-keygen
# @weight 15
# @timeout-scale 4

The key tool's line, and keys read and written: a key file OpenSSH's
ssh-keygen wrote and one Dropbear's dropbearkey wrote, read back; the
public line, fingerprint and randomart `ssh-keygen -l -v` printed for a
key; the private key file written, read back.  Making keys and the
files themselves, read by OpenSSH's tool, are proven live, by
tests/oracle/client.sh.  A public key from its secret costs seconds
pure-x, so the file is weighted.

## the line

### making a key: the file, the comment, the passphrase and -q carried

```ssh
(write (list (first (rest (ssh-plan (list "ssh-keygen" "-t" "ed25519" "-f" "k" "-C" "me@here" "-N" "" "-q"))))
             (first (rest (ssh-plan (list "ssh-keygen"))))))
```
---
    (('generate "k" "me@here" "" #t 16 "ed25519" 256) ('generate () () () #f 16 "ed25519" 256))

### -y, -l, -p, -A, -F and -R

```ssh
(write (List map (fn (_ args) (first (rest (ssh-plan (pair "ssh-keygen" args)))))
  (list (list "-y" "-f" "k") (list "-l" "-v" "-f" "k") (list "-p" "-P" "" "-N" "" "-f" "k") (list "-A")
        (list "-F" "[h]:2222") (list "-R" "h" "-f" "kh"))))
```
---
    (('public "k" ()) ('fingerprint "k" #t) ('passphrase "k" "" "" 16) ('hosts ()) ('find "[h]:2222" ()) ('remove "h" "kh"))

### ECDSA on 256 bits, the default, 384 or 521; RSA on 3072, the default, or another from 1024 to 16384; types and sizes not served, and unknown ones, refused

```ssh
(write (List map (fn (_ a) (first (rest (ssh-plan (List append (list "ssh-keygen" "-f" "k" "-t") a)))))
  (list (list "ecdsa") (list "ecdsa" "-b" "384") (list "ecdsa" "-b" "521") (list "rsa") (list "rsa" "-b" "4096")
        (list "dsa") (list "frob") (list "ecdsa" "-b" "512") (list "rsa" "-b" "512") (list "rsa" "-b" "32768"))))
```
---
    (('generate "k" () () #f 16 "ecdsa" 256) ('generate "k" () () #f 16 "ecdsa" 384) ('generate "k" () () #f 16 "ecdsa" 521) ('generate "k" () () #f 16 "rsa" 3072) ('generate "k" () () #f 16 "rsa" 4096) "x-ssh: key type dsa is not served yet\n" "unknown key type frob\n" "Invalid ECDSA key length: valid lengths are 256, 384 or 521 bits\r\n" "Invalid RSA key length: minimum is 1024 bits\r\n" "Invalid RSA key length: maximum is 16384 bits\r\n")

## a key Dropbear wrote

The file `dropbearkey -t ed25519` made, 83 bytes.

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

### its public line, fingerprint and randomart are ssh-keygen's

```ssh
(import x/codec/hex)
(import ssh/keygen ssh-key-public-line ssh-key-fingerprint ssh-key-randomart)
(def %kg-pub (Hex decode "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(display (ssh-key-public-line %kg-pub "jon@Mac"))
(newline)
(display (ssh-key-fingerprint %kg-pub))
(newline)
(display (ssh-key-randomart %kg-pub))
```
---
```output
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMxrJbFYrb2hCCDvzVNWbN1TdsP/SQyU80/bLdTv9Oe jon@Mac
SHA256:iQ82DeYUuKnMx3err1yzUY3TNC8WAD1NdlQ2piigmCQ
+--[ED25519 256]--+
| E . ....o.oo.o+o|
|  o + ... ooo.o..|
|   o ++  . o+.   |
|    o+ + ..= +   |
| o o  * S + = .  |
|  + o..+.. o .   |
|   . . .=.       |
|     . ..+       |
|      ++o        |
+----[SHA256]-----+
```

## a key OpenSSH wrote

`ssh-keygen -t ed25519 -N '' -C me@here`'s file.

### its seed, its comment, and the public line `ssh-keygen -y` printed

```ssh
(import x/codec/hex)
(import x/codec/ed25519)
(import ssh/keys ssh-seed-of-key-text ssh-key-of-text ssh-key-of-public-line)
(import ssh/keygen ssh-key-public-line)
(def %ok-text "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACA8uK/jtTekMuzNeB9IitxKmJIbY1RYEadGyfBmteSRtAAAAJD+5KDY/uSg\n2AAAAAtzc2gtZWQyNTUxOQAAACA8uK/jtTekMuzNeB9IitxKmJIbY1RYEadGyfBmteSRtA\nAAAECa7r6MpdssNo9ABJT1l6f4nZYjzVSpOBBKSMyn06fEHzy4r+O1N6Qy7M14H0iK3EqY\nkhtjVFgRp0bJ8Ga15JG0AAAAB21lQGhlcmUBAgMEBQY=\n-----END OPENSSH PRIVATE KEY-----\n")
(def %ok-seed (ssh-seed-of-key-text %ok-text))
(def %ok-comment (List ref 2 (ssh-key-of-text %ok-text ())))
(display (ssh-key-public-line (Ed25519 public %ok-seed) %ok-comment))
(newline)
(write (Hex encode (first (ssh-key-of-public-line "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDy4r+O1N6Qy7M14H0iK3EqYkhtjVFgRp0bJ8Ga15JG0 me@here"))))
```
---
```output
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDy4r+O1N6Qy7M14H0iK3EqYkhtjVFgRp0bJ8Ga15JG0 me@here
"3cb8afe3b537a432eccd781f488adc4a98921b63545811a746c9f066b5e491b4"
```

## writing

### the private key file this tool writes reads back: its seed and its comment

```ssh
(import x/codec/hex)
(import ssh/keygen ssh-key-openssh-text)
(import ssh/keys ssh-key-of-text)
(def %wr-seed (Hex decode "ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948"))
(def %wr-pub (Hex decode "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(def %wr-back (ssh-key-of-text (ssh-key-openssh-text %wr-seed %wr-pub "jon@Mac") ()))
(write (list (Hex encode (first %wr-back)) (List ref 2 %wr-back)))
```
---
    ("ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948" "jon@Mac")

## under a passphrase

`ssh-keygen -t ed25519 -N x-ssh -a 2 -C sealed@here`'s file: aes256-ctr
under bcrypt-pbkdf, two rounds.  OpenSSH's sixteen are proven live, by
tests/oracle/client.sh.

### it opens under its passphrase: the public line its seed makes is the one ssh-keygen wrote

```ssh
(import x/codec/ed25519)
(import ssh/keys ssh-key-of-text)
(import ssh/keygen ssh-key-public-line)
(def %sl-text "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDy0pojVw\naM6dG5LvZhdiuoAAAAAgAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMyaRFRPx6NmxOjj\nOye/6UtsYWQ4LGlAMH5D0sABGKOvAAAAkHJyB9jRQe4F9qEsijHY+id0wZOdqG+v1CqbQX\niUhDKsXqdkb9G3+QgREz0W7MAYj0hGJHMTrOL9BeYjAPKDLmLK8ZIAAj9rGUAPRyQAWN0U\nxr5RrLJmFwkhQs3rpQNfKTKsYtHveCHmID4T2QYj9OHrTbO3zChvGVx+uHeo4/4iJOqT8y\nMjV5TjvzfrDZMgFA==\n-----END OPENSSH PRIVATE KEY-----\n")
(def %sl-key (ssh-key-of-text %sl-text "x-ssh"))
(display (ssh-key-public-line (Ed25519 public (first %sl-key)) (List ref 2 %sl-key)))
```
---
```output
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMyaRFRPx6NmxOjjOye/6UtsYWQ4LGlAMH5D0sABGKOv sealed@here
```

### without its passphrase, or under a wrong one, it does not open, in OpenSSH's words

```ssh
(import ssh/keys ssh-key-of-text)
(def %sn-text "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDy0pojVw\naM6dG5LvZhdiuoAAAAAgAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMyaRFRPx6NmxOjj\nOye/6UtsYWQ4LGlAMH5D0sABGKOvAAAAkHJyB9jRQe4F9qEsijHY+id0wZOdqG+v1CqbQX\niUhDKsXqdkb9G3+QgREz0W7MAYj0hGJHMTrOL9BeYjAPKDLmLK8ZIAAj9rGUAPRyQAWN0U\nxr5RrLJmFwkhQs3rpQNfKTKsYtHveCHmID4T2QYj9OHrTbO3zChvGVx+uHeo4/4iJOqT8y\nMjV5TjvzfrDZMgFA==\n-----END OPENSSH PRIVATE KEY-----\n")
(write (List map (fn (_ pass) (guard (e (e msg)) (ssh-key-of-text %sn-text pass) "opened")) (list () "" "x-ss")))
```
---
    ("incorrect passphrase supplied to decrypt private key" "incorrect passphrase supplied to decrypt private key" "incorrect passphrase supplied to decrypt private key")

### a key sealed here is OpenSSH's aes256-ctr under bcrypt, and opens under its passphrase alone

```ssh
(import x/codec/hex)
(import ssh/keygen ssh-key-openssh-text)
(import ssh/keys ssh-key-of-text)
(def %sw-seed (Hex decode "ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948"))
(def %sw-pub (Hex decode "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(def %sw-text (ssh-key-openssh-text %sw-seed %sw-pub "jon@Mac" "hunter2" 1))
(def %sw-back (ssh-key-of-text %sw-text "hunter2"))
(write (list (Str8 sub 36 62 %sw-text) (Hex encode (first %sw-back)) (List ref 2 %sw-back)
             (guard (e (e msg)) (ssh-key-of-text %sw-text "hunter3") "opened")))
```
---
    ("b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAAB" "ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948" "jon@Mac" "incorrect passphrase supplied to decrypt private key")

### -a's rounds carried, and a count OpenSSH refuses refused in its words

```ssh
(write (List map (fn (_ args) (rest (ssh-plan (pair "ssh-keygen" args))))
  (list (list "-a" "4" "-N" "pw" "-f" "k") (list "-p" "-a" "8" "-f" "k") (list "-a" "x") (list "-a" "0"))))
```
---
    ((('generate "k" () "pw" #f 4 "ed25519" 256) 0) (('passphrase "k" () () 8) 0) ("Invalid number: x (invalid)\n" 255) ("Invalid number: 0 (too small)\n" 255))
