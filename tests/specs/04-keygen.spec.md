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
    (('generate "k" "me@here" "" #t) ('generate () () () #f))

### -y, -l, -p, -A, -F and -R

```ssh
(write (List map (fn (_ args) (first (rest (ssh-plan (pair "ssh-keygen" args)))))
  (list (list "-y" "-f" "k") (list "-l" "-v" "-f" "k") (list "-p" "-P" "" "-N" "" "-f" "k") (list "-A")
        (list "-F" "[h]:2222") (list "-R" "h" "-f" "kh"))))
```
---
    (('public "k" ()) ('fingerprint "k" #t) ('passphrase "k" "" "") ('hosts ()) ('find "[h]:2222" ()) ('remove "h" "kh"))

### types not served, and unknown types, are refused

```ssh
(write (List map (fn (_ t) (first (rest (ssh-plan (list "ssh-keygen" "-t" t "-f" "k"))))) (list "rsa" "frob")))
```
---
    ("x-ssh: key type rsa is not served yet\n" "unknown key type frob\n")

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
(import ssh/keys ssh-seed-of-key-text ssh-key-of-public-line)
(import ssh/keygen ssh-key-public-line)
(def %ok-text "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACA8uK/jtTekMuzNeB9IitxKmJIbY1RYEadGyfBmteSRtAAAAJD+5KDY/uSg\n2AAAAAtzc2gtZWQyNTUxOQAAACA8uK/jtTekMuzNeB9IitxKmJIbY1RYEadGyfBmteSRtA\nAAAECa7r6MpdssNo9ABJT1l6f4nZYjzVSpOBBKSMyn06fEHzy4r+O1N6Qy7M14H0iK3EqY\nkhtjVFgRp0bJ8Ga15JG0AAAAB21lQGhlcmUBAgMEBQY=\n-----END OPENSSH PRIVATE KEY-----\n")
(def %ok-seed (ssh-seed-of-key-text %ok-text))
(def %ok-comment (rest ((eval (lit %openssh-key) (module ssh/keys)) %ok-text)))
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
(def %wr-seed (Hex decode "ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948"))
(def %wr-pub (Hex decode "9331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(def %wr-back ((eval (lit %openssh-key) (module ssh/keys)) (ssh-key-openssh-text %wr-seed %wr-pub "jon@Mac")))
(write (list (Hex encode (first %wr-back)) (rest %wr-back)))
```
---
    ("ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c3182948" "jon@Mac")
