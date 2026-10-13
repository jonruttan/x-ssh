# dropbearconvert, the key converter
# @weight 2

A key written in each format, from the key Dropbear wrote in
04-keygen: Dropbear's bytes come back as they were, and OpenSSH's text
is what ssh/keys reads the same seed from.  The files themselves, read
by ssh-keygen and dropbearkey, are proven live by tests/oracle/dropbear.sh.

## the formats

### Dropbear's bytes, written back as they were

```ssh
(import x/codec/hex)
(import ssh/keys ssh-key-of-dropbear-bytes)
(import ssh/convert ssh-key-dropbear-bytes)
(def %cv-file (Hex decode "0000000b7373682d6564323535313900000040ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c31829489331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(def %cv-key (ssh-key-of-dropbear-bytes %cv-file 83))
(def %cv-back (ssh-key-dropbear-bytes (first %cv-key) (rest %cv-key)))
(def %cv-bref (prim-ref (lit str) (lit byte-ref)))
(def %cv-c->i (prim-ref (lit char) (lit ->int)))
(def %cv-hex
  (fn (_ s n)
    (Hex encode-bytes
      ((fn (self i acc) (if (< i 0) acc (self (- i 1) (pair (%cv-c->i (%cv-bref s i)) acc)))) (- n 1) ()))))
(write (list (rest %cv-back) (str=? (%cv-hex (first %cv-back) 83) (%cv-hex %cv-file 83))))
```
---
    (83 #t)

### OpenSSH's text: its lines, and the seed ssh/keys reads back from it

```ssh
(import x/codec/hex)
(import ssh/keys ssh-key-of-dropbear-bytes ssh-seed-of-key-text)
(import ssh/convert ssh-key-openssh-text)
(def %cv-file (Hex decode "0000000b7373682d6564323535313900000040ef78c24940a720e4126bdee6d54b548bee55210f5794bd598a3e9c48c31829489331ac96c562b6f6842083bf354d59b3754ddb0ffd243253cd3f6cb753bfd39e"))
(def %cv-key (ssh-key-of-dropbear-bytes %cv-file 83))
(def %cv-text (ssh-key-openssh-text (first %cv-key) (rest %cv-key)))
(def %cv-lines (Str8 split "\n" %cv-text))
(write (list (first %cv-lines)
             (List ref (- (List length %cv-lines) 2) %cv-lines)
             (List map (fn (_ l) (Str8 length l)) (List take (- (List length %cv-lines) 3) (rest %cv-lines)))
             (str=? (Hex encode (ssh-seed-of-key-text %cv-text)) (Hex encode (first %cv-key)))))
```
---
    ("-----BEGIN OPENSSH PRIVATE KEY-----" "-----END OPENSSH PRIVATE KEY-----" (70 70 70 70 32) #t)
