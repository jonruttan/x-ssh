# the agent's protocol
# @weight 4
# @timeout-scale 4

ssh/agent answers OpenSSH's agent protocol (draft-miller-ssh-agent):
each request a type byte and its fields, each answer the same.  These
ask an agent directly, the bytes a socket would carry, with keys made
here.

## the requests

### add, list, sign, lock, unlock, remove, remove all; an extension and a confirm constraint refused

```ssh
(import ssh/keygen ssh-identity-make)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-put-string ssh-put-text ssh-out-run ssh-in ssh-in-buf ssh-get-byte ssh-get-uint32 ssh-get-string ssh-get-text)
(import ssh/pubkey ssh-pubkey-blob ssh-pubkey-verify?)
(def %ag (fn (_ s) (eval s (module ssh/agent))))
(def a ((%ag (lit %agent)) #f ()))
(def call
  (fn (_ type fill)
    (def o (ssh-out))
    (ssh-put-byte o type)
    (fill o)
    (def r (ssh-out-run o))
    (def reply (ssh-out-run ((%ag (lit %answer)) a (first r) (rest r))))
    (ssh-in (first reply) 0 (rest reply))))
(def code (fn (_ in) (ssh-get-byte in)))
(def none (fn (_ o) ()))
(def blob (fn (_ id) (fn (_ o) ((fn (_ b) (ssh-put-string o (first b) (List ref 1 b) (List ref 2 b))) (ssh-pubkey-blob (first id))))))
(def text (fn (_ t) (fn (_ o) (ssh-put-text o t))))
(def add (fn (_ id comment) (fn (_ o) ((%ag (lit %put-identity)) o id comment))))
(def listed
  (fn (_)
    (def in (call 11 none))
    (def t (ssh-get-byte in))
    (def n (ssh-get-uint32 in))
    (pair t ((fn (self k acc) (if (= k 0) (List reverse acc) (do (ssh-get-string in) (self (- k 1) (pair (ssh-get-text in) acc))))) n ()))))
(def id1 (ssh-identity-make "ed25519" 256))
(def id2 (ssh-identity-make "ecdsa" 256))
(def signed
  (fn (_ id)
    (def in (call 13 (fn (_ o) ((blob id) o) (ssh-put-text o "abc") (ssh-put-uint32 o 0))))
    (def t (ssh-get-byte in))
    (if (= t 14)
      (do (def s (ssh-get-string in))
          (def sig (list (ssh-in-buf in) (first s) (rest s)))
          (list t (ssh-pubkey-verify? (first id) sig (list "abd" 0 3)) (ssh-pubkey-verify? (first id) sig (list "abc" 0 3))))
      (list t))))
(write
  (list (code (call 17 (add id1 "one")))
        (code (call 25 (fn (_ o) ((add id2 "two") o) (ssh-put-byte o 1) (ssh-put-uint32 o 100))))
        (listed)
        (signed id1) (signed id2)
        (code (call 22 (text "pw")))
        (listed) (signed id1) (code (call 17 (add id1 "again")))
        (code (call 23 (text "no"))) (code (call 23 (text "pw")))
        (code (call 18 (blob id2))) (code (call 18 (blob id2)))
        (listed)
        (code (call 19 none)) (listed)
        (code (call 27 (text "session-bind@openssh.com")))
        (code (call 25 (fn (_ o) ((add id1 "one") o) (ssh-put-byte o 2))))
        (listed)))
```
---
    (6 6 (12 "one" "two") (14 #f #t) (14 #f #t) 6 (12) (5) 5 5 6 6 5 (12 "one") 6 (12) 5 5 (12))

### a key's lifetime passes: it is gone from the list

```ssh
(import ssh/keygen ssh-identity-make)
(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-out-run ssh-in ssh-get-byte ssh-get-uint32)
(def %ag (fn (_ s) (eval s (module ssh/agent))))
(def a ((%ag (lit %agent)) #f 1))
(def call
  (fn (_ type fill)
    (def o (ssh-out)) (ssh-put-byte o type) (fill o)
    (def r (ssh-out-run o))
    (def reply (ssh-out-run ((%ag (lit %answer)) a (first r) (rest r))))
    (ssh-in (first reply) 0 (rest reply))))
(def count (fn (_) (def in (call 11 (fn (_ o) ()))) (ssh-get-byte in) (ssh-get-uint32 in)))
(def added (ssh-get-byte (call 17 (fn (_ o) ((%ag (lit %put-identity)) o (ssh-identity-make "ed25519" 256) "k")))))
(def before (count))
(Sys sleep 2)
(write (list added before (count)))
```
---
    (6 1 0)
