# The binary packet protocol
# @weight 4

RFC 4253 6 under each cipher and MAC served: a connection's send keys
and the other end's receive keys made as the key exchange makes them,
from one shared secret, exchange hash and session id, then packets sent
one way over a loopback socket and read back.  The keys are made by
ssh/transport's own `%keys`; the secret and the hash are fixed bytes.

## round trips

### every cipher, with every MAC where it takes one: payloads of 1, 100 and 5000 bytes come back whole

The engines are built first, as a connection builds them.  The
receiving end asks `ssh-pending?` before each read, as a loop that
waits on other descriptors does.

```x
(do
  (import x/sys/socket)
  (import x/sys/gc)
  (import ssh/transport ssh-open ssh-send-packet! ssh-recv-packet! ssh-pending? ssh-engines! ssh-cipher-names ssh-mac-names)
  (ssh-engines! ())
  (def %t-keys (eval (lit %keys) (module ssh/transport)))
  (def %t-slot! (eval (lit %slot!) (module ssh/transport)))
  (def %t-aead? (eval (lit %aead?) (module ssh/transport)))
  (def %t-set (prim-ref (lit ptr) (lit set!)))
  (def %t-bytes
    (fn (_ n from)
      (def s ((prim-ref (lit str) (lit make)) n))
      ((fn (self i) (when (< i n) (%t-set ((prim-ref (lit str) (lit ->ptr)) s) i (& (+ from (* i 7)) 255) 1) (self (+ i 1)))) 0)
      s))
  (def %t-kmp (pair (%t-bytes 33 1) 33))
  (def %t-h (%t-bytes 32 2))
  (def %t-sid (%t-bytes 32 3))
  (def %t-lfd (Socket tcp-listen-on "127.0.0.1" 0))
  (def %t-port (Socket local-port %t-lfd))
  ; bytes read in, a recv at a time, until a whole packet is buffered
  (def %t-pending! (eval (lit %pending!) (module ssh/transport)))
  (def %t-fill!
    (fn (self c) (unless (ssh-pending? c) (do (%t-pending! c (+ (rest ((eval (lit %slot) (module ssh/transport)) c 2)) 1)) (self c)))))
  (def %t-pair
    (fn (_ cipher mac)
      (def a (ssh-open (Socket tcp-connect "127.0.0.1" %t-port) ()))
      (def b (ssh-open (Socket accept %t-lfd) ()))
      (%t-slot! a 7 %t-sid) (%t-slot! b 7 %t-sid)
      (%t-slot! a 5 (%t-keys a %t-kmp %t-h cipher mac 65))
      (%t-slot! b 6 (%t-keys b %t-kmp %t-h cipher mac 65))
      (pair a b)))
  (def %t-same?
    (fn (_ p s n)
      (if (= (rest p) n)
        ((fn (self i) (if (= i n) #t (if (= ((prim-ref (lit str) (lit byte-ref)) (first p) i) ((prim-ref (lit str) (lit byte-ref)) s i)) (self (+ i 1)) #f))) 0)
        #f)))
  (def %t-trip
    (fn (_ cipher mac)
      (def ab (%t-pair cipher mac))
      (def ok
        (List map
          (fn (_ n)
            (def s (%t-bytes n n))
            (ssh-send-packet! (first ab) s n)
            (%t-fill! (rest ab))
            (%t-same? (ssh-recv-packet! (rest ab)) s n))
          (list 1 100 5000)))
      (Heap collect)
      (List all? (fn (_ x) x) ok)))
  (display
    (List flat-map
      (fn (_ cipher)
        (if (%t-aead? cipher)
          (list (list cipher (%t-trip cipher ())))
          (List map (fn (_ mac) (list cipher mac (%t-trip cipher mac))) ssh-mac-names)))
      ssh-cipher-names)))
```
---
```output
((chacha20-poly1305@openssh.com #t) (aes128-ctr hmac-sha2-256-etm@openssh.com #t) (aes128-ctr hmac-sha2-512-etm@openssh.com #t) (aes128-ctr hmac-sha2-256 #t) (aes128-ctr hmac-sha2-512 #t) (aes192-ctr hmac-sha2-256-etm@openssh.com #t) (aes192-ctr hmac-sha2-512-etm@openssh.com #t) (aes192-ctr hmac-sha2-256 #t) (aes192-ctr hmac-sha2-512 #t) (aes256-ctr hmac-sha2-256-etm@openssh.com #t) (aes256-ctr hmac-sha2-512-etm@openssh.com #t) (aes256-ctr hmac-sha2-256 #t) (aes256-ctr hmac-sha2-512 #t) (aes128-gcm@openssh.com #t) (aes256-gcm@openssh.com #t))
```

### a byte changed in flight fails the packet's tag, under each kind of framing

The byte is one of the payload's, changed after it is received and
before it is read.

```x
(do
  (import x/sys/socket)
  (import ssh/transport ssh-open ssh-send-packet! ssh-recv-packet! ssh-pending? ssh-engines!)
  (ssh-engines! ())
  (def %t-keys (eval (lit %keys) (module ssh/transport)))
  (def %t-slot (eval (lit %slot) (module ssh/transport)))
  (def %t-slot! (eval (lit %slot!) (module ssh/transport)))
  (def %t-set (prim-ref (lit ptr) (lit set!)))
  (def %t-bytes
    (fn (_ n from)
      (def s ((prim-ref (lit str) (lit make)) n))
      ((fn (self i) (when (< i n) (%t-set ((prim-ref (lit str) (lit ->ptr)) s) i (& (+ from (* i 7)) 255) 1) (self (+ i 1)))) 0)
      s))
  (def %t-kmp (pair (%t-bytes 33 1) 33))
  (def %t-h (%t-bytes 32 2))
  (def %t-sid (%t-bytes 32 3))
  (def %t-lfd (Socket tcp-listen-on "127.0.0.1" 0))
  (def %t-port (Socket local-port %t-lfd))
  ; bytes read in, a recv at a time, until a whole packet is buffered
  (def %t-pending! (eval (lit %pending!) (module ssh/transport)))
  (def %t-fill!
    (fn (self c) (unless (ssh-pending? c) (do (%t-pending! c (+ (rest ((eval (lit %slot) (module ssh/transport)) c 2)) 1)) (self c)))))
  (def %t-forged
    (fn (_ cipher mac)
      (def a (ssh-open (Socket tcp-connect "127.0.0.1" %t-port) ()))
      (def b (ssh-open (Socket accept %t-lfd) ()))
      (%t-slot! a 7 %t-sid) (%t-slot! b 7 %t-sid)
      (%t-slot! a 5 (%t-keys a %t-kmp %t-h cipher mac 65))
      (%t-slot! b 6 (%t-keys b %t-kmp %t-h cipher mac 65))
      (ssh-send-packet! a (%t-bytes 64 9) 64)
      (%t-fill! b)
      (def run (%t-slot b 2))
      (%t-set ((prim-ref (lit str) (lit ->ptr)) (first run)) 40
              (- 255 ((prim-ref (lit char) (lit ->int)) ((prim-ref (lit str) (lit byte-ref)) (first run) 40))) 1)
      (guard (e (e msg)) (ssh-recv-packet! b) "read")))
  (display (List map (fn (_ cm) (%t-forged (first cm) (rest cm)))
    (list (pair "chacha20-poly1305@openssh.com" ()) (pair "aes256-gcm@openssh.com" ())
          (pair "aes128-ctr" "hmac-sha2-256") (pair "aes256-ctr" "hmac-sha2-512-etm@openssh.com")))))
```
---
    (ssh: a packet failed its authentication tag ssh: a packet failed its authentication tag ssh: a packet failed its authentication tag ssh: a packet failed its authentication tag)
