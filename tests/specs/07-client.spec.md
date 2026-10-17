# ssh, the client's settings
# @weight 1

The client's settings, from configuration lines as OpenSSH reads them:
what `ssh -G` prints.  Connecting under them -- the host key policy,
each identity, passwords from the terminal or SSH_ASKPASS, forwards, the
clocks and the environment sent -- is proven live by
tests/oracle/client.sh and tests/oracle/server.sh.

## settings

### OpenSSH's defaults, for a host and a local user

```ssh
(import ssh/client ssh-client-settings)
(def %cs (ssh-client-settings () "example.org" "jon"))
(def %cg (fn (_ k) (rest (List find (fn (_ p) (eq? (first p) k)) %cs))))
(write (List map %cg (list (lit hostname) (lit port) (lit user) (lit strict) (lit batch) (lit password) (lit prompts)
                           (lit limits) (lit forwards) (lit level) (lit session) (lit command))))
```
---
    ("example.org" 22 "jon" "ask" #f #t 3 (0 3 0) () "info" "default" ())

### Hostname's %h, the first value holding, and forwards in either shape

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options ssh-config-read)
(def %cs (ssh-client-settings
  (List append (ssh-config-options (list "LocalForward 8080:web:80" "Port 2200"))
               (ssh-config-read "Host gw\n  Hostname %h.example.org\n  Port 22\n  LocalForward *:9000 db:5432\n  RemoteForward 7000 localhost:22\n  ServerAliveInterval 1m\n  StrictHostKeyChecking accept-new\n" "c" "gw" "jon" "jon" ""))
  "gw" "jon"))
(def %cg (fn (_ k) (rest (List find (fn (_ p) (eq? (first p) k)) %cs))))
(write (List map %cg (list (lit hostname) (lit port) (lit forwards) (lit remotes) (lit limits) (lit strict))))
```
---
    ("gw.example.org" 2200 (("localhost" 8080 "web" 80) (() 9000 "db" 5432)) (("localhost" 7000 "localhost" 22)) (60 3 0) "accept-new")

### ClearAllForwardings clears them; GatewayPorts binds every interface

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %cf (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit forwards))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (%cf (list "ClearAllForwardings yes" "LocalForward 1:h:1")) (%cf (list "GatewayPorts yes" "LocalForward 1:h:1"))))
```
---
    (() ((() 1 "h" 1)))

### a value OpenSSH refuses is refused in its words

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(write (List map (fn (_ o) (guard (e (e msg)) (ssh-client-settings (ssh-config-options (list o)) "h" "u")))
  (list "Port 0" "StrictHostKeyChecking maybe" "LocalForward 2222:h" "SessionType subsystem")))
```
---
    ("command-line: line 1: Badly formatted port number." "command-line: line 1: unsupported option \"maybe\"." "command-line: line 1: Bad local forwarding specification '2222:h'" "command-line: line 1: SessionType subsystem is not served")

### identity files: the ones named, or ~/.ssh/id_ed25519 when none is; tokens expanded

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %ci (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit identities))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (%ci (list "IdentityFile /k/%r@%h" "User git")) (rest (first (%ci ())))))
```
---
    ((("/k/git@h" . #t)) #f)

## terminals

### -t stands for RequestTTY yes, -T for no; auto is the default

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %ct (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit tty))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (List ref 3 (first (rest (ssh-plan (list "ssh" "-t" "h"))))) (%ct ()) (%ct (list "RequestTTY force"))))
```
---
    (("RequestTTY yes") "auto" "force")

### typed bytes through the escapes: ~~ is a tilde, a tilde mid-line is itself, ~. ends it

```ssh
(import x/type/vector)
(def %ce-escape (eval (lit %escape) (module ssh/session)))
(def %ce-run (Vector make 11 ()))
(def %ce-pass
  (fn (_ text)
    ((prim-ref (lit obj) (lit set!)) %ce-run 11 1)
    (def r (%ce-escape %ce-run text (Str8 length text)))
    (Str8 sub 0 (rest r) (first r))))
(write (list (%ce-pass "~~x") (%ce-pass "a~b") (%ce-pass "~x") (%ce-pass "ab\n~~")
             (guard (e (e msg)) (%ce-pass "ls\n~."))))
```
---
    ("~x" "a~b" "~x" "ab\n~" "escape")
