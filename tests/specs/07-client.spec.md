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
  (list "Port 0" "StrictHostKeyChecking maybe" "LocalForward 2222:h" "ChannelTimeout session=5")))
```
---
    ("command-line: line 1: Badly formatted port number." "command-line: line 1: unsupported option \"maybe\"." "command-line: line 1: Bad local forwarding specification '2222:h'" "command-line: line 1: the channel timeout session=5 is not served; global= is")

### identity files: the ones named, or ~/.ssh/id_rsa, id_ecdsa and id_ed25519 when none is; tokens expanded

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %ci (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit identities))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (%ci (list "IdentityFile /k/%r@%h" "User git"))
             (List map (fn (_ p) ((fn (_ s i) (pair (Str8 sub i (- (Str8 length s) i) s) (rest p))) (first p) (Str8 index-of "/.ssh/" (first p)))) (%ci ()))))
```
---
    ((("/k/git@h" . #t)) (("/.ssh/id_rsa" . #f) ("/.ssh/id_ecdsa" . #f) ("/.ssh/id_ed25519" . #f)))

## proxies and dynamic forwards

### ProxyCommand or ProxyJump, the first holding, `none` for neither; a jump to the destination itself dropped

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %px (fn (_ opts)
  (def s (ssh-client-settings (ssh-config-options opts) "h" "u"))
  (def g (fn (_ k) (rest (List find (fn (_ p) (eq? (first p) k)) s))))
  (list (g (lit proxy-command)) (g (lit proxy-jump)))))
(write (List map %px (list (list "ProxyCommand nc %h \"%p\"")
                           (list "ProxyJump a,u@b:2" "ProxyCommand x")
                           (list "ProxyCommand none" "ProxyJump a")
                           (list "ProxyJump a,h")
                           (list "ProxyJump h:2200"))))
```
---
    (("nc %h \"%p\"" ()) (() "a,u@b:2") (() ()) (() ()) (() "h:2200"))

### a jump's hops, as OpenSSH reads them: a URI's, an empty port, brackets; a bad one refused

```ssh
(import ssh/client ssh-client-jump)
(write (List map (fn (_ j) (ssh-client-jump j))
  (list "u@a:2222,b" "ssh://u@h:22/" "[::1]:2" "h:" "a@b@c" "@h" "h:0" "ssh://[::1]:2" "::1")))
```
---
    ((("u" "a" 2222) (() "b" ())) (("u" "h" 22)) ((() "::1" 2)) ((() "h" ())) (("a@b" "c" ())) () () () ())

### DynamicForward: [bind_address:]port, the address as given; a bad one refused in OpenSSH's words

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %dy (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit dynamics))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (%dy (list "DynamicForward 1080" "DynamicForward *:1081" "DynamicForward [::1]:1082" "DynamicForward localhost:1083"))
             (guard (e (e msg)) (%dy (list "DynamicForward 0")))
             (guard (e (e msg)) (%dy (list "ProxyJump a:x")))))
```
---
    (((() 1080) ("*" 1081) ("::1" 1082) ("localhost" 1083)) "command-line: line 1: Bad forwarding specification." "command-line: line 1: Invalid ProxyJump \"a:x\"")

### RemoteForward given only [bind_address:]port is SOCKS at the server's end, no host and port 0

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %rm (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit remotes))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (%rm (list "RemoteForward 1080" "RemoteForward *:1081" "RemoteForward 10.0.0.1:1082" "RemoteForward [::1]:1083" "RemoteForward 1084 h:22"))
             (%rm (list "GatewayPorts yes" "RemoteForward 1080"))))
```
---
    ((("localhost" 1080 () 0) (() 1081 () 0) ("10.0.0.1" 1082 () 0) ("::1" 1083 () 0) ("localhost" 1084 "h" 22)) ((() 1080 () 0)))

### PermitRemoteOpen: any by default, none, or host:port each, `*` any host or port, the first line holding; refused in OpenSSH's words

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %po (fn (_ opts) (rest (List find (fn (_ p) (eq? (first p) (lit remote-open))) (ssh-client-settings (ssh-config-options opts) "h" "u")))))
(write (list (%po ()) (%po (list "PermitRemoteOpen none")) (%po (list "PermitRemoteOpen ANY"))
             (%po (list "PermitRemoteOpen a.b:22 *:80 [::1]:* c:*" "PermitRemoteOpen d:1"))
             (guard (e (e msg)) (%po (list "PermitRemoteOpen a.b")))
             (guard (e (e msg)) (%po (list "PermitRemoteOpen a:0")))
             (guard (e (e msg)) (%po (list "PermitRemoteOpen x:1 none")))))
```
---
    (("any") ("none" . 'none) ("ANY") ("a.b:22 *:80 [::1]:* c:*" ("a.b" 22) ("*" 80) ("::1" ()) ("c" ())) "command-line: line 1: bad port number in permitremoteopen" "command-line: line 1: bad port number in permitremoteopen" "command-line: line 1: keyword permitremoteopen \"none\" argument must appear alone.")

### a SOCKS request says how many bytes it took; PermitRemoteOpen allows a place by host and port, `*` either

```ssh
(def %so (eval (lit %socks) (module ssh/session)))
(def %oa (eval (lit %open-allowed?) (module ssh/session)))
(write (list (List ref 4 (%so (list 4 1 0 22 127 0 0 1 0 9 9) #f))
             (List ref 4 (%so (list 5 1 0 5 1 0 3 1 104 0 22 7) #t))
             (List map (fn (_ hp) (%oa (list (list "a" 22) (list "*" 80) (list "b" ())) (first hp) (rest hp)))
               (list (pair "a" 22) (pair "a" 23) (pair "z" 80) (pair "b" 1) (pair "A" 22)))
             (%oa () "x" 1) (%oa (lit none) "x" 1)))
```
---
    (9 11 (#t #f #t #t #f) #t #f)

### a command keyword's argument is the rest of its line, quotes and all

```ssh
(import ssh/config ssh-config-words)
(write (List map (fn (_ l) (ssh-config-words l))
  (list "RemoteCommand echo \"a  b\" c  " "ProxyCommand=nc %h %p" "Ciphers \"a b\" c")))
```
---
    (("RemoteCommand" "echo \"a  b\" c") ("ProxyCommand" "nc %h %p") ("Ciphers" "a b" "c"))

## the address, the escape character, the background, known hosts by command

### AddressFamily, BindAddress, EscapeChar, ForkAfterAuthentication, KnownHostsCommand and SyslogFacility, unset and set

```ssh
(import ssh/client ssh-client-settings)
(import ssh/config ssh-config-options)
(def %sv (fn (_ opts)
  (def s (ssh-client-settings (ssh-config-options opts) "h" "u"))
  (List map (fn (_ k) (rest (List find (fn (_ p) (eq? (first p) k)) s)))
    (list (lit family) (lit bind) (lit escape) (lit fork) (lit known-command) (lit facility)))))
(write (list (%sv ())
             (%sv (list "AddressFamily inet" "BindAddress 10.0.0.1" "EscapeChar none" "ForkAfterAuthentication yes"
                        "KnownHostsCommand /bin/kh %H \"%I\"" "SyslogFacility LOCAL0"))))
```
---
    (("any" () 126 #f () "user") ("inet" "10.0.0.1" () #t "/bin/kh %H \"%I\"" "local0"))

### an escape character as -e and EscapeChar read it, and as -G prints it; a bad one refused

```ssh
(import ssh/client ssh-client-settings ssh-client-escape)
(import ssh/config ssh-config-options)
(def %et (eval (lit %escape-text) (module ssh/client)))
(write (list (List map ssh-client-escape (list "~" "^A" "^~" "^" "none" "ab"))
             (List map %et (list 126 1 30 127 ()))
             (guard (e (e msg)) (ssh-client-settings (ssh-config-options (list "EscapeChar ab")) "h" "u"))))
```
---
    ((126 1 30 94 'none ()) ("~" "\\^A" "\\^^" "\\^?" "none") "command-line: line 1: Bad escape character.")

### AddressFamily inet6 is refused, IPv6 not being served; any and inet are not

```ssh
(import ssh/config ssh-config-options ssh-config-faults ssh-config-ssh-keywords)
(def %rf (eval (lit %refused) (module ssh/client)))
(write (List map (fn (_ o) (ssh-config-faults (ssh-config-options (list o)) ssh-config-ssh-keywords %rf ()))
  (list "AddressFamily any" "AddressFamily inet" "AddressFamily inet6")))
```
---
    (() () ("command-line: line 1: addressfamily is not served"))

### -Q's answers: kex by either name, key-sig, no certificates, an unknown query

```ssh
(import ssh/client ssh-client-query)
(write (List map ssh-client-query (list "kex" "KexAlgorithms" "key-sig" "key-cert" "nope")))
```
---
    (("curve25519-sha256" "curve25519-sha256@libssh.org") ("curve25519-sha256" "curve25519-sha256@libssh.org") ("ssh-ed25519" "ecdsa-sha2-nistp256" "ecdsa-sha2-nistp384" "ecdsa-sha2-nistp521" "ssh-rsa" "rsa-sha2-256" "rsa-sha2-512") ("") 'unsupported)

### KnownHostsCommand's words, split as OpenSSH splits them

```ssh
(def %av (eval (lit %argv) (module ssh/client)))
(write (%av "/bin/kh %H \"a b\" 'c d' e\\ f  "))
```
---
    ("/bin/kh" "%H" "a b" "c d" "e f")

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

### typed bytes through the escapes: ~~ is a tilde, a tilde mid-line is itself, ~. ends it; another escape character in its place

```ssh
(import x/type/vector)
(def %ce-escape (eval (lit %escape) (module ssh/session)))
(def %ce-run (Vector make 11 ()))
(def %ce-pass
  (fn (_ text esc)
    ((prim-ref (lit obj) (lit set!)) %ce-run 11 1)
    (def r (%ce-escape %ce-run text (Str8 length text) esc))
    (Str8 sub 0 (rest r) (first r))))
(write (list (%ce-pass "~~x" 126) (%ce-pass "a~b" 126) (%ce-pass "~x" 126) (%ce-pass "ab\n~~" 126)
             (guard (e (e msg)) (%ce-pass "ls\n~." 126))
             (%ce-pass "!!x\n~." 33) (guard (e (e msg)) (%ce-pass "ls\n!." 33))))
```
---
    ("~x" "a~b" "~x" "ab\n~" "escape" "!x\n~." "escape")
