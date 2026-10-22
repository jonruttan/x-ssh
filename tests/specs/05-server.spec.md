# sshd, the server
# @weight 2
# @timeout-scale 4

The server's settings, from configuration lines as OpenSSH reads them,
and its password check.  Serving -- the key exchange from the server's
end, publickey and password authentication under the settings, a command
on three pipes, direct-tcpip channels for a client's forwards and
listeners for its remote forwards, keepalives and the channel timeout,
the environment AcceptEnv takes, the background, the pidfile and the log
-- is proven live by tests/oracle/server.sh, with Dropbear's client,
OpenSSH's and git as the oracles.

## settings

### OpenSSH's defaults

```ssh
(import ssh/server ssh-server-settings)
(display ((eval (lit %print) (module ssh/server)) (ssh-server-settings ())))
```
---
```output
port 22
listenaddress 0.0.0.0:22
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
pidfile /var/run/sshd.pid
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
passwordauthentication yes
pubkeyauthentication yes
pubkeyacceptedalgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256
permitemptypasswords no
permitrootlogin prohibit-password
allowtcpforwarding yes
gatewayports no
clientaliveinterval 0
clientalivecountmax 3
channeltimeout none
syslogfacility AUTH
loglevel INFO
maxauthtries 6
```

### the first value holds; a command-line Port stands in place of the file's

```ssh
(import ssh/server ssh-server-settings)
(import ssh/config ssh-config-options ssh-config-read)
(def %st (ssh-server-settings
  (List append (ssh-config-options (list "Port 2222" "PasswordAuthentication no"))
               (ssh-config-read "Port 22\nPort 23\nPasswordAuthentication yes\nListenAddress 127.0.0.1\nListenAddress [::1]:2200\nChannelTimeout global=5m\nClientAliveInterval 30\nAcceptEnv LANG LC_*\n" "f" () () () ""))))
(def %sg (fn (_ k) (rest (List find (fn (_ p) (eq? (first p) k)) %st))))
(write (List map %sg (list (lit ports) (lit listen) (lit password) (lit limits) (lit accept))))
```
---
    ((2222) (("127.0.0.1" . 2222) ("::1" . 2200)) #f (30 3 300) ("LANG" "LC_*"))

### a value OpenSSH refuses is refused in its words

```ssh
(import ssh/server ssh-server-settings)
(import ssh/config ssh-config-options)
(write (List map (fn (_ o) (guard (e (e msg)) (ssh-server-settings (ssh-config-options (list o)))))
  (list "Port ssh" "PermitRootLogin maybe" "Ciphers aes128-ctr" "ChannelTimeout session=5")))
```
---
    ("command-line: line 1: Badly formatted port number." "command-line: line 1: unsupported option \"maybe\"." "command-line: line 1: ciphers leaves out chacha20-poly1305@openssh.com, the one served" "command-line: line 1: the channel timeout session=5 is not served; global= is")

### authorized_keys files: %h and %u, a relative one under the home directory

```ssh
(def %kf (eval (lit %key-files) (module ssh/server)))
(write (%kf (list ".ssh/authorized_keys" "/etc/ssh/keys/%u" "%h/k%%") "jon" "/home/jon"))
```
---
    ("/home/jon/.ssh/authorized_keys" "/etc/ssh/keys/jon" "/home/jon/k%")

## passwords

### crypt(3) of a password against a stored hash: DES, $1$, $5$, $6$; a locked or unknown one is ()

The hashes are x-lang's Crypt examples for "pw".

```ssh
(def %pw-crypt (eval (lit %crypt) (module ssh/server)))
(def %pw-stored
  (list "abzlUXK5ed5rs" "$1$saltsalt$6SNdNaZLKst2LlSm7oPPL1"
        "$5$saltsalt$0rl.MZtoLLPP3X0Rdl8riRnphIcAXJY27/aOAyK2hB5"
        "$6$saltsalt$pauPrmdmG4BTE9h2HPmywiw152IFch6BJCEsaY6D.PLTfpV8sqvXwWdyfsgVgozkYH9B80bAip/08R2BPH2xk/"))
(write (list (List map (fn (_ s) (str=? (%pw-crypt "pw" s) s)) %pw-stored)
             (str=? (%pw-crypt "px" (first %pw-stored)) (first %pw-stored))
             (%pw-crypt "pw" "!") (%pw-crypt "pw" "*") (%pw-crypt "pw" "$y$j9T$abc")))
```
---
    ((#t #t #t #t) #f () () ())
