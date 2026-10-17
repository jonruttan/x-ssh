# configuration files
# @weight 1

ssh/config reads ssh_config(5) and sshd_config(5) as OpenSSH does: a
keyword and its arguments a line, the first value given the one that
holds.

## lines

### a keyword, an `=` or not, quoted words, comments

```ssh
(import ssh/config ssh-config-words)
(write (List map ssh-config-words
  (list "Port 2222" "  PasswordAuthentication=no" "SendEnv = LANG LC_*" "IdentityFile \"/a b/key\" # mine" "# a comment" "")))
```
---
    (("Port" "2222") ("PasswordAuthentication" "no") ("SendEnv" "LANG" "LC_*") ("IdentityFile" "/a b/key") () ())

### a file's lines, keywords lowercased, each with where it came from

```ssh
(import ssh/config ssh-config-read)
(write (ssh-config-read "Port 22\n\n# off\nPermitRootLogin no\n" "/etc/ssh/sshd_config" () () () "/etc/ssh"))
```
---
    (("port" ("22") "/etc/ssh/sshd_config: line 1") ("permitrootlogin" ("no") "/etc/ssh/sshd_config: line 4"))

### an unclosed quote is refused where it is

```ssh
(import ssh/config ssh-config-read)
(write (guard (e (e msg)) (ssh-config-read "Banner \"x" "f" () () () "")))
```
---
    "f: line 1: no matching quote"

## the client's conditions

### Host patterns rule the lines after them, `!` excluding

```ssh
(import ssh/config ssh-config-read ssh-config-first)
(def %cf-text "User everyone\nHost *.example.org !bad.example.org\n  Port 2222\nHost other\n  Port 9\n")
(write (List map (fn (_ h) (ssh-config-first (ssh-config-read %cf-text "c" h "u" "u" "") "port"))
  (list "git.example.org" "bad.example.org" "other" "elsewhere")))
```
---
    (("2222") () ("9") ())

### Match all, host and user hold; exec never does

```ssh
(import ssh/config ssh-config-read ssh-config-all)
(def %cf-text "Match host a* user root\n Port 1\nMatch exec true\n Port 2\nMatch all\n Port 3\n")
(write (list (ssh-config-all (ssh-config-read %cf-text "c" "abc" "root" "me" "") "port")
             (ssh-config-all (ssh-config-read %cf-text "c" "abc" "jon" "me" "") "port")))
```
---
    ((("1") ("3")) (("3")))

## values

### times: seconds, or numbers with units

```ssh
(import ssh/config ssh-config-time)
(write (List map ssh-config-time (list "90" "1h30m" "2m" "1w" "" "5x" "m")))
```
---
    (90 5400 120 604800 () () ())

### patterns: `*` and `?`, case aside

```ssh
(import ssh/config ssh-config-patterns?)
(write (list (ssh-config-patterns? (list "*.ORG") "a.example.org") (ssh-config-patterns? (list "h?st") "host")
             (ssh-config-patterns? (list "*" "!h*") "host") (ssh-config-patterns? (list "LC_*") "LANG")))
```
---
    (#t #t #f #f)

## faults

### a keyword OpenSSH does not know, and one not served unless left off

```ssh
(import ssh/config ssh-config-options ssh-config-faults ssh-config-sshd-keywords)
(write (ssh-config-faults (ssh-config-options (list "Frob yes" "AllowUsers jon" "ForceCommand none" "Port 22"))
         ssh-config-sshd-keywords (list (pair "allowusers" "") (pair "forcecommand" "none")) ()))
```
---
    ("command-line: line 1: Bad configuration option: frob" "command-line: line 1: allowusers is not served")
