; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/known.x -- the hosts this user has seen
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; ~/.ssh/known_hosts, OpenSSH's file and Dropbear's client's: a line a
; host, `NAMES TYPE KEY`, NAMES a comma list, a name `host` for port 22
; and `[host]:port` for any other, KEY the key's blob in base64.  A
; server's key is looked up by its name and its type: the same key is
; known, another is a changed key -- refused, since that is what a man in
; the middle looks like -- and none is an unknown host, recorded when the
; caller accepts it.  Blank lines, comments and @-markers are passed over;
; hashed names (`|1|...`) match nothing, so a host known only by its hash
; is unknown here.

(module ssh/known)

(import x/sys/file)
(import x/sys/posix)
(import x/codec/base64)
(import ssh/bytes ssh-out ssh-put-text ssh-put-string ssh-out-run)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))

; The file: $HOME/.ssh/known_hosts.
(def %dir (fn (_) (Str8 append (Sys getenv "HOME") "/.ssh")))
(def %file (fn (_) (Str8 append (%dir) "/known_hosts")))

; A host's name in the file, by its port.
(def ssh-known-name
  (fn (_ host port)
    (if (= port 22) host
      (Str8 append "[" host "]:" ((prim-ref (lit convert) (lit to)) port (Type named STRING) 10)))))

; An Ed25519 key's blob in base64, as the file spells it.
(def %blob64
  (fn (_ key)
    (def out (ssh-out))
    (ssh-put-text out "ssh-ed25519")
    (ssh-put-string out key 0 32)
    (def r (ssh-out-run out))
    (Base64 encode-bytes
      ((fn (self i acc)
         (if (< i 0) acc (self (- i 1) (pair (%char->int (%byte-ref (first r) i)) acc))))
       (- (rest r) 1) ()))))

; A line's words, split on spaces and tabs.
(def %words
  (fn (_ line)
    (List filter (fn (_ w) (> (Str8 length w) 0))
      (Str8 split " " (Str8 join " " (Str8 split "\t" line))))))

; The file's entries for a name: ((TYPE . KEY64) ...).
(def %entries
  (fn (_ name)
    (def path (%file))
    (if (not (File exists? path)) ()
      ((fn (self lines acc)
         (if (null? lines) acc
           (do (def ws (%words (first lines)))
               (self (rest lines)
                 (if (if (< (List length ws) 3) #t
                       (match ((str=? (Str8 sub 0 1 (first ws)) "#") #t)
                              ((str=? (Str8 sub 0 1 (first ws)) "@") #t)
                              (#t #f)))
                   acc
                   (if (List any? (fn (_ n) (str=? n name)) (Str8 split "," (first ws)))
                     (pair (pair (List ref 1 ws) (List ref 2 ws)) acc)
                     acc))))))
       (Str8 split "\n" (File read-all path)) ()))))

; What the file says of a server's Ed25519 key: known, changed or unknown.
(def ssh-known-check
  (fn (_ name key)
    (def want (%blob64 key))
    (def same-type (List filter (fn (_ e) (str=? (first e) "ssh-ed25519")) (%entries name)))
    (match
      ((null? same-type) (lit unknown))
      ((List any? (fn (_ e) (str=? (rest e) want)) same-type) (lit known))
      (#t (lit changed)))))

; The key recorded for the name, the directory made if it is missing.
(def ssh-known-add!
  (fn (_ name key)
    (unless (File exists? (%dir)) (File mkdir (%dir) 448))
    (def line (Str8 append name " ssh-ed25519 " (%blob64 key) "\n"))
    (def fd (File open (%file) (list (lit wronly) (lit creat) (lit append)) 420))
    (when (< fd 0) (Err raise 'io (Str8 append "ssh: cannot write " (%file)) ()))
    (File write fd line (%byte-len line))
    (File close fd)))

(provide ssh/known ssh-known-name ssh-known-check ssh-known-add!)
