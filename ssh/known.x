; # x-ssh -- SSH on x-lang
;
; ## ssh/known.x -- known_hosts
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; OpenSSH's known_hosts: a line a host, `NAMES TYPE KEY`, NAMES a comma
; list, a name `host` for port 22 and `[host]:port` for any other, KEY the
; key's blob in base64.  A server's key is looked up by its name and its
; type in each file the configuration names: the same key is known,
; another is a changed key -- refused, since that is what a man in the
; middle looks like -- and none is an unknown host, recorded in the
; first file when the policy accepts it.  Blank lines, comments and
; @-markers are passed over; hashed names (`|1|...`) match nothing, so a
; host known only by its hash is unknown here.

(module ssh/known)

(import x/sys/file)
(import x/sys/posix)
(import x/codec/base64)
(import ssh/bytes ssh-out ssh-put-text ssh-put-string ssh-out-run)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %byte-len (prim-ref (lit str) (lit byte-len)))

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

; The file's lines, numbered from 1: ((NO . TEXT) ...); () when it cannot
; be read.
(def %lines
  (fn (_ path)
    (def text (guard (e ()) (File read-all path)))
    (if (null? text) ()
      ((fn (self ls no acc) (if (null? ls) (List reverse acc) (self (rest ls) (+ no 1) (pair (pair no (first ls)) acc))))
       (Str8 split "\n" text) 1 ()))))

; Whether a line is an entry naming name: (TYPE KEY64), or ().
(def %entry
  (fn (_ text name)
    (def ws (%words text))
    (if (if (< (List length ws) 3) #t
          (if (str=? (Str8 sub 0 1 (first ws)) "#") #t (str=? (Str8 sub 0 1 (first ws)) "@")))
      ()
      (if (List any? (fn (_ n) (str=? n name)) (Str8 split "," (first ws)))
        (list (List ref 1 ws) (List ref 2 ws))
        ()))))

; The lines of a file naming name: ((NO . TEXT) ...).
(def ssh-known-find
  (fn (_ path name)
    (List filter (fn (_ l) (not (null? (%entry (rest l) name)))) (%lines path))))

; What the files say of a server's Ed25519 key: (known), (changed FILE
; NO), the first entry of its type holding another key, or (unknown).
(def ssh-known-check
  (fn (_ files name key)
    (def want (%blob64 key))
    (def seen
      (List flat-map
        (fn (_ f)
          (List flat-map
            (fn (_ l)
              (def e (%entry (rest l) name))
              (if (if (null? e) #t (not (str=? (first e) "ssh-ed25519"))) () (list (list (List ref 1 e) f (first l)))))
            (%lines f)))
        files))
    (match
      ((null? seen) (list (lit unknown)))
      ((List any? (fn (_ s) (str=? (first s) want)) seen) (list (lit known)))
      (#t (list (lit changed) (List ref 1 (first seen)) (List ref 2 (first seen)))))))

; The key recorded for the name in path, its directory made if missing.
(def ssh-known-add!
  (fn (_ path name key)
    (def slash ((fn (self i) (if (< i 0) () (if (= (%byte-ref path i) #\/) i (self (- i 1))))) (- (Str8 length path) 1)))
    (def dir (if (if (null? slash) #t (= slash 0)) () (Str8 sub 0 slash path)))
    (unless (if (null? dir) #t (File exists? dir)) (File mkdir dir 448))
    (def line (Str8 append name " ssh-ed25519 " (%blob64 key) "\n"))
    (def fd (File open path (list (lit wronly) (lit creat) (lit append)) 420))
    (when (< fd 0) (Err raise 'io (Str8 append "cannot write " path) ()))
    (File write fd line (%byte-len line))
    (File close fd)))

; The lines naming name taken out of path, its old text kept as
; path.old; answers the numbers of the lines taken.
(def ssh-known-remove!
  (fn (_ path name)
    (def text (File read-all path))
    (def ls (%lines path))
    (def gone (List filter (fn (_ l) (not (null? (%entry (rest l) name)))) ls))
    (unless (null? gone)
      (do (def kept (List map rest (List filter (fn (_ l) (null? (%entry (rest l) name))) ls)))
          (def body (Str8 join "\n" kept))
          (def old (Str8 append path ".old"))
          (File write-all old text)
          (File write-all path body)))
    (List map first gone)))

(provide ssh/known ssh-known-name ssh-known-check ssh-known-add! ssh-known-find ssh-known-remove!)
