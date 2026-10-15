; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/client.x -- the client: one command on a host
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What dbclient does for `dbclient -i key user@host command`: connect,
; exchange versions and keys, check the server's key against
; known_hosts, authenticate with the key, run the command with this
; process's standard input as its own, pass its output through, and
; leave with its status.  An unknown host is refused unless -y accepts
; it, which records its key; a changed key is always refused.

(module ssh/client)

(import x/sys/socket)
(import x/sys/file)
(import x/sys/posix)
(import ssh/bytes ssh-copy)
(import ssh/transport ssh-open ssh-host-key ssh-engines! ssh-exchange-versions! ssh-kex!
  ssh-auth-service! ssh-auth-publickey! ssh-auth-password!)
(import ssh/session ssh-session-run! ssh-disconnect!)
(import ssh/keys ssh-seed-of-key-file)
(import ssh/known ssh-known-name ssh-known-check ssh-known-add!)

(def %byte-len (prim-ref (lit str) (lit byte-len)))

(def %say (fn (_ fd text) (File write fd text (%byte-len text))))

; The caller's standard input.  The platform keeps it on fd 3, fd 0
; carrying x's own program text; with none, fd 3 is not open, a read of
; it fails, and the command's input ends at once.
(def %stdin 3)

; The process's CPU time in milliseconds, as text: what -v stamps each
; trace line with.
(def %ms
  (fn (_)
    ((prim-ref (lit convert) (lit to)) (/ (Sys clock) 1000) (Type named STRING) 10)))

; A dotted address for a name: what the resolver says, or the name when
; it already is one.
(def %address
  (fn (_ host)
    (def r (Socket resolve host))
    (if (null? r) host (if (pair? r) (first r) r))))

; The command run; its exit status, or 255 when the connection failed.
; The server's key against known_hosts, before any credential is sent:
; #t to go on, or a message to refuse with.  An unknown host is recorded
; when the caller accepts it; a changed key is refused whatever it says.
(def %host-key-ok
  (fn (_ c host port accept tr)
    (def name (ssh-known-name host port))
    (def key (ssh-host-key c))
    (def seen (ssh-known-check name key))
    (match
      ((eq? seen (lit known)) (do (unless (null? tr) (tr (Str8 append "host key known for " name))) #t))
      ((eq? seen (lit changed))
        (Str8 append "x-ssh: the ssh-ed25519 key of host '" name "' differs from the one in known_hosts; refusing\n"))
      (accept
        (do (ssh-known-add! name key)
            (%say 2 (Str8 append "x-ssh: host '" name "' is not in known_hosts; its ssh-ed25519 key is added\n"))
            #t))
      (#t (Str8 append "x-ssh: host '" name "' is not in known_hosts; -y accepts and records its key\n")))))

(def ssh-client-run
  (fn (_ host port user keyfile command trace accept forwards remotes netcat limits)
    (def tr (if trace (fn (_ t) (%say 2 (Str8 append "x-ssh: " (%ms) " ms " t "\n"))) ()))
    (def seed (if (null? keyfile) () (ssh-seed-of-key-file keyfile)))
    (def fd (Socket tcp-connect (%address host) port))
    (def c (ssh-open fd tr))
    (ssh-engines! c)
    (ssh-exchange-versions! c)
    (ssh-kex! c)
    (def known (%host-key-ok c host port accept tr))
    (if (not (eq? known #t))
      (do (%say 2 known) (Socket close fd) 255)
      (%authenticated-run c fd user seed command tr forwards remotes netcat limits))))

; The forwards' listen addresses resolved: "localhost" and any name to
; the dotted address the listener binds, () left as every interface.
(def %forwards-resolved
  (fn (_ forwards)
    (List map (fn (_ f) (pair (if (null? (first f)) () (%address (first f))) (rest f))) forwards)))

; The password Dropbear's client takes from its environment, or ().
(def %password
  (fn (_) ((fn (_ p) (if (if (null? p) #t (= (Str8 length p) 0)) () p)) (Sys getenv "DROPBEAR_PASSWORD"))))

; Authentication as Dropbear's client tries it: the key when there is one,
; then DROPBEAR_PASSWORD when the server offers password.  #t, or the
; server's remaining methods.
(def %authenticate
  (fn (_ c user seed tr)
    (ssh-auth-service! c)
    (def by-key (if (null? seed) (list "password") (ssh-auth-publickey! c user seed)))
    (def password (%password))
    (if (if (eq? by-key #t) #t (if (null? password) #t (not (List any? (fn (_ m) (str=? m "password")) by-key))))
      by-key
      (do (unless (null? tr) (tr "trying password"))
          (ssh-auth-password! c user password)))))

(def %authenticated-run
  (fn (_ c fd user seed command tr forwards remotes netcat limits)
    (def ok (%authenticate c user seed tr))
    (if (not (eq? ok #t))
      (do (%say 2 (Str8 append "x-ssh: authentication failed; the server offers " (Str8 join "," ok) "\n"))
          (Socket close fd)
          255)
      (do (unless (null? tr) (tr (Str8 append "authenticated as " user)))
          (def status
            (ssh-session-run! c command (if (if (null? command) (null? netcat) #f) () %stdin)
              (fn (_ buf start len) (File write 1 (ssh-copy buf start len) len))
              (fn (_ buf start len) (File write 2 (ssh-copy buf start len) len))
              (%forwards-resolved forwards) remotes
              (if (null? netcat) () (pair (%address (first netcat)) (rest netcat)))
              limits))
          (ssh-disconnect! c)
          (Socket close fd)
          (def code (if (null? status) 0 status))
          (unless (null? tr)
            (tr (Str8 append "exit status " ((prim-ref (lit convert) (lit to)) code (Type named STRING) 10))))
          code))))

(provide ssh/client ssh-client-run)
