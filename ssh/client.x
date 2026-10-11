; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/client.x -- the client: one command on a host
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; What dbclient does for `dbclient -i key user@host command`: connect,
; exchange versions and keys, authenticate with the key, run the
; command with this process's standard input as its own, pass its output
; through, and leave with its status.  The host
; key is taken as presented and shown: a known_hosts comes later, and
; -y says so as dbclient's does.

(module ssh/client)

(import x/sys/socket)
(import x/sys/file)
(import x/sys/posix)
(import ssh/bytes ssh-copy)
(import ssh/transport ssh-open ssh-engines! ssh-exchange-versions! ssh-kex! ssh-auth-publickey!)
(import ssh/session ssh-exec! ssh-disconnect!)
(import ssh/keys ssh-seed-of-key-file)

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
(def ssh-client-run
  (fn (_ host port user keyfile command trace)
    (def tr (if trace (fn (_ t) (%say 2 (Str8 append "x-ssh: " (%ms) " ms " t "\n"))) ()))
    (def seed (ssh-seed-of-key-file keyfile))
    (def fd (Socket tcp-connect (%address host) port))
    (def c (ssh-open fd tr))
    (ssh-engines! c)
    (ssh-exchange-versions! c)
    (ssh-kex! c)
    (def ok (ssh-auth-publickey! c user seed))
    (if (not (eq? ok #t))
      (do (%say 2 (Str8 append "x-ssh: authentication failed; the server offers " (Str8 join "," ok) "\n"))
          (Socket close fd)
          255)
      (do (unless (null? tr) (tr (Str8 append "authenticated as " user)))
          (def status
            (ssh-exec! c command %stdin
              (fn (_ buf start len) (File write 1 (ssh-copy buf start len) len))
              (fn (_ buf start len) (File write 2 (ssh-copy buf start len) len))))
          (ssh-disconnect! c)
          (Socket close fd)
          (def code (if (null? status) 0 status))
          (unless (null? tr)
            (tr (Str8 append "exit status " ((prim-ref (lit convert) (lit to)) code (Type named STRING) 10))))
          code))))

(provide ssh/client ssh-client-run)
