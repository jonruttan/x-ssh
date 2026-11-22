; # x-ssh -- SSH on x-lang
;
; ## lib/ssh/run.x -- the entry
;
; @description SSH: `x -l ssh -- PROGRAM [ARGS]` runs the client, the
;   server, the key tool or scp, by OpenSSH's names.
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
(module ssh/run)
(import ssh/base ssh-version ssh-main)

(set! %lang-name "SSH")
(set! %lang-version ssh-version)
(set! %repl-prompt "ssh> ")

; The operands: what follows the "--" after the launcher's own options.
; With none the session goes on to the REPL.
(def main
  (fn (_)
    (let ((ops (rest (Sys args (lit program)))))
      (unless (null? ops) (ssh-main ops)))))

(provide ssh/run main)
