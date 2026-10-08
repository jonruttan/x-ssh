; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## run.x -- the entry
;
; @description SSH: `x -l ssh -- PROGRAM [ARGS]` runs the client, the
;   server or a key tool, as Dropbear's multi-purpose binary does.
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
(import ssh/base)

(set! %lang-name "SSH")
(set! %lang-version ssh-version)
(set! %repl-prompt "ssh> ")

; The operands: what follows the "--" after the launcher's own options.
(let ((ops (rest (Sys args (lit program)))))
  (unless (null? ops) (ssh-main ops)))
