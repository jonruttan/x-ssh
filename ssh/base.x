; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/base.x -- the parts, assembled
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; Each part is a module of its own: its first form names it, its private
; names are its own, and what it provides is imported here by name.  This
; file stays unscoped, so those imports bind in the root, where run.x and
; the spec harness reach them; the exports carry the ssh- prefix for that.

(provide ssh/base ssh-version ssh-main ssh-programs ssh-program ssh-plan)

(def ssh-version "0.1.0")

(import ssh/cli ssh-programs ssh-program ssh-plan ssh-main)
