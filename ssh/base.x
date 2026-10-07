; # x-ssh -- SSH on x-lang, after Dropbear
;
; ## ssh/base.x -- the parts, assembled
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; The parts share one flat namespace, every name led by ssh- (or %ssh- for
; the ones no caller outside the bundle needs); each part calls the others
; through those names at run time, so the order below is only the order of
; loading.

(provide ssh/base ssh-version ssh-main ssh-argv ssh-programs ssh-program ssh-plan)

(def ssh-version "0.1.0")

(import ssh/cli)
