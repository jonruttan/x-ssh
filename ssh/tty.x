; # x-ssh -- SSH on x-lang
;
; ## ssh/tty.x -- a terminal's modes on the wire
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; The encoded terminal modes a pty-req carries (RFC 4254 8): an opcode
; byte and a uint32 for each, ended by TTY_OP_END.  The modes are x-lang
; Term's, by name: a control character's code, () when it is turned off,
; which goes as 255, as OpenSSH sends _POSIX_VDISABLE; a flag's BOOL as 1
; or 0; and the speeds in baud.

(module ssh/tty)

(import ssh/bytes ssh-out ssh-put-byte ssh-put-uint32 ssh-out-run ssh-in ssh-get-byte ssh-get-uint32)

(def %opcodes
  (list (pair 'vintr 1) (pair 'vquit 2) (pair 'verase 3) (pair 'vkill 4) (pair 'veof 5)
        (pair 'veol 6) (pair 'veol2 7) (pair 'vstart 8) (pair 'vstop 9) (pair 'vsusp 10)
        (pair 'vdsusp 11) (pair 'vreprint 12) (pair 'vwerase 13) (pair 'vlnext 14) (pair 'vflush 15)
        (pair 'vswtch 16) (pair 'vstatus 17) (pair 'vdiscard 18)
        (pair 'ignpar 30) (pair 'parmrk 31) (pair 'inpck 32) (pair 'istrip 33) (pair 'inlcr 34)
        (pair 'igncr 35) (pair 'icrnl 36) (pair 'iuclc 37) (pair 'ixon 38) (pair 'ixany 39)
        (pair 'ixoff 40) (pair 'imaxbel 41) (pair 'iutf8 42)
        (pair 'isig 50) (pair 'icanon 51) (pair 'xcase 52) (pair 'echo 53) (pair 'echoe 54)
        (pair 'echok 55) (pair 'echonl 56) (pair 'noflsh 57) (pair 'tostop 58) (pair 'iexten 59)
        (pair 'echoctl 60) (pair 'echoke 61) (pair 'pendin 62)
        (pair 'opost 70) (pair 'olcuc 71) (pair 'onlcr 72) (pair 'ocrnl 73) (pair 'onocr 74) (pair 'onlret 75)
        (pair 'cs7 90) (pair 'cs8 91) (pair 'parenb 92) (pair 'parodd 93)
        (pair 'ispeed 128) (pair 'ospeed 129)))

; A control character's opcode: 1 to 18.
(def %char? (fn (_ op) (< op 30)))

; The modes as a pty-req carries them: (BUF . LEN), each mode an opcode
; has, in the order given, then TTY_OP_END.
(def ssh-tty-modes-encode
  (fn (_ modes)
    (def out (ssh-out))
    (List for-each
      (fn (_ m)
        (def row (List find (fn (_ r) (eq? (first r) (first m))) %opcodes))
        (unless (null? row)
          (do (ssh-put-byte out (rest row))
              (ssh-put-uint32 out
                (match
                  ((null? (rest m)) 255)
                  ((eq? (rest m) #t) 1)
                  ((eq? (rest m) #f) 0)
                  (#t (rest m)))))))
      modes)
    (ssh-put-byte out 0)
    (ssh-out-run out)))

; The modes len bytes of s from start encode, as (NAME . VALUE) in their
; order: a character 255 as (), a flag as a BOOL, a speed as its baud.
; An opcode with no name here is passed over, its uint32 with it; TTY_OP_END,
; an opcode of 160 or more, whose argument is undefined, or the end of
; the bytes ends them.
(def ssh-tty-modes-decode
  (fn (_ s start len)
    (def in (ssh-in s start len))
    ((fn (self acc)
       (def op (guard (e 0) (ssh-get-byte in)))
       (if (if (= op 0) #t (>= op 160)) (List reverse acc)
         (do (def v (guard (e ()) (ssh-get-uint32 in)))
             (def row (List find (fn (_ r) (= (rest r) op)) %opcodes))
             (match
               ((null? v) (List reverse acc))
               ((null? row) (self acc))
               ((%char? op) (self (pair (pair (first row) (if (= v 255) () v)) acc)))
               ((>= op 128) (self (pair (pair (first row) v) acc)))
               (#t (self (pair (pair (first row) (not (= v 0))) acc)))))))
     ())))

(provide ssh/tty ssh-tty-modes-encode ssh-tty-modes-decode)
