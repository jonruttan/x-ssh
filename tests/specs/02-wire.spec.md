# The wire's encodings
# @weight 2

RFC 4251 5, as ssh/bytes writes and reads them: every field binary,
NULs included, so a round trip is read back by count.

## writing

### byte, uint32, string, bool and name-list, as bytes

```x
(do
  (import x/codec/hex)
  (import ssh/bytes ssh-out ssh-put-byte ssh-put-bool ssh-put-uint32 ssh-put-text ssh-put-names ssh-out-run)
  (def %w-bref (prim-ref (lit str) (lit byte-ref)))
  (def %w-c->i (prim-ref (lit char) (lit ->int)))
  (def %w-hex
    (fn (_ r)
      (Hex encode-bytes
        ((fn (self i acc) (if (< i 0) acc (self (- i 1) (pair (%w-c->i (%w-bref (first r) i)) acc))))
         (- (rest r) 1) ()))))
  (def o (ssh-out))
  (ssh-put-byte o 20)
  (ssh-put-bool o #t)
  (ssh-put-uint32 o 258)
  (ssh-put-text o "ab")
  (ssh-put-names o (list "none" "zlib"))
  (display (%w-hex (ssh-out-run o))))
```
---
    140100000102000000026162000000096e6f6e652c7a6c6962

### an mpint drops leading zeros and keeps the number positive

RFC 4251's own examples: 0 is the empty string; 9a378f9b2e332a7 has no
lead byte; 80 gets one; and a value under 128 is itself.

```x
(do
  (import x/codec/hex)
  (import ssh/bytes ssh-out ssh-put-mpint ssh-out-run)
  (def %w-bref (prim-ref (lit str) (lit byte-ref)))
  (def %w-c->i (prim-ref (lit char) (lit ->int)))
  (def %w-hex
    (fn (_ r)
      (Hex encode-bytes
        ((fn (self i acc) (if (< i 0) acc (self (- i 1) (pair (%w-c->i (%w-bref (first r) i)) acc))))
         (- (rest r) 1) ()))))
  (def %w-mp (fn (_ hex) (def o (ssh-out)) (def b (Hex decode hex)) (ssh-put-mpint o b 0 (>> (Str8 length hex) 1)) (%w-hex (ssh-out-run o))))
  (display (list (%w-mp "00000000") (%w-mp "09a378f9b2e332a7") (%w-mp "0080") (%w-mp "7f"))))
```
---
    (00000000 0000000809a378f9b2e332a7 000000020080 000000017f)

## reading

### fields read back, a string as a region of the buffer, and a short packet raises

```x
(do
  (import x/codec/hex)
  (import ssh/bytes ssh-in ssh-in-left ssh-get-byte ssh-get-bool ssh-get-uint32 ssh-get-string ssh-get-text ssh-get-names)
  (def b (Hex decode "140100000102000000026162000000096e6f6e652c7a6c6962"))
  (def in (ssh-in b 0 25))
  (def t (ssh-get-byte in))
  (def flag (ssh-get-bool in))
  (def n (ssh-get-uint32 in))
  (def s (ssh-get-string in))
  (def names (ssh-get-names in))
  (def short (guard (e (lit raised)) (ssh-get-uint32 in)))
  (display (list t flag n s names (ssh-in-left in) short)))
```
---
    (20 #t 258 (10 . 2) (none zlib) 0 raised)
