# public keys and signatures
# @weight 4
# @timeout-scale 4

ssh/pubkey reads the key types a signature is checked by -- Ed25519, RSA,
ECDSA over P-256 and P-384 -- from their blobs, and checks a signature by
one.  The keys are ones `ssh-keygen` made; their sizes and fingerprints
are what `ssh-keygen -l` printed for them; the signatures are what
`openssl dgst -sign` made over "abc" with the same keys, RSA's PKCS#1
v1.5 over SHA-256 and SHA-512, ECDSA's r and s over SHA-256 and SHA-384,
each wrapped in its SSH signature blob here.

## keys

### type, label, size and fingerprint, as ssh-keygen -l says them

```ssh
(import ssh/pubkey ssh-pubkey-of-line ssh-pubkey-type ssh-pubkey-label ssh-pubkey-bits ssh-pubkey-blob)
(import ssh/keygen ssh-blob-fingerprint)
(write (List map (fn (_ l) ((fn (_ k) (list (ssh-pubkey-type k) (ssh-pubkey-label k) (ssh-pubkey-bits k) (ssh-blob-fingerprint (ssh-pubkey-blob k))))
                            (ssh-pubkey-of-line (first l) (List ref 1 l))))
  (list (list "ssh-rsa" "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/+umrNG51+cU9uuLwDJXC3+PUiD6y11Wb4Jtd/EEuajzeEg90KwVPmmSW1cafMP3vVhvUan1YtHh0j4m6W752K3Ab8IC7fGSdnETGcdE9/LXUVazudibhM1X6g+M1fLVuJaQrcZM8l9u4N4LAo6n8+fdqyNAV4wXEih7sVKAW9bNAOUAB2EagIznQMrfJjJ4nDkNVXMmrXoYkq6/Gui6wgqJ4Uw3VBirdt7Z+4oqQG94Et2OsAGG2NKFkqMmrYmRS2Wq4ezgim0HoMz9hRq2ujEokKut/eNCH0O7B331GTslrmLDWUoEeoqJCmp4zBol1iJBgoicBzEocybooemaX")
        (list "ecdsa-sha2-nistp256" "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLX31fQAHPdmtmUdf67Ug1xJSaWeALMMHdzPlyPXL6ROYHM3/PLN9scb0XkCd6DoqRSg2VjpJZ6rOJY4mO/1mng=")
        (list "ecdsa-sha2-nistp384" "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDu91D+1D4Ofj4u0hmgAkiJn+3/Lert9AEAda2ybM/0bK2zGihl17tpCuUVQINbehE9wtNkl7DYfuX6VledGJEyAxGTMvyujgGhAjxNo7D5D8XtHLz1By5tllAybbP6o8g=="))))
```
---
    (("ssh-rsa" "RSA" 2048 "SHA256:gVf7sxNgCrMbt2iWVJPOYtlMYr0p75BX94v9nbOM7Rs") ("ecdsa-sha2-nistp256" "ECDSA" 256 "SHA256:JGfFQyUtZG/jdtmovlbLUndGvrZphD4yp4G5gS3lBi4") ("ecdsa-sha2-nistp384" "ECDSA" 384 "SHA256:azhhEiDPvcAh34bnJysfcZj+LrfPLyDss1wVIM9pn4Q"))

### a line whose type is not its blob's, or not a type served, is ()

```ssh
(import ssh/pubkey ssh-pubkey-of-line)
(write (list (ssh-pubkey-of-line "ssh-ed25519" "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/+umrNG51+cU9uuLwDJXC3+PUiD6y11Wb4Jtd/EEuajzeEg90KwVPmmSW1cafMP3vVhvUan1YtHh0j4m6W752K3Ab8IC7fGSdnETGcdE9/LXUVazudibhM1X6g+M1fLVuJaQrcZM8l9u4N4LAo6n8+fdqyNAV4wXEih7sVKAW9bNAOUAB2EagIznQMrfJjJ4nDkNVXMmrXoYkq6/Gui6wgqJ4Uw3VBirdt7Z+4oqQG94Et2OsAGG2NKFkqMmrYmRS2Wq4ezgim0HoMz9hRq2ujEokKut/eNCH0O7B331GTslrmLDWUoEeoqJCmp4zBol1iJBgoicBzEocybooemaX") (ssh-pubkey-of-line "ssh-dss" "AAAAB3NzaC1kc3M=")))
```
---
    (() ())

## signatures

### RSA over SHA-256 and SHA-512, ECDSA over P-256 and P-384; not over another message, and never SHA-1's ssh-rsa

```ssh
(import x/codec/hex)
(import ssh/bytes ssh-out ssh-put-text ssh-put-string ssh-put-mpint ssh-out-run)
(import ssh/pubkey ssh-pubkey-of-line ssh-pubkey-verify?)
(def %pk-buf
  (fn (_ hex)
    (def bs (Hex decode-bytes hex))
    (def r ((prim-ref (lit str) (lit make)) (+ (List length bs) 1)))
    (def p ((prim-ref (lit str) (lit ->ptr)) r))
    ((fn (self i bs) (unless (null? bs) (do ((prim-ref (lit ptr) (lit set!)) p i (first bs) 1) (self (+ i 1) (rest bs))))) 0 bs)
    (pair r (List length bs))))
(def %pk-rsa-sig
  (fn (_ alg hex)
    (def s (%pk-buf hex))
    (def o (ssh-out)) (ssh-put-text o alg) (ssh-put-string o (first s) 0 (rest s))
    ((fn (_ r) (list (first r) 0 (rest r))) (ssh-out-run o))))
(def %pk-ec-sig
  (fn (_ alg r s)
    (def rb (%pk-buf r)) (def sb (%pk-buf s))
    (def i (ssh-out)) (ssh-put-mpint i (first rb) 0 (rest rb)) (ssh-put-mpint i (first sb) 0 (rest sb))
    (def ir (ssh-out-run i))
    (def o (ssh-out)) (ssh-put-text o alg) (ssh-put-string o (first ir) 0 (rest ir))
    ((fn (_ x) (list (first x) 0 (rest x))) (ssh-out-run o))))
(def %pk-rsa (ssh-pubkey-of-line "ssh-rsa" "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/+umrNG51+cU9uuLwDJXC3+PUiD6y11Wb4Jtd/EEuajzeEg90KwVPmmSW1cafMP3vVhvUan1YtHh0j4m6W752K3Ab8IC7fGSdnETGcdE9/LXUVazudibhM1X6g+M1fLVuJaQrcZM8l9u4N4LAo6n8+fdqyNAV4wXEih7sVKAW9bNAOUAB2EagIznQMrfJjJ4nDkNVXMmrXoYkq6/Gui6wgqJ4Uw3VBirdt7Z+4oqQG94Et2OsAGG2NKFkqMmrYmRS2Wq4ezgim0HoMz9hRq2ujEokKut/eNCH0O7B331GTslrmLDWUoEeoqJCmp4zBol1iJBgoicBzEocybooemaX"))
(def %pk-p256 (ssh-pubkey-of-line "ecdsa-sha2-nistp256" "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLX31fQAHPdmtmUdf67Ug1xJSaWeALMMHdzPlyPXL6ROYHM3/PLN9scb0XkCd6DoqRSg2VjpJZ6rOJY4mO/1mng="))
(def %pk-p384 (ssh-pubkey-of-line "ecdsa-sha2-nistp384" "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDu91D+1D4Ofj4u0hmgAkiJn+3/Lert9AEAda2ybM/0bK2zGihl17tpCuUVQINbehE9wtNkl7DYfuX6VledGJEyAxGTMvyujgGhAjxNo7D5D8XtHLz1By5tllAybbP6o8g=="))
(def %pk-abc (list "abc" 0 3))
(def %pk-abd (list "abd" 0 3))
(write (list (ssh-pubkey-verify? %pk-rsa (%pk-rsa-sig "rsa-sha2-256" "72a8d30741b8eb0c9c307a7062ea6df3443031e1639238a8b73bb0eaf15d31f17fec560a0777b90a08c6eabd9a5888eb39a68d82bba62ee6516eff9fda72431e9caa5ab0892c5451905acafad00e8b8aaf7443147249ed939a9159a81cc90624de93f8bdbc6761d6033b56d667e50082489dca8fc58f2b5567f57faa88ff94dd1e69ff8956a7d8a031f7ab95e8b561e99b70d7dc6e07469f67734bad7d93bb5d46898c14c2b3ba912662ba379867b1e88cf9be51899da5259d1b1eceffe5cfe57e30587e7b3271ee26c771e5b9553e9f68420bbfac741936e77f62ccc0b2f93c73f3a9e45f15ca5528e4c780d36636335b2b4ae8c85c13c8b3bb038528c438ff") %pk-abc)
             (ssh-pubkey-verify? %pk-rsa (%pk-rsa-sig "rsa-sha2-512" "529506b6fd8437093a2ad569e341e8e61956aa048e4e41cc82778d8f17036b5df097b66d3f549af9715d806ec25ce978fe375b5a13c163b948736a182500cfdc439b9a81a56110ed6e6b218155727fd1724c9aaf0119833fd71147f49f2878afd5f444ba9031924e511c5e1a2aa2107494354b6212bb0a9c0945be822dc720530e6cc8679b9b4429d509020fe953733181a0faacecfbfdc1d7f0baf7d7892b47664d15be92df23627048d747f0722a483d688a485db37e092ed3cd488562f366165968d7cf37779b0037c2b0e3bb22f7efa5bdcf444c13c7405c106e2d4da1631bf3bfe110ef93dc493eccfbe6a2ce1e853c96dcb4d4991cd04a9a9fa53e19e1") %pk-abc)
             (ssh-pubkey-verify? %pk-p256 (%pk-ec-sig "ecdsa-sha2-nistp256" "36A8CF06684D13DB96746500700FB9AD007804D6A3F188023EB0B3B030D1B7CE" "6E6D273D4DBE7E044970A8293606A8D849BB45C62A590520FE1B4754AF54DD72") %pk-abc)
             (ssh-pubkey-verify? %pk-p384 (%pk-ec-sig "ecdsa-sha2-nistp384" "2014731B18319CB7AAD9C0255D93DBB7907D99C7EF9C91E7D1F8078CD2B7FAB5DDF2A8A3698C4BCCC6638C7EAB2753E0" "0B755E19E4A1C83E4CC2C288481F3A0A4477B6CB6D1EAC394896DFE6449CADDFBE73CA03C8113DD6306E292C5251C2F5") %pk-abc)
             (ssh-pubkey-verify? %pk-rsa (%pk-rsa-sig "rsa-sha2-256" "72a8d30741b8eb0c9c307a7062ea6df3443031e1639238a8b73bb0eaf15d31f17fec560a0777b90a08c6eabd9a5888eb39a68d82bba62ee6516eff9fda72431e9caa5ab0892c5451905acafad00e8b8aaf7443147249ed939a9159a81cc90624de93f8bdbc6761d6033b56d667e50082489dca8fc58f2b5567f57faa88ff94dd1e69ff8956a7d8a031f7ab95e8b561e99b70d7dc6e07469f67734bad7d93bb5d46898c14c2b3ba912662ba379867b1e88cf9be51899da5259d1b1eceffe5cfe57e30587e7b3271ee26c771e5b9553e9f68420bbfac741936e77f62ccc0b2f93c73f3a9e45f15ca5528e4c780d36636335b2b4ae8c85c13c8b3bb038528c438ff") %pk-abd)
             (ssh-pubkey-verify? %pk-p256 (%pk-ec-sig "ecdsa-sha2-nistp256" "36A8CF06684D13DB96746500700FB9AD007804D6A3F188023EB0B3B030D1B7CE" "6E6D273D4DBE7E044970A8293606A8D849BB45C62A590520FE1B4754AF54DD72") %pk-abd)
             (ssh-pubkey-verify? %pk-rsa (%pk-rsa-sig "ssh-rsa" "72a8d30741b8eb0c9c307a7062ea6df3443031e1639238a8b73bb0eaf15d31f17fec560a0777b90a08c6eabd9a5888eb39a68d82bba62ee6516eff9fda72431e9caa5ab0892c5451905acafad00e8b8aaf7443147249ed939a9159a81cc90624de93f8bdbc6761d6033b56d667e50082489dca8fc58f2b5567f57faa88ff94dd1e69ff8956a7d8a031f7ab95e8b561e99b70d7dc6e07469f67734bad7d93bb5d46898c14c2b3ba912662ba379867b1e88cf9be51899da5259d1b1eceffe5cfe57e30587e7b3271ee26c771e5b9553e9f68420bbfac741936e77f62ccc0b2f93c73f3a9e45f15ca5528e4c780d36636335b2b4ae8c85c13c8b3bb038528c438ff") %pk-abc)))
```
---
    (#t #t #t #t #f #f #f)

## identities

An RSA key `ssh-keygen -t rsa -b 1024` made and an ECDSA one `-t ecdsa`
made, their private files read; the signatures `openssl dgst -sign`
made over "abc" with the same keys, ECDSA's with `-sigopt nonce-type:1`,
RFC 6979's nonce.

### an identity's signatures are openssl's, each one its key verifies, and its file written reads back

```ssh
(import ssh/keys ssh-key-identity-of-text)
(import ssh/keygen ssh-identity-openssh-text)
(import ssh/bytes ssh-same-bytes?)
(import ssh/pubkey ssh-identity-pubkey ssh-identity-comment ssh-identity-sign ssh-pubkey-verify? ssh-pubkey-base64)
(def %id-rsa (ssh-key-identity-of-text (Str8 join "\n" (list
    "-----BEGIN OPENSSH PRIVATE KEY-----"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn"
    "NhAAAAAwEAAQAAAIEA4YUu1IKFPCCjPjqhRwiCOnd//TwuePnztcAVzQWNQODaKXiUiVy1"
    "Clm8mJJTX6ScEFFb41zyNCJVYsT8SREh/NGnjrFl4VNcry/UBiSBUDNQRPI6B2Fvz7Ij8N"
    "l2CuDz5eemsJQRJACbwYL/lSQkDBX148GEbbwUr8IK7xr6XIkAAAIAXZtoLV2baC0AAAAH"
    "c3NoLXJzYQAAAIEA4YUu1IKFPCCjPjqhRwiCOnd//TwuePnztcAVzQWNQODaKXiUiVy1Cl"
    "m8mJJTX6ScEFFb41zyNCJVYsT8SREh/NGnjrFl4VNcry/UBiSBUDNQRPI6B2Fvz7Ij8Nl2"
    "CuDz5eemsJQRJACbwYL/lSQkDBX148GEbbwUr8IK7xr6XIkAAAADAQABAAAAgH8gA1D5rj"
    "9BqqO2ixkum7J3kGdgmFXLmGzYtbFXstNirLf558kywD7wbNaYjXT5ppuwMRsOVt26iOVf"
    "Y1OQ29XINJLBFxIgeroaZxaRI+wrQooj3hL9G12iZY6TrgrVyv4hihJNpOsrCOihiFuNr8"
    "H5nN/DmqEqsLci7t/iP5OBAAAAQQCeRlkeZ4k/GzLbYQEEKtmmkCJ4UT7dm7AyB3uiHHcZ"
    "4loeJZ1MO6m/JvDhTcTX/0ZAyw1I1Y5caOICjWT1eh+IAAAAQQDzAoSUWYPI333s1Q6yms"
    "bGKmfleZFHH+O3ZCklXVeQtNu99u9KFfDlMBQUJ/0bfXEcxZk4kWspqhHEzueGYFWxAAAA"
    "QQDtk1Pm8XhazPKxiRgqNeKtowCTNIo7ZEFI0Q5F2WpzLfVyU/zNZH07udFhcoSqTyRycZ"
    "fRQcCrVgtchfSuwDJZAAAACHJzYUBzcGVjAQI="
    "-----END OPENSSH PRIVATE KEY-----"
    "")) ""))
(def %id-ec (ssh-key-identity-of-text (Str8 join "\n" (list
    "-----BEGIN OPENSSH PRIVATE KEY-----"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS"
    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRjgIFo/x48IXNxY0y8JauL++ZzXPag"
    "zond/aO5vqEP52IV1wGx2G9oVFtblxNuU/5//aD7IOP1JSCCM+QbCsCKAAAAqHwGOKZ8Bj"
    "imAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOAgWj/Hjwhc3Fj"
    "TLwlq4v75nNc9qDOid39o7m+oQ/nYhXXAbHYb2hUW1uXE25T/n/9oPsg4/UlIIIz5BsKwI"
    "oAAAAgD/Az9JQItj3tni7jIPkr+QrwEAxJBad8HlVv/Syb3RAAAAAKZWNkc2FAc3BlYwEC"
    "AwQFBg=="
    "-----END OPENSSH PRIVATE KEY-----"
    "")) ""))
(def %id-same? (fn (_ a b) (if (= (List ref 2 a) (List ref 2 b)) (ssh-same-bytes? (first a) (List ref 1 a) (first b) (List ref 1 b) (List ref 2 a)) #f)))
(def %id-check
  (fn (_ id alg want)
    (def sig (ssh-identity-sign id %pk-abc alg))
    (list (%id-same? sig want) (ssh-pubkey-verify? (ssh-identity-pubkey id) sig %pk-abc))))
(def %id-back
  (fn (_ id)
    ((fn (_ b) (list (str=? (ssh-pubkey-base64 (ssh-identity-pubkey b)) (ssh-pubkey-base64 (ssh-identity-pubkey id))) (ssh-identity-comment b)))
     (ssh-key-identity-of-text (ssh-identity-openssh-text id (ssh-identity-comment id)) ""))))
(write (list (%id-check %id-rsa "rsa-sha2-256" (%pk-rsa-sig "rsa-sha2-256" "2aadf8def2cbc5bd05ffe8f4abcb3064f0dc87e82809d55c756c3c574aa0c595cdb580fc5b68d7ccca6b83117fac066b0ca8590f0b1dc89e07b1f730f04e643c387579362f40e69168e1ae38f67988c68bf16c12bf5251e5b136ef2cf65731291bfc553b0c0564a42a79380ec35f5b6618300ef5cf9dbecf991709c0ebb6bdff"))
             (%id-check %id-rsa "rsa-sha2-512" (%pk-rsa-sig "rsa-sha2-512" "7cb30148324c1c338e5f070cae7dbf878921820813068bdd3bd4fd14fdf3995d248ffecf7f876d094672cb47f82bdd0500ff72926e138ea25be164a63399c15a63d887efadfca47fc030462cc76b14bfe3faace9cbcda8102f715f45c08cdd395f8e2ad0a9f0551a30825ec853011d336e6c9b39310028427563f33195c6c5c8"))
             (%id-check %id-ec "ecdsa-sha2-nistp256" (%pk-ec-sig "ecdsa-sha2-nistp256" "454578510951193E69E84DFF142249CDAB09F6CEEE72F8AD308CEFD08D957522" "316CA21ACB9537ED74C2F48DE37FA2F06E53D363FF410058E98CFC8149D70DDB"))
             (%id-back %id-rsa) (%id-back %id-ec)))
```
---
    ((#t #t) (#t #t) (#t #t) (#t "rsa@spec") (#t "ecdsa@spec"))
