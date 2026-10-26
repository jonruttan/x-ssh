; # x-ssh -- SSH on x-lang
;
; ## ssh/config.x -- configuration files, as OpenSSH reads them
;
; @author [Jon Ruttan](jonruttan@gmail.com)
; @copyright 2026 Jon Ruttan
; @license MIT No Attribution (MIT-0)
;
; ssh_config(5) and sshd_config(5) share a shape: a line a keyword and its
; arguments, the keyword's case not mattering, an `=` allowed after it,
; double quotes grouping words and `#` beginning a comment.  The first
; value a keyword is given is the one that holds, so lines are kept in
; the order read -- command-line options first, then the files -- and a
; reader takes the first, or all of them for a keyword that gathers.
;
; The client's file is conditional: `Host` patterns and `Match` criteria
; rule the lines after them, judged against the host and user connected
; to.  `Include` reads other files in place, a relative path under the
; directory the file's kind lives in, `*` and `?` matching names.
;
; A line is (KEYWORD ARGS ORIGIN): the keyword lowercased, its arguments
; as written, and where it came from, "FILE: line N", for messages.

(module ssh/config)

(import x/sys/file)

(def %byte-ref (prim-ref (lit str) (lit byte-ref)))
(def %char->int (prim-ref (lit char) (lit ->int)))
(def %cvt (prim-ref (lit convert) (lit to)))
(def %num (fn (_ n) (%cvt n (Type named STRING) 10)))

(def %space? (fn (_ c) (if (= c #\space) #t (if (= c #\tab) #t (= c #\return)))))

; A line's words: the keyword, to a space or an `=`, then the arguments,
; a quoted one whole.  () for a blank line or a comment.
(def ssh-config-words
  (fn (_ line)
    (def n (Str8 length line))
    (def at (fn (_ i) (%byte-ref line i)))
    (def skip (fn (self i) (if (if (< i n) (%space? (at i)) #f) (self (+ i 1)) i)))
    (def word-end (fn (self i) (if (if (< i n) (not (%space? (at i))) #f) (self (+ i 1)) i)))
    (def args
      (fn (self j acc)
        (def k (skip j))
        (match
          ((>= k n) (List reverse acc))
          ((= (at k) #\#) (List reverse acc))
          ((= (at k) #\")
            (do (def close ((fn (self i) (match ((>= i n) ()) ((= (at i) #\") i) (#t (self (+ i 1))))) (+ k 1)))
                (when (null? close) (Err raise 'value "no matching quote" ()))
                (self (+ close 1) (pair (Str8 sub (+ k 1) (- close k 1) line) acc))))
          (#t (do (def e (word-end k)) (self e (pair (Str8 sub k (- e k) line) acc)))))))
    (def i0 (skip 0))
    (if (if (>= i0 n) #t (= (at i0) #\#)) ()
      (do (def kend ((fn (self i) (if (if (< i n) (not (if (%space? (at i)) #t (= (at i) #\=))) #f) (self (+ i 1)) i)) i0))
          (def j (skip kend))
          (pair (Str8 sub i0 (- kend i0) line)
                (args (if (if (< j n) (= (at j) #\=) #f) (+ j 1) j) ()))))))

; Whether a pattern matches a string: `*` any run of characters, `?` any
; one.
(def ssh-config-wild?
  (fn (_ p s)
    (def pn (Str8 length p))
    (def sn (Str8 length s))
    ((fn (self i j)
       (match
         ((= i pn) (= j sn))
         ((= (%byte-ref p i) #\*) (if (self (+ i 1) j) #t (if (< j sn) (self i (+ j 1)) #f)))
         ((= j sn) #f)
         ((if (= (%byte-ref p i) #\?) #t (= (%byte-ref p i) (%byte-ref s j))) (self (+ i 1) (+ j 1)))
         (#t #f)))
     0 0)))

; Whether a list of patterns matches a name, case aside: no `!`-negated
; pattern matching and at least one plain one.
(def ssh-config-patterns?
  (fn (_ patterns name)
    (def s (Str8 downcase name))
    (def neg? (fn (_ p) (if (> (Str8 length p) 0) (= (%byte-ref p 0) #\!) #f)))
    (def hit? (fn (_ p) (ssh-config-wild? (Str8 downcase p) s)))
    (if (List any? (fn (_ p) (if (neg? p) (hit? (Str8 sub 1 (- (Str8 length p) 1) p)) #f)) patterns) #f
      (List any? (fn (_ p) (if (neg? p) #f (hit? p))) patterns))))

; A time as sshd_config(5) writes one -- a number of seconds, or numbers
; each with a unit, s m h d or w, as in 1h30m -- in seconds; () for one
; that is not.
(def ssh-config-time
  (fn (_ t)
    (def n (Str8 length t))
    (def unit
      (fn (_ c)
        (match ((if (= c #\s) #t (= c #\S)) 1) ((if (= c #\m) #t (= c #\M)) 60)
               ((if (= c #\h) #t (= c #\H)) 3600) ((if (= c #\d) #t (= c #\D)) 86400)
               ((if (= c #\w) #t (= c #\W)) 604800) (#t ()))))
    (if (= n 0) ()
      ((fn (self i acc total digits)
         (if (= i n) (if digits (+ total acc) (if (= i 0) () total))
           (do (def c (%byte-ref t i))
               (match
                 ((if (>= c #\0) (<= c #\9) #f)
                   (self (+ i 1) (+ (* acc 10) (- (%char->int c) 48)) total #t))
                 ((if digits (not (null? (unit c))) #f) (self (+ i 1) 0 (+ total (* acc (unit c))) #f))
                 (#t ())))))
       0 0 0 #f))))

; A path's leading ~ as the home directory.
(def ssh-config-tilde
  (fn (_ path)
    (if (if (> (Str8 length path) 0) (= (%byte-ref path 0) #\~) #f)
      (Str8 append (Sys getenv "HOME") (Str8 sub 1 (- (Str8 length path) 1) path))
      path)))

; Settled options read, as ssh and sshd both read them: lines are
; ssh-config-read's (KEYWORD ARGS ORIGIN), ORIGIN what a refusal
; names.
(def ssh-config-line (fn (_ lines kw) (List find (fn (_ l) (str=? (first l) kw)) lines)))
(def ssh-config-bad (fn (_ l what) (Err raise 'value (Str8 append (List ref 2 l) ": " what) ())))
(def ssh-config-arg (fn (_ l) (if (null? (first (rest l))) "" (first (first (rest l))))))

; A keyword's first argument, or default.
(def ssh-config-one (fn (_ lines kw default) (def l (ssh-config-line lines kw)) (if (null? l) default (ssh-config-arg l))))

; A keyword's value, one of choices, lowercased, or default.
(def ssh-config-choice
  (fn (_ lines kw choices default)
    (def l (ssh-config-line lines kw))
    (if (null? l) default
      (do (def v (Str8 downcase (ssh-config-arg l)))
          (if (List any? (fn (_ c) (str=? c v)) choices) v
            (ssh-config-bad l (Str8 append "unsupported option \"" v "\".")))))))

(def ssh-config-yes? (fn (_ lines kw default) (str=? (ssh-config-choice lines kw (list "yes" "no") (if default "yes" "no")) "yes")))

; A decimal's value, or () when the text is not all digits.
(def ssh-config-int-or-nil
  (fn (_ t)
    (def n (Str8 length t))
    (if (if (> n 0) ((fn (self i) (if (= i n) #t (if (if (>= (%byte-ref t i) #\0) (<= (%byte-ref t i) #\9) #f) (self (+ i 1)) #f))) 0) #f)
      (%cvt t (Type named INTEGER) 10)
      ())))

(def ssh-config-count
  (fn (_ lines kw default)
    (def l (ssh-config-line lines kw))
    (if (null? l) default ((fn (_ n) (if (null? n) (ssh-config-bad l "invalid number.") n)) (ssh-config-int-or-nil (ssh-config-arg l))))))

(def ssh-config-seconds
  (fn (_ lines kw default)
    (def l (ssh-config-line lines kw))
    (if (null? l) default ((fn (_ n) (if (null? n) (ssh-config-bad l "invalid time value.") n)) (ssh-config-time (ssh-config-arg l))))))

; ChannelTimeout's global time, in seconds, 0 for none: the one channel
; timeout served is the one over every channel together.
(def ssh-config-channel-timeout
  (fn (_ lines)
    (def l (ssh-config-line lines "channeltimeout"))
    (if (if (null? l) #t (str=? (Str8 downcase (ssh-config-arg l)) "none")) 0
      (List fold
        (fn (_ acc a)
          (def eq (Str8 index-of "=" a))
          (def t (if (null? eq) () (ssh-config-time (Str8 sub (+ eq 1) (- (Str8 length a) eq 1) a))))
          (match
            ((null? t) (ssh-config-bad l (Str8 append "invalid channel timeout " a)))
            ((str=? (Str8 sub 0 eq a) "global") t)
            (#t (ssh-config-bad l (Str8 append "the channel timeout " a " is not served; global= is")))))
        0 (first (rest l))))))

; The files a path names, its components' patterns matched against their
; directories' entries, in order; a path without one is itself, there or
; not.
(def %glob
  (fn (_ path)
    (def wild? (fn (_ c) (if (null? (Str8 index-of "*" c)) (not (null? (Str8 index-of "?" c))) #t)))
    (def parts (Str8 split "/" path))
    (def under (fn (_ d name) (if (str=? d "") (Str8 append "/" name) (Str8 append d "/" name))))
    (if (not (List any? wild? parts)) (list path)
      (List fold
        (fn (_ dirs part)
          (List flat-map
            (fn (_ d)
              (if (wild? part)
                (List map (fn (_ e) (under d e))
                  (List sort (fn (_ a b) (Str8 <? a b))
                    (List filter (fn (_ e) (ssh-config-wild? part e))
                      (guard (e ()) (File list-dir (if (str=? d "") "/" d))))))
                (list (under d part))))
            dirs))
        (list (first parts))
        (rest parts)))))

; A Match line's criteria judged for the host and users: all; host,
; originalhost, user and localuser against pattern lists, `!` before one
; negating it; those that need what this client does not do -- canonical,
; final, exec and the rest -- never hold.
(def %match?
  (fn (_ args host user local origin)
    (def known (list "canonical" "final" "exec" "localnetwork" "tagged" "version" "sessiontype" "command"))
    ((fn (self as)
       (if (null? as) #t
         (do (def c (Str8 downcase (first as)))
             (def neg (if (> (Str8 length c) 0) (= (%byte-ref c 0) #\!) #f))
             (def name (if neg (Str8 sub 1 (- (Str8 length c) 1) c) c))
             (match
               ((str=? name "all") (if neg #f (self (rest as))))
               ((List any? (fn (_ k) (str=? k name)) (list "host" "originalhost" "user" "localuser"))
                 (do (when (null? (rest as)) (Err raise 'value (Str8 append origin ": Match " name " wants an argument") ()))
                     (def who (match ((str=? name "user") user) ((str=? name "localuser") local) (#t host)))
                     (def hit (ssh-config-patterns? (Str8 split "," (first (rest as))) who))
                     (if (if neg (not hit) hit) (self (rest (rest as))) #f)))
               ((List any? (fn (_ k) (str=? k name)) known) #f)
               (#t (Err raise 'value (Str8 append origin ": Unsupported Match attribute " name) ()))))))
     args)))

; A file's text as its lines, in order: (KEYWORD ARGS ORIGIN).  host is
; () for the server's file, which has no Host and whose Match is the
; server's to refuse; for the client's, Host and Match rule which lines
; count, judged for host, user and local.  Include reads its files in
; place, relative to dir.
(def ssh-config-read
  (fn (_ text name host user local dir)
    ((fn (self lines no active acc)
       (if (null? lines) (List reverse acc)
         (do (def origin (Str8 append name ": line " (%num no)))
             (def ws (guard (e (Err raise 'value (Str8 append origin ": " (e msg)) ())) (ssh-config-words (first lines))))
             (def kw (if (null? ws) () (Str8 downcase (first ws))))
             (match
               ((null? ws) (self (rest lines) (+ no 1) active acc))
               ((if (null? host) #f (str=? kw "host"))
                 (self (rest lines) (+ no 1) (ssh-config-patterns? (rest ws) host) acc))
               ((if (null? host) #f (str=? kw "match"))
                 (self (rest lines) (+ no 1) (%match? (rest ws) host user local origin) acc))
               ((str=? kw "include")
                 (self (rest lines) (+ no 1) active
                   (if (not active) acc
                     (List fold
                       (fn (_ acc path)
                         (List fold (fn (_ acc file)
                                      (def t (guard (e ()) (File read-all file)))
                                      (if (null? t) acc
                                        (List append (List reverse (ssh-config-read t file host user local dir)) acc)))
                           acc (%glob (ssh-config-tilde (if (= (%byte-ref path 0) #\/) path
                                                          (if (= (%byte-ref path 0) #\~) path (Str8 append dir "/" path)))))))
                       acc (rest ws)))))
               (#t (self (rest lines) (+ no 1) active
                     (if active (pair (list kw (rest ws) origin) acc) acc)))))))
     (Str8 split "\n" text) 1 #t ())))

; `-o` options as lines, each a file of one line.
(def ssh-config-options
  (fn (_ options)
    (List flat-map (fn (_ o) (ssh-config-read o "command-line" () () () "")) options)))

; The arguments of a keyword's first line, or ().
(def ssh-config-first
  (fn (_ lines kw)
    (def l (List find (fn (_ l) (str=? (first l) kw)) lines))
    (if (null? l) () (first (rest l)))))

; The arguments of every line of a keyword, in order.
(def ssh-config-all
  (fn (_ lines kw)
    (List map (fn (_ l) (first (rest l))) (List filter (fn (_ l) (str=? (first l) kw)) lines))))

; What is wrong with lines, as messages: a keyword OpenSSH does not know,
; unless ignore patterns match it, and one this program does not serve
; given other than the value that leaves it off.
(def ssh-config-faults
  (fn (_ lines known refused ignore)
    (List flat-map
      (fn (_ l)
        (def kw (first l))
        (def r (List find (fn (_ r) (str=? (first r) kw)) refused))
        (match
          ((not (List any? (fn (_ k) (str=? k kw)) known))
            (if (if (null? ignore) #f (ssh-config-patterns? ignore kw)) ()
              (list (Str8 append (List ref 2 l) ": Bad configuration option: " kw))))
          ((null? r) ())
          ((if (null? (first (rest l))) #f (str=? (Str8 downcase (first (first (rest l)))) (rest r))) ())
          (#t (list (Str8 append (List ref 2 l) ": " kw " is not served")))))
      lines)))
; Every keyword sshd_config(5) knows, lowercased, the deprecated ones too.
(def ssh-config-sshd-keywords
  (list "acceptenv" "addressfamily" "allowagentforwarding" "allowgroups" "allowstreamlocalforwarding"
        "allowtcpforwarding" "allowusers" "authenticationmethods" "authorizedkeyscommand"
        "authorizedkeyscommanduser" "authorizedkeysfile" "authorizedprincipalscommand"
        "authorizedprincipalscommanduser" "authorizedprincipalsfile" "banner" "casignaturealgorithms"
        "channeltimeout" "chrootdirectory" "ciphers" "clientalivecountmax" "clientaliveinterval" "compression"
        "denygroups" "denyusers" "disableforwarding" "exposeauthinfo" "fingerprinthash" "forcecommand"
        "gatewayports" "gssapiauthentication" "gssapicleanupcredentials" "gssapidelegatecredentials"
        "gssapistrictacceptorcheck" "hostbasedacceptedalgorithms" "hostbasedauthentication"
        "hostbasedusesnamefrompacketonly" "hostcertificate" "hostkey" "hostkeyagent" "hostkeyalgorithms"
        "ignorerhosts" "ignoreuserknownhosts" "include" "ipqos" "kbdinteractiveauthentication"
        "kerberosauthentication" "kerberosgetafstoken" "kerberosorlocalpasswd" "kerberosticketcleanup"
        "kexalgorithms" "listenaddress" "logingracetime" "loglevel" "logverbose" "macs" "match" "maxauthtries"
        "maxsessions" "maxstartups" "modulifile" "pamservicename" "passwordauthentication"
        "permitemptypasswords" "permitlisten" "permitopen" "permitrootlogin" "permittty" "permittunnel"
        "permituserenvironment" "permituserrc" "persourcemaxstartups" "persourcenetblocksize"
        "persourcepenalties" "persourcepenaltyexemptlist" "pidfile" "port" "printlastlog" "printmotd"
        "pubkeyacceptedalgorithms" "pubkeyauthoptions" "pubkeyauthentication" "refuseconnection" "rekeylimit"
        "requiredrsasize" "revokedkeys" "rdomain" "securitykeyprovider" "setenv" "sshdauthpath"
        "sshdsessionpath" "streamlocalbindmask" "streamlocalbindunlink" "strictmodes" "subsystem"
        "syslogfacility" "tcpkeepalive" "trustedusercakeys" "unusedconnectiontimeout" "usedns" "usepam"
        "versionaddendum" "x11displayoffset" "x11forwarding" "x11uselocalhost" "xauthlocation"
        "challengeresponseauthentication" "protocol" "useprivilegeseparation" "pubkeyacceptedkeytypes"
        "hostbasedacceptedkeytypes" "keyregenerationinterval" "serverkeybits" "rsaauthentication"
        "rhostsrsaauthentication" "uselogin" "showpatchlevel"))

; Every keyword ssh_config(5) knows, lowercased, the deprecated ones too.
(def ssh-config-ssh-keywords
  (list "addkeystoagent" "addressfamily" "batchmode" "bindaddress" "bindinterface" "canonicaldomains"
        "canonicalizefallbacklocal" "canonicalizehostname" "canonicalizemaxdots" "canonicalizepermittedcnames"
        "casignaturealgorithms" "certificatefile" "channeltimeout" "checkhostip" "ciphers" "clearallforwardings"
        "compression" "connectionattempts" "connecttimeout" "controlmaster" "controlpath" "controlpersist"
        "dynamicforward" "enableescapecommandline" "enablesshkeysign" "escapechar" "exitonforwardfailure"
        "fingerprinthash" "forkafterauthentication" "forwardagent" "forwardx11" "forwardx11timeout"
        "forwardx11trusted" "gatewayports" "globalknownhostsfile" "gssapiauthentication"
        "gssapidelegatecredentials" "hashknownhosts" "host" "hostbasedacceptedalgorithms"
        "hostbasedauthentication" "hostkeyalgorithms" "hostkeyalias" "hostname" "identitiesonly"
        "identityagent" "identityfile" "ignoreunknown" "include" "ipqos" "kbdinteractiveauthentication"
        "kbdinteractivedevices" "kexalgorithms" "knownhostscommand" "localcommand" "localforward" "loglevel"
        "logverbose" "macs" "match" "nohostauthenticationforlocalhost" "nohostauthenticationforproxycommand"
        "numberofpasswordprompts" "obscurekeystroketiming" "passwordauthentication" "permitlocalcommand"
        "permitremoteopen" "pkcs11provider" "port" "preferredauthentications" "proxycommand" "proxyjump"
        "proxyusefdpass" "pubkeyacceptedalgorithms" "pubkeyauthentication" "refuseconnection" "rekeylimit"
        "remotecommand" "remoteforward" "requesttty" "requiredrsasize" "revokedhostkeys" "securitykeyprovider"
        "sendenv" "serveralivecountmax" "serveraliveinterval" "sessiontype" "setenv" "stdinnull"
        "streamlocalbindmask" "streamlocalbindunlink" "stricthostkeychecking" "syslogfacility" "tag"
        "tcpkeepalive" "tunnel" "tunneldevice" "updatehostkeys" "usekeychain" "user" "userknownhostsfile"
        "verifyhostkeydns" "versionaddendum" "visualhostkey" "warnweakcrypto" "xauthlocation"
        "challengeresponseauthentication" "protocol" "cipher" "rsaauthentication" "useroaming"
        "pubkeyacceptedkeytypes" "hostbasedkeytypes"))

(provide ssh/config ssh-config-words ssh-config-wild? ssh-config-patterns? ssh-config-time ssh-config-tilde
  ssh-config-read ssh-config-options ssh-config-first ssh-config-all ssh-config-faults
  ssh-config-sshd-keywords ssh-config-ssh-keywords
  ssh-config-line ssh-config-bad ssh-config-arg ssh-config-one ssh-config-choice ssh-config-yes? ssh-config-int-or-nil
  ssh-config-count ssh-config-seconds ssh-config-channel-timeout)
