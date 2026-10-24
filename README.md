# x-ssh

SSH on x-lang, as a lang bundle: OpenSSH's client, server and key tool,
and scp.

    x -l ssh -- PROGRAM [ARGS]

The first operand names the program, by OpenSSH's name:

    sshd          the server
    ssh           the client
    ssh-keygen    the key tool
    scp           secure copy

Each takes OpenSSH's options and reads OpenSSH's configuration files.
The ciphers, digests and key exchange are x-lang codecs, written in x
and compiled, so the bundle runs where nothing but the kernel and x are
installed (x-os).  OpenSSH's and Dropbear's clients and servers are what
it is tested against.

## Served

Every end speaks curve25519-sha256 and chacha20-poly1305@openssh.com,
with publickey and password authentication and one session a
connection: a command, or a shell on a terminal.  Keys and signatures:
ssh-ed25519, RSA (rsa-sha2-256 and -512) and ECDSA (nistp256, nistp384,
nistp521), for host keys and user keys, at either end.

- `ssh`: a command run on a host, or with none a shell, its output and
  exit status, with the client's standard input carried to it.  A
  terminal is asked for as RequestTTY says -- by default for a shell
  when standard input is one, `-t` for a command too, `-T` never -- with
  TERM and the window; the local terminal is raw for the session, a
  resize is sent on, and `~.` at a line's start ends the connection.
  The configuration is
  ssh_config(5)'s: `-o` options, then `~/.ssh/config` (or `-F`'s file),
  then `/etc/ssh/ssh_config`, the first value holding, with `Host` and
  `Match` blocks and `Include`.  Each flag stands for its keyword: `-p`
  Port, `-l` User, `-i` IdentityFile, `-L` LocalForward, `-R`
  RemoteForward, `-g` GatewayPorts, `-N` SessionType none, `-n` StdinNull,
  `-q` and `-v` LogLevel; `-W host:port` carries standard input and
  output through the server, as a ProxyCommand wants; `-G` prints the
  settings in force.  Served keywords: Hostname, Port, User,
  IdentityFile (`~/.ssh/id_rsa`, `id_ecdsa` and `id_ed25519` by default;
  OpenSSH's or Dropbear's key files, a key under a passphrase among
  them), StrictHostKeyChecking,
  UserKnownHostsFile,
  GlobalKnownHostsFile, HostKeyAlias, BatchMode, PasswordAuthentication,
  PubkeyAuthentication, NumberOfPasswordPrompts, LocalForward,
  RemoteForward, GatewayPorts, ClearAllForwardings, ServerAliveInterval,
  ServerAliveCountMax, ChannelTimeout (`global=`), SendEnv, SetEnv,
  RemoteCommand, SessionType, StdinNull, LogLevel, IgnoreUnknown.  A new
  host is asked about at the terminal under StrictHostKeyChecking ask,
  as OpenSSH asks; a changed key is always refused.  A password is asked
  at the terminal with echo off, or of SSH_ASKPASS as
  SSH_ASKPASS_REQUIRE says.  A key under a passphrase is offered by its
  public half, and its passphrase asked the same way only once the server
  would take it; an empty answer, or BatchMode, passes the key over.
- `sshd`: the server, for the user it runs as.  The configuration is
  sshd_config(5)'s: `-o` options, then `/etc/ssh/sshd_config` (or `-f`'s
  file), with `Include`; `-h` adds a HostKey, `-p` a Port in place of the
  file's.  Served keywords: Port, ListenAddress, HostKey (Ed25519, RSA
  or ECDSA, one of each type, OpenSSH's or Dropbear's file; one under a
  passphrase is refused, as OpenSSH's sshd refuses it), PidFile,
  AuthorizedKeysFile, PubkeyAcceptedAlgorithms, HostKeyAlgorithms,
  PasswordAuthentication (checked against
  `/etc/shadow` with crypt(3)'s
  DES, `$1$`, `$5$` or `$6$`), PubkeyAuthentication,
  PermitEmptyPasswords, PermitRootLogin, MaxAuthTries,
  AllowTcpForwarding, DisableForwarding, GatewayPorts,
  ClientAliveInterval, ClientAliveCountMax, ChannelTimeout (`global=`),
  AcceptEnv, SyslogFacility, LogLevel.  A keyword that would restrict who
  gets in -- AllowUsers, Match, ForceCommand and the like -- is refused
  rather than passed over; an algorithm list that leaves out the one
  served is refused.  Without `-D` it detaches, writing its PidFile; the
  log goes to syslog as `sshd`, or to standard error under `-e`, to a
  file under `-E`; `-d` serves one connection in the foreground; `-t`
  tests the configuration and `-T` prints it.  Each connection is served
  by a forked child, in the user's home directory; a command runs under
  the user's shell, and a session that asks for a terminal gets a
  pseudo-terminal with its TERM and window, resized as the client's
  is, its shell interactive on it.  `git
  clone` over it works.
- `ssh-keygen`: `-t ed25519|ecdsa|rsa [-b bits] [-f FILE] [-C comment]
  [-N passphrase]` makes a key in OpenSSH's format -- ECDSA on 256
  bits, the default, 384 or 521, RSA on 3072, the default, or 1024 to
  16384 -- sealed under the passphrase as OpenSSH seals it
  (aes256-ctr under bcrypt-pbkdf, `-a`
  rounds, 16 by default), and says so with its fingerprint and
  randomart; `-y` prints a key file's public line, `-l` its fingerprint
  (`-v` its randomart), for Ed25519, RSA and ECDSA keys; `-p` rewrites
  a key file in OpenSSH's format under a new passphrase or none (`-P`
  the old, `-N` the new, asked at the terminal when not given), which
  turns a Dropbear key into one; `-A` makes the RSA, ECDSA and Ed25519
  host keys a server reads by default; `-F` and `-R` find and remove a
  host in known_hosts.
- `scp`: files to and from a host, either end, in the original protocol
  (`-O`).  As the client it spawns the ssh program (`-S`, default `ssh`)
  with OpenSSH's options and passes on `-P`, `-i`, `-o`, `-F` and `-v`,
  `-r` walking directories and `-p` sending times.  As the remote end
  (`-t`, `-f`, `-d`) it is what an OpenSSH `scp -O` reaches.
- `-V` on each, and `--help` from its option declaration.

Not served yet: other ciphers, agents, SFTP, terminal
modes from pty-req, other users than the one a server runs as.

The oracles in `tests/oracle/` are the live tests: `client.sh` drives
the client against a built Dropbear, `server.sh` drives the server with
Dropbear's and OpenSSH's clients, and `scp.sh` runs scp from either end.
Each takes a built Dropbear's directory.

`tests/linux/run.sh` is the Linux leg: password logins, which want a
shadow file and a known password, run as root in a container built from
`tests/linux/Containerfile` at the declared release, with Dropbear's and
OpenSSH's clients as the oracles.

## Install and test

    make install          # into <share>/langs/ssh
    make test             # the spec suite
    make check            # the suite against tests/contract/known-failures.txt

Set `X=/path/to/x` to use a particular x.

## Layout

    lang.xon          what the bundle is: lang, dialect, required release, entry
    run.x             the entry
    ssh/base.x        the parts, assembled
    ssh/bytes.x       the wire's encodings
    ssh/transport.x   the transport layer, from either end: kex, the cipher
    ssh/session.x     the connection protocol, the client's side
    ssh/config.x      ssh_config and sshd_config, as OpenSSH reads them
    ssh/client.x      the client: settings, host keys, authentication, one command
    ssh/server.x      the server: settings, authentication, commands, forwards
    ssh/keys.x        key files, OpenSSH's (sealed or not) and Dropbear's
    ssh/ask.x         secrets asked at the terminal or of SSH_ASKPASS
    ssh/known.x       known_hosts
    ssh/keygen.x      ssh-keygen
    ssh/scp.x         scp, either end
    ssh/cli.x         the command line: ssh-programs, ssh-plan, ssh-main
    tests/            the spec suite and its runner, gate, harness and oracles

## Licence

MIT No Attribution (MIT-0).
