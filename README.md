# x-ssh

SSH on x-lang, after Dropbear, as a lang bundle: the client, the server
and the key tools.

    x -l ssh -- PROGRAM [ARGS]

As Dropbear's multi-purpose binary, the first operand names the program:

    dropbear                    the server
    dbclient, ssh               the client
    dropbearkey, ssh-keygen     the key generator
    dropbearconvert             the key converter
    scp                         secure copy

The reference is Dropbear itself: its client and server are what this
bundle's are tested against.  The ciphers, digests and key exchange are
x-lang codecs, written in x and compiled, so the bundle runs where nothing
but the kernel and x are installed (x-os).

## Served

Every end speaks curve25519-sha256, ssh-ed25519 and
chacha20-poly1305@openssh.com, with publickey authentication and one
command a connection.

- `dbclient`: a command run on a host, its output and exit status, with
  the client's standard input carried to it.  `-i` names an OpenSSH or
  Dropbear ssh-ed25519 key, `-l` the user, `-p` the port; hosts are
  checked against `~/.ssh/known_hosts`, `-y` accepting and recording a
  new one.  `-L [address:]port:host:port` carries each connection to a
  local port through the server to `host:port` (`-g` listens on every
  interface, `-N` runs no command).  `-v` traces the connection, with
  CPU milliseconds a step.
- `dropbear`: the server: `-r` its host key (default
  `/etc/dropbear/dropbear_ed25519_host_key`), made there under `-R` when
  the file is missing; `-p` where it listens, `-D` the directory of the
  `authorized_keys` it admits.  Without `-F` it forks into the background
  as daemon(3) has it, writing `-P`'s pidfile (default
  `/var/run/dropbear.pid`); it logs to standard error, so in the
  background its log goes nowhere.  Each connection is served by a forked
  child; the command runs under the user's shell, with its standard
  input, output and error on the channel, and a client's `-L` forwards
  are served as `direct-tcpip` channels unless `-j` refuses them.  `git
  clone` over it works.
- `dropbearkey`: `-t ed25519 -f FILE` makes a key in Dropbear's format;
  `-y` prints a key's public line and fingerprint.
- `dropbearconvert`: `openssh|dropbear openssh|dropbear IN OUT` writes an
  ssh-ed25519 key read in one format in the other, with Dropbear's
  messages.
- `scp`: files to and from a host, either end.  As the client it spawns
  the ssh program (`-S`, default `ssh`; `-P` and `-i` are passed on) and
  speaks the protocol over its pipes, `-r` walking directories and `-p`
  sending times.  As the remote end (`-t`, `-f`, `-d`) it is what an
  OpenSSH `scp -O` reaches.  A received time is acknowledged and not set:
  the platform's File has no door that sets a given time yet.
- `-V` on each, and `--help` from its option declaration.

Not served yet: other ciphers and key types, encrypted key files, port
forwarding, agents, passwords, syslog.

The oracles in `tests/oracle/` are the live tests: `dropbear.sh` drives
the client against a built Dropbear, `server.sh` drives the server with
Dropbear's and OpenSSH's clients, and `scp.sh` runs scp from either end.
Each takes a built Dropbear's directory.

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
    ssh/client.x      the client: one command on a host
    ssh/server.x      the server: commands run for authenticated keys
    ssh/keys.x        key files, OpenSSH's and Dropbear's
    ssh/known.x       known_hosts
    ssh/keygen.x      dropbearkey
    ssh/convert.x     dropbearconvert
    ssh/scp.x         scp, either end
    ssh/cli.x         the command line: ssh-argv, ssh-program, ssh-plan, ssh-main
    tests/            the spec suite and its runner, gate, harness and oracles

## Licence

MIT No Attribution (MIT-0).
