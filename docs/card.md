# x-ssh card

## Run

```sh
x -l ssh -- PROGRAM [ARG ...]             # a program, by OpenSSH's name
x -l ssh -- ssh [USER@]HOST [COMMAND]     # a shell on a host, or a command
x -l ssh -- sshd -D -p 2222               # a server, in the foreground
x -l ssh -- scp FILE HOST:PATH            # a file to a host
x -l ssh -- sftp HOST                     # files, at a prompt
x -l ssh -- PROGRAM --help                # its options
x -l ssh -- ssh -V 2>&1 | tail -1 -> x-ssh v0.1.0
x -l ssh -- nosuch 2>&1 | grep -c 'the server' -> 1
```

| Program                | Is                                               |
|------------------------|--------------------------------------------------|
| `ssh`                  | the client                                       |
| `sshd`                 | the server                                       |
| `ssh-keygen`           | the key tool                                     |
| `scp` `sftp`           | secure copy; secure file transfer                |
| `sftp-server`          | the SFTP server, on standard input and output    |
| `ssh-agent` `ssh-add`  | the authentication agent; keys added to it       |
| a name that is none    | lists these                                      |

## Client

```sh
x -l ssh -- ssh -Q kex | xargs -> curve25519-sha256 curve25519-sha256@libssh.org
x -l ssh -- ssh -Q cipher | sed 1q -> chacha20-poly1305@openssh.com
x -l ssh -- ssh -Q cipher | sed -n 2p -> aes128-ctr
x -l ssh -- ssh -Q mac | tail -2 | xargs -> hmac-sha2-256 hmac-sha2-512
x -l ssh -- ssh -Q key | sed 1q -> ssh-ed25519
x -l ssh -- ssh -Q sig | tail -2 | xargs -> rsa-sha2-256 rsa-sha2-512
x -l ssh -- ssh -G -F /dev/null -p 2222 ada@box | grep ^port -> port 2222
x -l ssh -- ssh -G -F /dev/null ada@box | grep '^user ' -> user ada
```

| Flag                   | Is                                               |
|------------------------|--------------------------------------------------|
| `-p PORT` `-l USER`    | Port; User                                       |
| `-i FILE`              | IdentityFile: the key to offer                   |
| `-F FILE` `-o KEYWORD=VALUE` | another configuration file; one setting    |
| `-L [BIND:]PORT:HOST:PORT` | LocalForward: a local port to a far host     |
| `-R [BIND:]PORT:HOST:PORT` | RemoteForward: a far port to a host from here |
| `-D [BIND:]PORT`       | DynamicForward: a SOCKS proxy                    |
| `-J HOST` `-W HOST:PORT` | ProxyJump; standard input and output forwarded |
| `-t` `-T`              | ask for a terminal; never                        |
| `-N` `-f` `-n`         | no command; into the background; no standard input |
| `-A` `-a`              | forward the agent; do not                        |
| `-M` `-S PATH` `-O WORD` | a shared connection: master, its path, a request |
| `-q` `-v` `-E FILE`    | quiet; more said; the log to a file              |
| `-Q KIND`              | what is served: `cipher` `mac` `kex` `key` `sig` |
| `-G`                   | print the settings in force and exit             |
| `~.` at a line's start | end the connection                               |
| `~/.ssh/config`, `/etc/ssh/ssh_config` | read as OpenSSH reads them       |

## Keys

```sh
cd $(mktemp -d); x -l ssh -- ssh-keygen -q -t ecdsa -N '' -f k; ls *b -> k.pub
```

| `ssh-keygen`           | Does                                             |
|------------------------|--------------------------------------------------|
| `-t ed25519` `-t ecdsa` `-t rsa` | the kind of key to make                |
| `-b BITS`              | ECDSA 256, 384, 521; RSA 1024 to 16384 (3072)    |
| `-f FILE` `-C COMMENT` | where it goes, `FILE` and `FILE.pub`; its comment |
| `-N PASSPHRASE`        | seal it; `''` for none                           |
| `-y -f FILE`           | a key file's public line                         |
| `-l -f FILE`           | its fingerprint; `-v` its randomart              |
| `-p -f FILE`           | a new passphrase; a Dropbear key made OpenSSH's  |
| `-A`                   | the host keys a server reads by default          |
| `-F HOST` `-R HOST`    | find a host in known_hosts; remove it            |

## Server

```sh
x -l ssh -- sshd -t -h /nosuch 2>&1 | sed 1q -> Unable to load host key: /nosuch
```

| `sshd`                 | Does                                             |
|------------------------|--------------------------------------------------|
| `-p PORT` `-h FILE`    | the port; a host key                             |
| `-f FILE` `-o KEYWORD=VALUE` | the configuration; one setting             |
| `-D` `-d`              | stay in the foreground; serve one connection there |
| `-e` `-E FILE`         | the log to standard error; to a file             |
| `-t` `-T`              | test the configuration; print it                 |
| run as a user          | serves that user                                 |
| run as root            | serves any user in `/etc/passwd`, as that user   |
| `~/.ssh/authorized_keys` | the keys a user may sign in with               |
| `Subsystem sftp internal-sftp` | SFTP, served in a child of the server    |
| `AllowUsers` `Match` `ForceCommand` | refused, not passed over            |

## Copying

| Form                   | Does                                             |
|------------------------|--------------------------------------------------|
| `scp FILE HOST:PATH`   | a file to a host                                 |
| `scp HOST:PATH FILE`   | a file from one                                  |
| `scp -r DIR HOST:PATH` | a directory                                      |
| `scp -P PORT` `-i FILE` `-p` | the port; the key; keep the times          |
| `scp -O`               | the original protocol, in place of SFTP          |
| `sftp [USER@]HOST[:PATH]` | a prompt on a host's files                    |
| `sftp -b FILE HOST`    | commands from a file                             |
| `cd` `lcd` `pwd` `lpwd` `ls` `lls` | where; what is there, far and near   |
| `get` `put` `-r` `-p`  | fetch; send; directories; keep times and modes   |
| `mkdir` `rmdir` `rm` `rename` `ln` `chmod` `df` | on the far side         |
| `bye`                  | leave                                            |

## Agent

| Form                   | Does                                             |
|------------------------|--------------------------------------------------|
| `ssh-agent`            | start one; it prints `SSH_AUTH_SOCK` for the shell |
| `ssh-agent COMMAND`    | run COMMAND with one, ended when it ends         |
| `ssh-agent -k`         | end the one `SSH_AGENT_PID` names                |
| `ssh-add [FILE]`       | add a key, or `~/.ssh/id_*`                      |
| `ssh-add -l` `-L`      | the agent's keys; their public lines             |
| `ssh-add -d FILE` `-D` | remove one; all                                  |
| `ssh-add -t SECONDS`   | a key's lifetime                                 |
| `ssh-add -x` `-X`      | lock the agent; unlock it                        |

## Differs

| Here                                        | In OpenSSH                    |
|---------------------------------------------|-------------------------------|
| it has had no independent review            | reviewed for decades          |
| the key exchange is curve25519-sha256 only  | several                       |
| one key exchange a connection               | a new one as it goes on       |
| no certificates or `sk-` keys               | both                          |
| publickey and password only                 | keyboard-interactive, GSSAPI  |
| no compression, no IPv6                     | both                          |
| the server has no privilege separation      | it has                        |
| the arithmetic is not constant-time         | it is                         |

## More

| Where                          | What                                     |
|--------------------------------|------------------------------------------|
| `README.md`, Served            | each program, option and keyword         |
| `README.md`, Security          | what it is fit for, and what it is not   |
| `tests/oracle/`                | live tests against OpenSSH and Dropbear  |
| `tests/specs/`                 | the wire, the keys, the configuration    |
