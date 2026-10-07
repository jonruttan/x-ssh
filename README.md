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

- the program list, with no program or an unknown one
- `-V`

## Install and test

    make install          # into <share>/langs/ssh
    make test             # the spec suite
    make check            # the suite against tests/contract/known-failures.txt

Set `X=/path/to/x` to use a particular x.

## Layout

    lang.xon          what the bundle is: lang, dialect, required release, entry
    run.x             the entry
    ssh/base.x        the parts, assembled
    ssh/cli.x         the command line: ssh-argv, ssh-program, ssh-plan, ssh-main
    tests/            the spec suite and its runner, gate and harness

## Licence

MIT No Attribution (MIT-0).
