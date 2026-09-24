# ssh-audit

[![CI](https://github.com/ivuorinen/ssh-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ivuorinen/ssh-audit/actions/workflows/ci.yml)

**ssh-audit** is a tool for ssh server auditing.

## Features
- SSH1 and SSH2 protocol server support;
- grab banner, recognize device or software and operating system, detect compression;
- gather key-exchange, host-key, encryption and message authentication code algorithms;
- output algorithm information (available since, removed/disabled, unsafe/weak/legacy, etc);
- output algorithm recommendations (append or remove based on recognized software version);
- analyze SSH version compatibility based on algorithm information;
- historical information from OpenSSH, Dropbear SSH and libssh;
- a single file with no dependencies beyond the Python standard library; requires Python 3.14+.

The SSH2 algorithm database is ported from [jtesta/ssh-audit](https://github.com/jtesta/ssh-audit)
(v3.9.0), the actively maintained fork of this project. CVEs are not reported: matching them
against the version in a server's banner was wildly inaccurate, because distributions backport
security fixes without changing that version (see [jtesta/ssh-audit#240](https://github.com/jtesta/ssh-audit/issues/240)).

## Usage
```
usage: ssh-audit.py [-h1246pbnvl] <host>

   -h,  --help             print this help
   -1,  --ssh1             force ssh version 1 only
   -2,  --ssh2             force ssh version 2 only
   -4,  --ipv4             enable IPv4 (order of precedence)
   -6,  --ipv6             enable IPv6 (order of precedence)
   -p,  --port=<port>      port to connect
   -b,  --batch            batch output
   -n,  --no-colors        disable colors
   -v,  --verbose          verbose output
   -l,  --level=<level>    minimum output level (info|warn|fail)

```
* `<host>` is `host`, `host:port`, an IPv6 address (`2001:db8::1`), or `[2001:db8::1]:port`; `-p` overrides a port given in `<host>`.
* if both IPv4 and IPv6 are used, order of precedence can be set by using either `-46` or `-64`.
* batch flag `-b` will output sections without header and without empty lines (implies verbose flag).
* verbose flag `-v` will prefix each line with section type and algorithm name.
* errors are written to stderr and exit with status 1; `-h` exits with status 0. A command-line error writes the usage text to stderr too.
* colors are used only on POSIX terminals: report lines when stdout is a terminal, errors when stderr is. Set a non-empty `NO_COLOR` or pass `-n` to disable them.

### example
```
$ ./ssh-audit.py 192.0.2.10
# general
(gen) banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
(gen) software: OpenSSH 9.6p1
(gen) compatibility: OpenSSH 8.5+, Dropbear SSH 2020.79+
(gen) compression: enabled (zlib@openssh.com)

# key exchange algorithms
(kex) sntrup761x25519-sha512@openssh.com  -- [info] available since OpenSSH 8.5
                                          └─ [info] default key exchange from OpenSSH 9.0 to 9.8
                                          └─ [info] hybrid key exchange based on post-quantum resistant algorithm and proven conventional X25519 algorithm
(kex) curve25519-sha256                   -- [warn] does not provide protection against post-quantum attacks
                                          └─ [info] available since OpenSSH 7.4, Dropbear SSH 2018.76
                                          └─ [info] default key exchange from OpenSSH 7.4 to 8.9
(kex) ecdh-sha2-nistp256                  -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency
                                          └─ [warn] does not provide protection against post-quantum attacks
                                          └─ [info] available since OpenSSH 5.7, Dropbear SSH 2013.62

# host-key algorithms
(key) rsa-sha2-512                        -- [info] available since OpenSSH 7.2
(key) ssh-ed25519                         -- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79

# encryption algorithms (ciphers)
(enc) chacha20-poly1305@openssh.com       -- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79
                                          └─ [info] default cipher since OpenSSH 6.9
(enc) aes128-ctr                          -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52

# message authentication code algorithms
(mac) hmac-sha2-256-etm@openssh.com       -- [info] available since OpenSSH 6.2
(mac) hmac-sha1                           -- [fail] using broken SHA-1 hash algorithm
                                          └─ [warn] using encrypt-and-MAC mode
                                          └─ [info] available since OpenSSH 2.1.0, Dropbear SSH 0.28

# algorithm recommendations (for OpenSSH 9.6)
(rec) -curve25519-sha256                  -- kex algorithm to remove
(rec) -ecdh-sha2-nistp256                 -- kex algorithm to remove
(rec) +rsa-sha2-256                       -- key algorithm to append
(rec) +aes128-gcm@openssh.com             -- enc algorithm to append
(rec) +aes192-ctr                         -- enc algorithm to append
(rec) +aes256-ctr                         -- enc algorithm to append
(rec) +aes256-gcm@openssh.com             -- enc algorithm to append
(rec) -hmac-sha1                          -- mac algorithm to remove
(rec) +hmac-sha2-512-etm@openssh.com      -- mac algorithm to append
(rec) +umac-128-etm@openssh.com           -- mac algorithm to append
```

## Development

The script and its tests use only the Python standard library. Development
tooling ([ruff](https://docs.astral.sh/ruff/) for linting and formatting,
[mypy](https://mypy-lang.org) for type checking, [prek](https://prek.j178.dev)
for git hooks) is optional and never needed to run the tool.

```sh
python3 -m unittest discover -s test   # run the test suite (or: make test)
make coverage                           # tests under coverage; fails below 100%
make check                              # lint, type check and coverage, as CI does
make help                               # list every target
prek install                            # enable the git hooks
```

The Makefile runs ruff, mypy and [coverage.py](https://coverage.readthedocs.io) through
`uvx` at pinned versions, so [uv](https://docs.astral.sh/uv/) is the only extra tool needed.
Coverage must stay at 100% of statements, lines and branches of `ssh-audit.py`;
`make coverage-html` writes a browsable report to `htmlcov/`.

## ChangeLog
### v2.0.0 (2026-09-24)
Breaking: requires Python 3.14 or newer, `-h` now exits 0, errors and
command-line usage go to stderr, and banner-version CVE matching is gone.

 - recognize libssh servers, which announce themselves as `libssh_<version>`, not `libssh-<version>`
 - prefix every pre-banner header line with `(gen) header:`, so a server cannot forge report lines
 - exit quietly when the reader of a piped report closes it (`| head`), instead of a BrokenPipeError traceback
 - write the usage text to stderr when the command line is wrong
 - accept IPv6 addresses as `<host>` (bare or `[addr]:port`); reject more than one host
 - send the client identification first and wait up to 15 s for the banner, instead of giving up after 0.7 s of server silence
 - bound the first packet read by a 15 s deadline; say why no banner was received
 - `-h` exits with status 0; `-n` also applies to command-line errors; an empty `NO_COLOR` no longer disables colors
 - report XMSS host keys as a warning, not a failure; fix a crash on SSH1 servers offering no known cipher
 - require Python 3.14; remove Python 2 compatibility code and the optional colorama dependency
 - refresh the SSH2 algorithm database from jtesta/ssh-audit v3.9.0 (post-quantum key exchanges, SHA-1 and NIST-curve failures, current OpenSSH/Dropbear/libssh versions) and follow its recommendation rules
 - remove banner-version CVE and security-issue matching, which reported backport-patched servers as vulnerable
 - announce the client as OpenSSH 10.3
 - mark continued algorithm notes with `└─` (falls back to `` `- `` when the output encoding lacks box drawing)
 - color fail, warn, good and section lines on POSIX terminals, including buffered algorithm sections
 - escape server text the output encoding cannot represent instead of crashing
 - recommend removing every faulty algorithm the server offers, even when version data does not list it for that server
 - require 100% statement, line and branch coverage (Makefile and CI)
 - compare versions numerically (fixes ordering of libssh 0.10+ and OpenSSH 10.x)
 - fix `--port=<port>` long option
 - validate packet lengths and bound reads; report malformed packets instead of crashing
 - read the banner only from complete lines; cap pre-banner lines and waiting time
 - escape control characters received from the server before printing them
 - write errors to stderr; colorize only terminal output and honour `NO_COLOR`
 - close sockets on every path
 - replace Travis CI with GitHub Actions, pytest with unittest; add pyproject.toml, ruff and prek

### v1.7.0 (2016-10-26)
 - implement options to allow specify IPv4/IPv6 usage and order of precedence
 - implement option to specify remote port (old behavior kept for compatibility)
 - add colors support for Microsoft Windows via optional colorama dependency
 - fix encoding and decoding issues, add tests, do not crash on encoding errors
 - use mypy-lang for static type checking and verify all code

### v1.6.0 (2016-10-14)
 - implement algorithm recommendations section (based on recognized software)
 - implement full libssh support (version history, algorithms, security, etc)
 - fix SSH-1.99 banner recognition and version comparison functionality
 - do not output empty algorithms (happens for misconfigured servers)
 - make consistent output for Python 3.x versions
 - add a lot more tests (conf, banner, software, SSH1/SSH2, output, etc)
 - use Travis CI to test for multiple Python versions (2.6-3.5, pypy, pypy3)

### v1.5.0 (2016-09-20)
 - create security section for related security information
 - match and output assigned CVE list and security issues for Dropbear SSH
 - implement full SSH1 support with fingerprint information
 - automatically fallback to SSH1 on protocol mismatch
 - add new options to force SSH1 or SSH2 (both allowed by default)
 - parse banner information and convert it to specific software and OS version
 - do not use padding in batch mode
 - several fixes (Cisco sshd, rare hangs, error handling, etc)

### v1.0.20160902
 - implement batch output option
 - implement minimum output level option
 - fix compatibility with Python 2.6

### v1.0.20160812
 - implement SSH version compatibility feature
 - fix wrong mac algorithm warning
 - fix Dropbear SSH version typo
 - parse pre-banner header
 - better errors handling

### v1.0.20160803
 - use OpenSSH 7.3 banner
 - add new key-exchange algorithms

### v1.0.20160207
 - use OpenSSH 7.2 banner
 - additional warnings for OpenSSH 7.2
 - fix OpenSSH 7.0 failure messages
 - add rijndael-cbc failure message from OpenSSH 6.7

### v1.0.20160105
 - multiple additional warnings
 - support for none algorithm
 - better compression handling
 - ensure reading enough data (fixes few Linux SSH)

### v1.0.20151230
 - Dropbear SSH support

### v1.0.20151223
 - initial version
