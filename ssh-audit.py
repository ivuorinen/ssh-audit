#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2016 Andris Raugulis (moo@arthepsy.eu)
# Copyright (C) 2017-2026 Joe Testa (jtesta@positronsecurity.com) - SSH2 algorithm database
# Copyright (C) 2026 Ismo Vuorinen (ismo@ivuorinen.net)
"""ssh-audit: audit an SSH server's banner, key exchange and algorithms.

Single-file, standard-library-only tool; see LICENSE for the full MIT terms.
"""

import base64
import binascii
import errno
import getopt
import hashlib
import os
import re
import socket
import struct
import sys
import time
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from io import BytesIO, StringIO
from typing import Any, NoReturn, TextIO

VERSION = 'v1.7.0'

# alg type -> alg name -> [versions, fail texts, warn texts, info texts]
type AlgorithmDB = dict[str, dict[str, list[list[str | None]]]]


def usage(err: str | None = None) -> NoReturn:
    uout = Output()
    p = os.path.basename(sys.argv[0])
    uout.head(f'# {p} {VERSION}, https://github.com/ivuorinen/ssh-audit\n')
    if err is not None:
        uout.error(err)
    uout.info(f'usage: {p} [-1246pbnvl] <host>\n')
    uout.info('   -h,  --help             print this help')
    uout.info('   -1,  --ssh1             force ssh version 1 only')
    uout.info('   -2,  --ssh2             force ssh version 2 only')
    uout.info('   -4,  --ipv4             enable IPv4 (order of precedence)')
    uout.info('   -6,  --ipv6             enable IPv6 (order of precedence)')
    uout.info('   -p,  --port=<port>      port to connect')
    uout.info('   -b,  --batch            batch output')
    uout.info('   -n,  --no-colors        disable colors')
    uout.info('   -v,  --verbose          verbose output')
    uout.info('   -l,  --level=<level>    minimum output level (info|warn|fail)')
    uout.sep()
    sys.exit(1)


class AuditConf:
    def __init__(self, host: str | None = None, port: int = 22) -> None:
        self.host = host
        self.port = port
        self.ssh1 = True
        self.ssh2 = True
        self.batch = False
        self.colors = True
        self.verbose = False
        self.minlevel = 'info'
        self.ipvo: Sequence[int] = ()
        self.ipv4 = False
        self.ipv6 = False

    def __setattr__(self, name: str, value: str | int | bool | Sequence[int]) -> None:
        """Validate and normalise every option; unknown names raise.

        Unknown names used to be dropped silently, so a misspelled option was a
        no-op that left the default in force without any report.
        """
        if name in ['ssh1', 'ssh2', 'batch', 'colors', 'verbose']:
            value = bool(value)
        elif name in ['ipv4', 'ipv6']:
            # ipv4/ipv6 are views of ipvo; the ipvo branch stores both flags.
            ipv = 4 if name == 'ipv4' else 6
            if value:
                ipvo = (*self.ipvo, ipv)
            elif len(self.ipvo) == 0:
                ipvo = (6,) if ipv == 4 else (4,)
            else:
                ipvo = tuple(x for x in self.ipvo if x != ipv)
            self.ipvo = ipvo
            return
        elif name == 'ipvo':
            if not isinstance(value, (tuple, list)):
                raise ValueError(f'invalid ipvo: {value!r}')
            value = tuple(x for x in unique_seq(value) if x in (4, 6))
            ipv_both = len(value) == 0
            object.__setattr__(self, 'ipv4', ipv_both or 4 in value)
            object.__setattr__(self, 'ipv6', ipv_both or 6 in value)
        elif name == 'port':
            port = parse_int(value)
            if port < 1 or port > 65535:
                raise ValueError(f'invalid port: {value}')
            value = port
        elif name == 'minlevel':
            if value not in ('info', 'warn', 'fail'):
                raise ValueError(f'invalid level: {value}')
        elif name != 'host':
            raise AttributeError(f'unknown option: {name}')
        object.__setattr__(self, name, value)

    @classmethod
    def from_cmdline(cls, args: list[str], usage_cb: Callable[..., NoReturn]) -> AuditConf:

        aconf = cls()
        try:
            sopts = 'h1246p:bnvl:'
            lopts = [
                'help',
                'ssh1',
                'ssh2',
                'ipv4',
                'ipv6',
                'port=',
                'batch',
                'no-colors',
                'verbose',
                'level=',
            ]
            opts, args = getopt.getopt(args, sopts, lopts)
        except getopt.GetoptError as err:
            usage_cb(str(err))
        aconf.ssh1, aconf.ssh2 = False, False
        oport = None
        for o, a in opts:
            if o in ('-h', '--help'):
                usage_cb()
            elif o in ('-1', '--ssh1'):
                aconf.ssh1 = True
            elif o in ('-2', '--ssh2'):
                aconf.ssh2 = True
            elif o in ('-4', '--ipv4'):
                aconf.ipv4 = True
            elif o in ('-6', '--ipv6'):
                aconf.ipv6 = True
            elif o in ('-p', '--port'):
                oport = a
            elif o in ('-b', '--batch'):
                aconf.batch = True
                aconf.verbose = True
            elif o in ('-n', '--no-colors'):
                aconf.colors = False
            elif o in ('-v', '--verbose'):
                aconf.verbose = True
            else:  # -l/--level, the last declared option
                if a not in ('info', 'warn', 'fail'):
                    usage_cb(f'level {a} is not valid')
                aconf.minlevel = a
        if len(args) == 0:
            usage_cb()
        if oport is not None:
            host = args[0]
            port = parse_int(oport)
        else:
            s = args[0].split(':')
            host = s[0].strip()
            if len(s) == 2:
                oport, port = s[1], parse_int(s[1])
            else:
                oport, port = '22', 22
        if not host:
            usage_cb('host is empty')
        if port <= 0 or port > 65535:
            usage_cb(f'port {oport} is not valid')
        aconf.host = host
        aconf.port = port
        if not (aconf.ssh1 or aconf.ssh2):
            aconf.ssh1, aconf.ssh2 = True, True
        return aconf


class Output:
    LEVELS = ['info', 'warn', 'fail']

    def __init__(self) -> None:
        self.batch = False
        self.colors = True
        self.verbose = False
        self.__minlevel = 0

    @property
    def minlevel(self) -> str:
        if self.__minlevel < len(self.LEVELS):
            return self.LEVELS[self.__minlevel]
        return 'unknown'

    @minlevel.setter
    def minlevel(self, name: str) -> None:
        self.__minlevel = self.getlevel(name)

    def getlevel(self, name: str) -> int:
        cname = 'info' if name == 'good' else name
        if cname not in self.LEVELS:
            return sys.maxsize
        return self.LEVELS.index(cname)

    def sep(self) -> None:
        if not self.batch:
            print()

    @property
    def colors_supported(self) -> bool:
        """Whether the stream stdout output finally reaches accepts colour.

        Checked on the stream behind any OutputBuffer: the buffer's StringIO is
        never a terminal, which left every buffered [fail] and [warn] line plain.
        """
        return Colors.enabled(OutputBuffer.target(sys.stdout))

    def error(self, text: str) -> None:
        """Print a failure to stderr, whatever the minimum level.

        Errors on stdout were written into redirected reports and never shown
        on the terminal; batch consumers parsed them as audit lines.
        """
        line = self.escape(text, sys.stderr)
        if self.colors and Colors.enabled(sys.stderr):
            line = Colors.paint('fail', line)
        print(line, file=sys.stderr)

    @staticmethod
    def continuation_marker() -> str:
        """Marker in front of an algorithm's second and later notes: ``└─``.

        Falls back to ASCII ``\\`-`` when stdout cannot encode box drawing
        (Windows output redirected to a cp1252 file), where printing it would
        raise UnicodeEncodeError and abort the audit. Both are two columns
        wide, so the notes stay aligned under the ``--`` separator.

        Inside an OutputBuffer the real stream behind the buffer decides.
        """
        encoding = getattr(OutputBuffer.target(sys.stdout), 'encoding', None)
        if encoding is None:
            return '└─'
        try:
            '└─'.encode(encoding)
        except UnicodeEncodeError, LookupError:
            return '`-'
        return '└─'

    @staticmethod
    def escape(text: object, stream: TextIO | None = None) -> str:
        """Render control and line-separator characters as ``\\xNN`` escapes.

        Banners, header lines, algorithm names and error payloads come from the
        audited server. Printed raw, ESC sequences and carriage returns let that
        server clear the screen or overwrite ``[fail]`` lines, making a weak
        server look clean. Newline and tab stay literal: header lines are joined
        with newlines by this program, and a server cannot embed one in a line.

        Characters the output stream's encoding cannot represent (CJK text in a
        header on a cp1252 console) are escaped too; printing them raised
        UnicodeEncodeError and aborted the audit.
        """
        escaped = ''.join(
            c
            if c in '\n\t' or unicodedata.category(c) not in ('Cc', 'Zl', 'Zp')
            else f'\\x{ord(c):02x}'
            if ord(c) < 0x100
            else f'\\u{ord(c):04x}'
            for c in str(text)
        )
        encoding = getattr(OutputBuffer.target(stream or sys.stdout), 'encoding', None)
        if encoding is None:
            return escaped
        try:
            return escaped.encode(encoding, 'backslashreplace').decode(encoding)
        except LookupError:
            return escaped

    def __getattr__(self, name: str) -> Callable[[str], None]:
        if name == 'head' and self.batch:
            return lambda x: None
        if not self.getlevel(name) >= self.__minlevel:
            return lambda x: None
        if self.colors and self.colors_supported:
            return lambda x: print(Colors.paint(name, self.escape(x)))
        return lambda x: print(self.escape(x))


class OutputBuffer(list[str]):
    class Capture(StringIO):
        """The StringIO an OutputBuffer installs as stdout; remembers the stream it replaced."""

        def __init__(self, target: TextIO) -> None:
            super().__init__()
            self.target = target

    @staticmethod
    def target(stream: TextIO) -> TextIO:
        """The stream text written to ``stream`` finally reaches.

        Colour and encoding decisions made while a buffer is active must use
        the real stream: the capture is never a TTY and has no encoding.
        """
        while isinstance(stream, OutputBuffer.Capture):
            stream = stream.target
        return stream

    def __enter__(self) -> OutputBuffer:
        self.__buf = OutputBuffer.Capture(sys.stdout)
        self.__stdout = sys.stdout
        sys.stdout = self.__buf
        return self

    def flush(self) -> None:
        for line in self:
            print(line)

    def __exit__(self, *args: Any) -> None:
        self.extend(self.__buf.getvalue().splitlines())
        sys.stdout = self.__stdout


class SSH2:
    class KexParty:
        def __init__(
            self, enc: list[str], mac: list[str], compression: list[str], languages: list[str]
        ) -> None:
            self.__enc = enc
            self.__mac = mac
            self.__compression = compression
            self.__languages = languages

        @property
        def encryption(self) -> list[str]:
            return self.__enc

        @property
        def mac(self) -> list[str]:
            return self.__mac

        @property
        def compression(self) -> list[str]:
            return self.__compression

        @property
        def languages(self) -> list[str]:
            return self.__languages

    class Kex:
        def __init__(
            self,
            cookie: bytes,
            kex_algs: list[str],
            key_algs: list[str],
            cli: SSH2.KexParty,
            srv: SSH2.KexParty,
            follows: bool,
            unused: int = 0,
        ) -> None:
            self.__cookie = cookie
            self.__kex_algs = kex_algs
            self.__key_algs = key_algs
            self.__client = cli
            self.__server = srv
            self.__follows = follows
            self.__unused = unused

        @property
        def cookie(self) -> bytes:
            return self.__cookie

        @property
        def kex_algorithms(self) -> list[str]:
            return self.__kex_algs

        @property
        def key_algorithms(self) -> list[str]:
            return self.__key_algs

        # client_to_server
        @property
        def client(self) -> SSH2.KexParty:
            return self.__client

        # server_to_client
        @property
        def server(self) -> SSH2.KexParty:
            return self.__server

        @property
        def follows(self) -> bool:
            return self.__follows

        @property
        def unused(self) -> int:
            return self.__unused

        def write(self, wbuf: WriteBuf) -> None:
            wbuf.write(self.cookie)
            wbuf.write_list(self.kex_algorithms)
            wbuf.write_list(self.key_algorithms)
            wbuf.write_list(self.client.encryption)
            wbuf.write_list(self.server.encryption)
            wbuf.write_list(self.client.mac)
            wbuf.write_list(self.server.mac)
            wbuf.write_list(self.client.compression)
            wbuf.write_list(self.server.compression)
            wbuf.write_list(self.client.languages)
            wbuf.write_list(self.server.languages)
            wbuf.write_bool(self.follows)
            wbuf.write_int(self.__unused)

        @property
        def payload(self) -> bytes:
            wbuf = WriteBuf()
            self.write(wbuf)
            return wbuf.write_flush()

        @classmethod
        def parse(cls, payload: bytes) -> SSH2.Kex:
            buf = ReadBuf(payload)
            cookie = buf.read(16)
            kex_algs = buf.read_list()
            key_algs = buf.read_list()
            cli_enc = buf.read_list()
            srv_enc = buf.read_list()
            cli_mac = buf.read_list()
            srv_mac = buf.read_list()
            cli_compression = buf.read_list()
            srv_compression = buf.read_list()
            cli_languages = buf.read_list()
            srv_languages = buf.read_list()
            follows = buf.read_bool()
            unused = buf.read_int()
            cli = SSH2.KexParty(cli_enc, cli_mac, cli_compression, cli_languages)
            srv = SSH2.KexParty(srv_enc, srv_mac, srv_compression, srv_languages)
            kex = cls(cookie, kex_algs, key_algs, cli, srv, follows, unused)
            return kex


class SSH1:
    CIPHERS = ['none', 'idea', 'des', '3des', 'tss', 'rc4', 'blowfish']
    # bit 0 is unused by the protocol
    AUTHS = ['', 'rhosts', 'rsa', 'password', 'rhosts_rsa', 'tis', 'kerberos']

    @staticmethod
    def crc32(v: bytes) -> int:
        """SSH1 packet checksum: CRC-32 with zero initial value and no final XOR.

        zlib's CRC-32 pre- and post-inverts the register; seeding it with
        0xFFFFFFFF and inverting the result cancels both inversions.
        """
        return binascii.crc32(v, 0xFFFFFFFF) ^ 0xFFFFFFFF

    class KexDB:
        # fmt: off
        FAIL_PLAINTEXT        = 'no encryption/integrity'
        FAIL_OPENSSH37_REMOVE = 'removed since OpenSSH 3.7'
        FAIL_NA_BROKEN        = 'not implemented in OpenSSH, broken algorithm'
        FAIL_NA_UNSAFE        = 'not implemented in OpenSSH (server), unsafe algorithm'
        TEXT_CIPHER_IDEA      = 'cipher used by commercial SSH'

        ALGORITHMS: AlgorithmDB = {
            'key': {
                'ssh-rsa1': [['1.2.2']],
            },
            'enc': {
                'none': [['1.2.2'], [FAIL_PLAINTEXT]],
                'idea': [[None], [], [], [TEXT_CIPHER_IDEA]],
                'des': [['2.3.0C'], [FAIL_NA_UNSAFE]],
                '3des': [['1.2.2']],
                'tss': [[''], [FAIL_NA_BROKEN]],
                'rc4': [[], [FAIL_NA_BROKEN]],
                'blowfish': [['1.2.2']],
            },
            'aut': {
                'rhosts': [['1.2.2', '3.6'], [FAIL_OPENSSH37_REMOVE]],
                'rsa': [['1.2.2']],
                'password': [['1.2.2']],
                'rhosts_rsa': [['1.2.2']],
                'tis': [['1.2.2']],
                'kerberos': [['1.2.2', '3.6'], [FAIL_OPENSSH37_REMOVE]],
            }
        }
        # fmt: on

    class PublicKeyMessage:
        def __init__(
            self,
            cookie: bytes,
            skey: tuple[int, int, int],
            hkey: tuple[int, int, int],
            pflags: int,
            cmask: int,
            amask: int,
        ) -> None:
            assert len(skey) == 3
            assert len(hkey) == 3
            self.__cookie = cookie
            self.__server_key = skey
            self.__host_key = hkey
            self.__protocol_flags = pflags
            self.__supported_ciphers_mask = cmask
            self.__supported_authentications_mask = amask

        @property
        def cookie(self) -> bytes:
            return self.__cookie

        @property
        def server_key_bits(self) -> int:
            return self.__server_key[0]

        @property
        def server_key_public_exponent(self) -> int:
            return self.__server_key[1]

        @property
        def server_key_public_modulus(self) -> int:
            return self.__server_key[2]

        @property
        def host_key_bits(self) -> int:
            return self.__host_key[0]

        @property
        def host_key_public_exponent(self) -> int:
            return self.__host_key[1]

        @property
        def host_key_public_modulus(self) -> int:
            return self.__host_key[2]

        @property
        def host_key_fingerprint_data(self) -> bytes:

            mod = WriteBuf._create_mpint(self.host_key_public_modulus, False)
            e = WriteBuf._create_mpint(self.host_key_public_exponent, False)
            return mod + e

        @property
        def protocol_flags(self) -> int:
            return self.__protocol_flags

        @property
        def supported_ciphers_mask(self) -> int:
            return self.__supported_ciphers_mask

        @property
        def supported_ciphers(self) -> list[str]:
            ciphers = []
            for i in range(len(SSH1.CIPHERS)):
                if self.__supported_ciphers_mask & (1 << i) != 0:
                    ciphers.append(SSH1.CIPHERS[i])
            return ciphers

        @property
        def supported_authentications_mask(self) -> int:
            return self.__supported_authentications_mask

        @property
        def supported_authentications(self) -> list[str]:
            auths = []
            for i in range(1, len(SSH1.AUTHS)):
                if self.__supported_authentications_mask & (1 << i) != 0:
                    auths.append(SSH1.AUTHS[i])
            return auths

        def write(self, wbuf: WriteBuf) -> None:
            wbuf.write(self.cookie)
            wbuf.write_int(self.server_key_bits)
            wbuf.write_mpint1(self.server_key_public_exponent)
            wbuf.write_mpint1(self.server_key_public_modulus)
            wbuf.write_int(self.host_key_bits)
            wbuf.write_mpint1(self.host_key_public_exponent)
            wbuf.write_mpint1(self.host_key_public_modulus)
            wbuf.write_int(self.protocol_flags)
            wbuf.write_int(self.supported_ciphers_mask)
            wbuf.write_int(self.supported_authentications_mask)

        @property
        def payload(self) -> bytes:
            wbuf = WriteBuf()
            self.write(wbuf)
            return wbuf.write_flush()

        @classmethod
        def parse(cls, payload: bytes) -> SSH1.PublicKeyMessage:
            buf = ReadBuf(payload)
            cookie = buf.read(8)
            server_key_bits = buf.read_int()
            server_key_exponent = buf.read_mpint1()
            server_key_modulus = buf.read_mpint1()
            skey = (server_key_bits, server_key_exponent, server_key_modulus)
            host_key_bits = buf.read_int()
            host_key_exponent = buf.read_mpint1()
            host_key_modulus = buf.read_mpint1()
            hkey = (host_key_bits, host_key_exponent, host_key_modulus)
            pflags = buf.read_int()
            cmask = buf.read_int()
            amask = buf.read_int()
            pkm = cls(cookie, skey, hkey, pflags, cmask, amask)
            return pkm


class ReadBuf:
    def __init__(self, data: bytes | None = None) -> None:
        super().__init__()
        self._buf = BytesIO(data) if data else BytesIO()
        self._len = len(data) if data else 0

    @property
    def unread_len(self) -> int:
        return self._len - self._buf.tell()

    def read(self, size: int) -> bytes:
        return self._buf.read(size)

    def read_byte(self) -> int:
        value: int = struct.unpack('B', self.read(1))[0]
        return value

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_int(self) -> int:
        value: int = struct.unpack('>I', self.read(4))[0]
        return value

    def read_list(self) -> list[str]:
        list_size = self.read_int()
        return self.read(list_size).decode('utf-8', 'replace').split(',')

    def read_string(self) -> bytes:
        n = self.read_int()
        return self.read(n)

    @classmethod
    def _parse_mpint(cls, v: bytes, pad: bytes, sf: str) -> int:
        r = 0
        if len(v) % 4:
            v = pad * (4 - (len(v) % 4)) + v
        for i in range(0, len(v), 4):
            r = (r << 32) | struct.unpack(sf, v[i : i + 4])[0]
        return r

    def read_mpint1(self) -> int:
        # NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
        bits = struct.unpack('>H', self.read(2))[0]
        n = (bits + 7) // 8
        return self._parse_mpint(self.read(n), b'\x00', '>I')

    def read_mpint2(self) -> int:
        # NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
        v = self.read_string()
        if len(v) == 0:
            return 0
        pad, sf = (b'\xff', '>i') if ord(v[0:1]) & 0x80 else (b'\x00', '>I')
        return self._parse_mpint(v, pad, sf)

    def read_line(self) -> str:
        return self._buf.readline().rstrip().decode('utf-8', 'replace')


class WriteBuf:
    def __init__(self, data: bytes | None = None) -> None:
        super().__init__()
        self._wbuf = BytesIO(data) if data else BytesIO()

    def write(self, data: bytes) -> WriteBuf:
        self._wbuf.write(data)
        return self

    def write_byte(self, v: int) -> WriteBuf:
        return self.write(struct.pack('B', v))

    def write_bool(self, v: bool) -> WriteBuf:
        return self.write_byte(1 if v else 0)

    def write_int(self, v: int) -> WriteBuf:
        return self.write(struct.pack('>I', v))

    def write_string(self, v: bytes | str) -> WriteBuf:
        if not isinstance(v, bytes):
            v = v.encode('utf-8')
        self.write_int(len(v))
        return self.write(v)

    def write_list(self, v: list[str]) -> WriteBuf:
        return self.write_string(','.join(v))

    @classmethod
    def _create_mpint(cls, n: int, signed: bool = True, bits: int | None = None) -> bytes:
        if bits is None:
            bits = n.bit_length()
        length = bits // 8 + (1 if n != 0 else 0)
        ql = (length + 7) // 8
        fmt, v2 = f'>{ql}Q', [0] * ql
        for i in range(ql):
            v2[ql - i - 1] = n & 0xFFFFFFFFFFFFFFFF
            n >>= 64
        data = bytes(struct.pack(fmt, *v2)[-length:])
        if not signed:
            data = data.lstrip(b'\x00')
        elif data.startswith(b'\xff\x80'):
            data = data[1:]
        return data

    def write_mpint1(self, n: int) -> WriteBuf:
        # NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
        bits = n.bit_length()
        data = self._create_mpint(n, False, bits)
        self.write(struct.pack('>H', bits))
        return self.write(data)

    def write_mpint2(self, n: int) -> WriteBuf:
        # NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
        data = self._create_mpint(n)
        return self.write_string(data)

    def write_flush(self) -> bytes:
        payload = self._wbuf.getvalue()
        self._wbuf.truncate(0)
        self._wbuf.seek(0)
        return payload


class SSH:
    class Protocol:
        # fmt: off
        SMSG_PUBLIC_KEY = 2
        MSG_KEXINIT     = 20
        # fmt: on

    class Product:
        OpenSSH = 'OpenSSH'
        DropbearSSH = 'Dropbear SSH'
        LibSSH = 'libssh'

    class Software:
        def __init__(
            self,
            vendor: str | None,
            product: str,
            version: str,
            patch: str | None,
            os_version: str | None,
        ) -> None:
            self.__vendor = vendor
            self.__product = product
            self.__version = version
            self.__patch = patch
            self.__os = os_version

        @property
        def vendor(self) -> str | None:
            return self.__vendor

        @property
        def product(self) -> str:
            return self.__product

        @property
        def version(self) -> str:
            return self.__version

        @property
        def patch(self) -> str | None:
            return self.__patch

        @property
        def os(self) -> str | None:
            return self.__os

        def compare_version(self, other: None | SSH.Software | str) -> int:

            if other is None:
                return 1
            if isinstance(other, SSH.Software):
                other = f'{other.version}{other.patch or ""}'
            else:
                other = str(other)
            mx = re.match(r'^([\d\.]+\d+)(.*)$', other)
            if mx:
                oversion, opatch = mx.group(1), mx.group(2).strip()
            else:
                oversion, opatch = other, ''
            sversion_key, oversion_key = version_key(self.version), version_key(oversion)
            if sversion_key < oversion_key:
                return -1
            elif sversion_key > oversion_key:
                return 1
            spatch = self.patch or ''
            if self.product == SSH.Product.DropbearSSH:
                if not re.match(r'^test\d.*$', opatch):
                    opatch = f'z{opatch}'
                if not re.match(r'^test\d.*$', spatch):
                    spatch = f'z{spatch}'
            elif self.product == SSH.Product.OpenSSH:
                mx1 = re.match(r'^p\d(.*)', opatch)
                mx2 = re.match(r'^p\d(.*)', spatch)
                if not (mx1 and mx2):
                    if mx1:
                        opatch = mx1.group(1)
                    if mx2:
                        spatch = mx2.group(1)
            if spatch < opatch:
                return -1
            elif spatch > opatch:
                return 1
            return 0

        def display(self, full: bool = True) -> str:
            r = f'{self.vendor} ' if self.vendor else ''
            r += f'{self.product} {self.version}'
            if full:
                patch = self.patch or ''
                if self.product == SSH.Product.OpenSSH:
                    mx = re.match(r'^(p\d)(.*)$', patch)
                    if mx is not None:
                        r += mx.group(1)
                        patch = mx.group(2).strip()
                if patch:
                    r += f' ({patch})'
                if self.os:
                    r += f' running on {self.os}'
            return r

        def __str__(self) -> str:
            return self.display()

        def __repr__(self) -> str:
            r = f'vendor={self.vendor}, ' if self.vendor else ''
            r += f'product={self.product}, version={self.version}'
            if self.patch:
                r += f', patch={self.patch}'
            if self.os:
                r += f', os={self.os}'
            return f'<{self.__class__.__name__}({r})>'

        @staticmethod
        def _fix_patch(patch: str) -> str | None:
            return re.sub(r'^[-_\.]+', '', patch) or None

        @staticmethod
        def _fix_date(d: str) -> str | None:
            if d is not None and len(d) == 8:
                return f'{d[:4]}-{d[4:6]}-{d[6:8]}'
            else:
                return None

        @classmethod
        def _extract_os_version(cls, c: str | None) -> str | None:
            if c is None:
                return None
            mx = re.match(r'^NetBSD(?:_Secure_Shell)?(?:[\s-]+(\d{8})(.*))?$', c)
            if mx:
                d = cls._fix_date(mx.group(1))
                return 'NetBSD' if d is None else f'NetBSD ({d})'
            mx = re.match(r'^FreeBSD(?:\slocalisations)?[\s-]+(\d{8})(.*)$', c)
            if not mx:
                mx = re.match(r'^[^@]+@FreeBSD\.org[\s-]+(\d{8})(.*)$', c)
            if mx:
                d = cls._fix_date(mx.group(1))
                return 'FreeBSD' if d is None else f'FreeBSD ({d})'
            w = ['RemotelyAnywhere', 'DesktopAuthority', 'RemoteSupportManager']
            for win_soft in w:
                mx = re.match(r'^in ' + win_soft + r' ([\d\.]+\d)$', c)
                if mx:
                    ver = mx.group(1)
                    return f'Microsoft Windows ({win_soft} {ver})'
            generic = ['NetBSD', 'FreeBSD']
            for g in generic:
                if c.startswith(g) or c.endswith(g):
                    return g
            return None

        @classmethod
        def parse(cls, banner: SSH.Banner) -> SSH.Software | None:

            software = str(banner.software)
            mx = re.match(r'^dropbear_([\d\.]+\d+)(.*)', software)
            if mx:
                patch = cls._fix_patch(mx.group(2))
                return cls(None, SSH.Product.DropbearSSH, mx.group(1), patch, None)
            mx = re.match(r'^OpenSSH[_\.-]+([\d\.]+\d+)(.*)', software)
            if mx:
                patch = cls._fix_patch(mx.group(2))
                os_version = cls._extract_os_version(banner.comments)
                return cls(None, SSH.Product.OpenSSH, mx.group(1), patch, os_version)
            mx = re.match(r'^libssh-([\d\.]+\d+)(.*)', software)
            if mx:
                patch = cls._fix_patch(mx.group(2))
                os_version = cls._extract_os_version(banner.comments)
                return cls(None, SSH.Product.LibSSH, mx.group(1), patch, os_version)
            mx = re.match(r'^RomSShell_([\d\.]+\d+)(.*)', software)
            if mx:
                patch = cls._fix_patch(mx.group(2))
                v, p = 'Allegro Software', 'RomSShell'
                return cls(v, p, mx.group(1), patch, None)
            mx = re.match(r'^mpSSH_([\d\.]+\d+)', software)
            if mx:
                v, p = 'HP', 'iLO (Integrated Lights-Out) sshd'
                return cls(v, p, mx.group(1), None, None)
            mx = re.match(r'^Cisco-([\d\.]+\d+)', software)
            if mx:
                v, p = 'Cisco', 'IOS/PIX sshd'
                return cls(v, p, mx.group(1), None, None)
            return None

    class Banner:
        _RXP, _RXR = r'SSH-\d\.\s*?\d+', r'(-\s*([^\s]*)(?:\s+(.*))?)?'
        RX_PROTOCOL = re.compile(re.sub(r'\\d(\+?)', r'(\\d\g<1>)', _RXP))
        RX_BANNER = re.compile(rf'^({_RXP}(?:(?:-{_RXP})*)){_RXR}$')

        def __init__(
            self,
            protocol: tuple[int, int],
            software: str | None,
            comments: str | None,
            valid_ascii: bool,
        ) -> None:
            self.__protocol = protocol
            self.__software = software
            self.__comments = comments
            self.__valid_ascii = valid_ascii

        @property
        def protocol(self) -> tuple[int, int]:
            return self.__protocol

        @property
        def software(self) -> str | None:
            return self.__software

        @property
        def comments(self) -> str | None:
            return self.__comments

        @property
        def valid_ascii(self) -> bool:
            return self.__valid_ascii

        def __str__(self) -> str:
            r = f'SSH-{self.protocol[0]}.{self.protocol[1]}'
            if self.software is not None:
                r += f'-{self.software}'
            if self.comments:
                r += f' {self.comments}'
            return r

        def __repr__(self) -> str:
            p = f'{self.protocol[0]}.{self.protocol[1]}'
            r = f'protocol={p}'
            if self.software:
                r += f', software={self.software}'
            if self.comments:
                r += f', comments={self.comments}'
            return f'<{self.__class__.__name__}({r})>'

        @classmethod
        def parse(cls, banner: str) -> SSH.Banner | None:
            valid_ascii = banner.isascii()
            ascii_banner = banner.encode('ascii', 'replace').decode('ascii')
            mx = cls.RX_BANNER.match(ascii_banner)
            if mx is None:
                return None
            protocol = min(re.findall(cls.RX_PROTOCOL, mx.group(1)))
            protocol = (int(protocol[0]), int(protocol[1]))
            software = (mx.group(3) or '').strip() or None
            if software is None and (mx.group(2) or '').startswith('-'):
                software = ''
            comments = (mx.group(4) or '').strip() or None
            if comments is not None:
                comments = re.sub(r'\s+', ' ', comments)
            return cls(protocol, software, comments, valid_ascii)

    class Fingerprint:
        def __init__(self, fpd: bytes) -> None:
            self.__fpd = fpd

        @property
        def sha256(self) -> str:
            h = base64.b64encode(hashlib.sha256(self.__fpd).digest())
            r = h.decode('ascii').rstrip('=')
            return f'SHA256:{r}'

    class Socket(ReadBuf, WriteBuf):
        class InsufficientReadException(Exception):
            pass

        # Pre-banner bounds: OpenSSH's client gives up after 1024 lines; the
        # deadline stops a tarpit that trickles lines just inside the read timeout.
        MAX_PRE_BANNER_LINES = 1024
        MAX_LINE_LENGTH = 8192
        BANNER_TIMEOUT = 15.0
        # Largest packet_length accepted: OpenSSH's PACKET_MAX_SIZE for SSH2,
        # the protocol 1.5 specification limit for SSH1.
        MAX_PACKET_LENGTH = {1: 262144, 2: 256 * 1024}

        def __init__(self, host: str, port: int) -> None:
            super().__init__()
            self.__block_size = 8
            self.__header: list[str] = []
            self.__banner: SSH.Banner | None = None
            self.__host = host
            self.__port = port
            self.__sock: socket.socket | None = None

        def __enter__(self) -> SSH.Socket:
            return self

        def _resolve(self, ipvo: Sequence[int]) -> Iterable[tuple[int, tuple[Any, ...]]]:
            ipvo = tuple(filter(lambda x: x in (4, 6), unique_seq(ipvo)))
            ipvo_len = len(ipvo)
            prefer_ipvo = ipvo_len > 0
            prefer_ipv4 = prefer_ipvo and ipvo[0] == 4
            if len(ipvo) == 1:
                family = {4: socket.AF_INET, 6: socket.AF_INET6}[ipvo[0]]
            else:
                family = socket.AF_UNSPEC
            try:
                stype = socket.SOCK_STREAM
                r = socket.getaddrinfo(self.__host, self.__port, family, stype)
                if prefer_ipvo:
                    r = sorted(r, key=lambda x: x[0], reverse=not prefer_ipv4)
                # getaddrinfo was asked for SOCK_STREAM, so every entry is a stream address.
                for af, _socktype, _proto, _canonname, addr in r:
                    yield (af, addr)
            except OSError as e:
                out.error(f'[exception] {e}')
                sys.exit(1)

        def connect(self, ipvo: Sequence[int] = (), cto: float = 3.0, rto: float = 5.0) -> None:
            err = None
            for af, addr in self._resolve(ipvo):
                s = None
                try:
                    s = socket.socket(af, socket.SOCK_STREAM)
                    s.settimeout(cto)
                    s.connect(addr)
                    s.settimeout(rto)
                    self.__sock = s
                    return
                except OSError as e:
                    err = e
                    self._close_socket(s)
            if err is None:
                errm = f'host {self.__host} has no DNS records'
            else:
                errt = (self.__host, self.__port, err)
                errm = f'cannot connect to {errt[0]} port {errt[1]}: {errt[2]}'
            out.error(f'[exception] {errm}')
            sys.exit(1)

        def get_banner(self, sshv: int = 2) -> tuple[SSH.Banner | None, list[str]]:
            banner = f'SSH-{"1.5" if sshv == 1 else "2.0"}-OpenSSH_10.3'
            rto = self._sock.gettimeout()
            self._sock.settimeout(0.7)
            s, e = self.recv()
            self._sock.settimeout(rto)
            if s < 0:
                return self.__banner, self.__header
            self.send(banner.encode() + b'\r\n')
            deadline = time.monotonic() + self.BANNER_TIMEOUT
            eof = False
            while self.__banner is None and not eof:
                # Only a complete line is parsed: a banner split across TCP
                # segments would otherwise match as a truncated banner.
                while not self._has_unread_line() and self.unread_len < self.MAX_LINE_LENGTH:
                    s, e = self.recv()
                    if s < 0 or time.monotonic() > deadline:
                        eof = True
                        break
                while self.__banner is None and self.unread_len > 0:
                    if (
                        not eof
                        and not self._has_unread_line()
                        and self.unread_len < self.MAX_LINE_LENGTH
                    ):
                        break
                    line = self.read_line()
                    if len(line.strip()) == 0:
                        continue
                    self.__banner = SSH.Banner.parse(line)
                    if self.__banner is None:
                        self.__header.append(line)
                if len(self.__header) >= self.MAX_PRE_BANNER_LINES or time.monotonic() > deadline:
                    break
            return self.__banner, self.__header

        def _has_unread_line(self) -> bool:
            return self._buf.getvalue().find(b'\n', self._buf.tell()) != -1

        def recv(self, size: int = 2048) -> tuple[int, str | None]:
            try:
                data = self._sock.recv(size)
            except TimeoutError:
                return (-1, 'timeout')
            except OSError as e:
                if e.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                    return (0, 'retry')
                return (-1, str(e.args[-1]))
            if len(data) == 0:
                return (-1, None)
            pos = self._buf.tell()
            self._buf.seek(0, 2)
            self._buf.write(data)
            self._len += len(data)
            self._buf.seek(pos, 0)
            return (len(data), None)

        def send(self, data: bytes) -> tuple[int, str | None]:
            try:
                self._sock.send(data)
                return (0, None)
            except OSError as e:
                return (-1, str(e.args[-1]))

        def ensure_read(self, size: int) -> None:
            while self.unread_len < size:
                s, e = self.recv()
                if s < 0:
                    raise SSH.Socket.InsufficientReadException(e)

        def read_packet(self, sshv: int = 2) -> tuple[int, bytes]:
            header = WriteBuf()
            try:
                self.ensure_read(4)
                packet_length = self.read_int()
                header.write_int(packet_length)
                if packet_length > self.MAX_PACKET_LENGTH[sshv]:
                    # Not a packet: typically a plaintext error such as
                    # "Protocol major versions differ.", whose first four bytes
                    # read as a huge length. Return what the server sent, bounded.
                    self._drain(self.MAX_PACKET_LENGTH[sshv])
                    header.write(self.read(self.unread_len))
                    return (-1, header.write_flush().strip())
                padding = b''
                if sshv == 1:
                    padding_length = 8 - packet_length % 8
                    self.ensure_read(padding_length)
                    padding = self.read(padding_length)
                    header.write(padding)
                    payload_length = packet_length
                    check_size = padding_length + payload_length
                    # type byte + CRC32
                    valid = packet_length >= 5
                else:
                    self.ensure_read(1)
                    padding_length = self.read_byte()
                    header.write_byte(padding_length)
                    payload_length = packet_length - padding_length - 1
                    check_size = 4 + 1 + payload_length + padding_length
                    # RFC 4253 section 6: at least 4 padding bytes, a message type byte
                    valid = padding_length >= 4 and payload_length >= 1
                if check_size % self.__block_size != 0:
                    out.error('[exception] invalid ssh packet (block size)')
                    sys.exit(1)
                if not valid:
                    out.error('[exception] invalid ssh packet (length)')
                    sys.exit(1)
                self.ensure_read(payload_length)
                if sshv == 1:
                    payload = self.read(payload_length - 4)
                    header.write(payload)
                    crc = self.read_int()
                    header.write_int(crc)
                    if crc != SSH1.crc32(padding + payload):
                        out.error('[exception] packet checksum CRC32 mismatch.')
                        sys.exit(1)
                else:
                    payload = self.read(payload_length)
                    header.write(payload)
                    self.ensure_read(padding_length)
                    self.read(padding_length)
                return payload[0], payload[1:]
            except SSH.Socket.InsufficientReadException as ex:
                if ex.args[0] is None:
                    header.write(self.read(self.unread_len))
                    e = header.write_flush().strip()
                else:
                    e = ex.args[0].encode('utf-8')
                return (-1, e)

        def _drain(self, limit: int) -> None:
            """Buffer incoming data until the peer stops sending or ``limit`` bytes wait."""
            while self.unread_len < limit:
                s, _ = self.recv()
                if s < 0:
                    return

        def _close_socket(self, s: socket.socket | None) -> None:
            """Shut down and close ``s``; close runs even when shutdown fails.

            shutdown() raises ENOTCONN on a socket whose connect failed, which
            previously skipped close() and leaked the descriptor.
            """
            if s is None:
                return
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                s.close()

        def __exit__(self, *args: Any) -> None:
            self._close_socket(self.__sock)
            self.__sock = None

        @property
        def _sock(self) -> socket.socket:
            if self.__sock is None:
                raise OSError(errno.ENOTCONN, 'not connected')
            return self.__sock


class KexDB:
    # Ported verbatim from jtesta/ssh-audit v3.9.0 (commit dbf8b696331925ce7d4dbf72cb93faf3968397aa),
    # src/ssh_audit/ssh2_kexdb.py; refresh by re-porting that file, not by hand.
    # fmt: off
    FAIL_1024BIT_MODULUS = 'using small 1024-bit modulus'
    FAIL_3DES = 'using broken & deprecated 3DES cipher'
    FAIL_BLOWFISH = 'using weak & deprecated Blowfish cipher'
    FAIL_CAST = 'using weak & deprecated CAST cipher'
    FAIL_DES = 'using broken DES cipher'
    FAIL_IDEA = 'using deprecated IDEA cipher'
    FAIL_LOGJAM_ATTACK = 'vulnerable to the Logjam attack: https://en.wikipedia.org/wiki/Logjam_(computer_security)'
    FAIL_MD5 = 'using broken MD5 hash algorithm'
    FAIL_NSA_BACKDOORED_CURVE = 'using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency'
    FAIL_PLAINTEXT = 'no encryption/integrity'
    FAIL_RC4 = 'using broken RC4 cipher'
    FAIL_RIJNDAEL = 'using deprecated & non-standardized Rijndael cipher'
    FAIL_RIPEMD = 'using deprecated RIPEMD hash algorithm'
    FAIL_SEED = 'using deprecated SEED cipher'
    FAIL_SERPENT = 'using deprecated Serpent cipher'
    FAIL_SHA1 = 'using broken SHA-1 hash algorithm'
    FAIL_SMALL_ECC_MODULUS = 'using small ECC modulus'
    FAIL_UNKNOWN = 'using unknown algorithm'
    FAIL_UNPROVEN = 'using unproven algorithm'
    FAIL_UNTRUSTED = 'using untrusted algorithm developed in secret by a government entity'

    WARN_2048BIT_MODULUS = '2048-bit modulus only provides 112-bits of symmetric strength'
    WARN_BLOCK_SIZE = 'using small 64-bit block size'
    WARN_CIPHER_MODE = 'using weak cipher mode'
    WARN_ENCRYPT_AND_MAC = 'using encrypt-and-MAC mode'
    WARN_EXPERIMENTAL = 'using experimental algorithm'
    WARN_NOT_PQ_SAFE = 'does not provide protection against post-quantum attacks'
    WARN_RNDSIG_KEY = 'using weak random number generator could reveal the key'
    WARN_TAG_SIZE = 'using small 64-bit tag size'
    WARN_TAG_SIZE_96 = 'using small 96-bit tag size'

    INFO_DEFAULT_OPENSSH_CIPHER = 'default cipher since OpenSSH 6.9'
    INFO_DEFAULT_OPENSSH_KEX_65_TO_73 = 'default key exchange from OpenSSH 6.5 to 7.3'
    INFO_DEFAULT_OPENSSH_KEX_74_TO_89 = 'default key exchange from OpenSSH 7.4 to 8.9'
    INFO_DEFAULT_OPENSSH_KEX_90_TO_98 = 'default key exchange from OpenSSH 9.0 to 9.8'
    INFO_DEFAULT_OPENSSH_KEX_99 = 'default key exchange in OpenSSH 9.9'
    INFO_DEFAULT_OPENSSH_KEX_100 = 'default key exchange since OpenSSH 10.0'
    INFO_DEPRECATED_IN_OPENSSH88 = 'deprecated in OpenSSH 8.8: https://www.openssh.com/txt/release-8.8'
    INFO_DISABLED_IN_DBEAR67 = 'disabled in Dropbear SSH 2015.67'
    INFO_DISABLED_IN_OPENSSH70 = 'disabled in OpenSSH 7.0: https://www.openssh.com/txt/release-7.0'
    INFO_NEVER_IMPLEMENTED_IN_OPENSSH = 'despite the @openssh.com tag, this was never implemented in OpenSSH'
    INFO_HYBRID_PQ_X25519_KEX = 'hybrid key exchange based on post-quantum resistant algorithm and proven conventional X25519 algorithm'
    INFO_HYBRID_PQ_NISTP_KEX = 'hybrid key exchange based on post-quantum resistant algorithm and a suspected back-doored NIST P-curve'
    INFO_REMOVED_IN_OPENSSH61 = 'removed since OpenSSH 6.1, removed from specification'
    INFO_REMOVED_IN_OPENSSH69 = 'removed in OpenSSH 6.9: https://www.openssh.com/txt/release-6.9'
    INFO_REMOVED_IN_OPENSSH70 = 'removed in OpenSSH 7.0: https://www.openssh.com/txt/release-7.0'
    INFO_WITHDRAWN_PQ_ALG = 'the sntrup4591761 algorithm was withdrawn, as it may not provide strong post-quantum security'
    INFO_EXTENSION_NEGOTIATION = 'pseudo-algorithm that denotes the peer supports RFC8308 extensions'
    INFO_STRICT_KEX = 'pseudo-algorithm that denotes the peer supports a stricter key exchange method as a counter-measure to the Terrapin attack (CVE-2023-48795)'

    # NIST PQC security levels: https://blog.cloudflare.com/pq-2025/
    INFO_NIST_PQC_LEVEL_2 = 'rated at NIST PQC level 2 (at least as hard to break as SHA256)'
    INFO_NIST_PQC_LEVEL_3 = 'rated at NIST PQC level 3 (at least as hard to break as AES-192)'
    INFO_NIST_PQC_LEVEL_5 = 'rated at NIST PQC level 5 (at least as hard to break as AES-256)'

    ALGORITHMS: AlgorithmDB = {
        # Format: 'algorithm_name': [['version_first_appeared_in'], [reason_for_failure1, reason_for_failure2, ...], [warning1, warning2, ...], [info1, info2, ...]]
        'kex': {
            'Curve25519SHA256': [[], [], [WARN_NOT_PQ_SAFE]],
            'curve25519-sha256': [['7.4,d2018.76'], [], [WARN_NOT_PQ_SAFE], [INFO_DEFAULT_OPENSSH_KEX_74_TO_89]],
            'curve25519-sha256@libssh.org': [['6.4,d2013.62,l10.6.0'], [], [WARN_NOT_PQ_SAFE], [INFO_DEFAULT_OPENSSH_KEX_65_TO_73]],
            'curve448-sha512': [[], [], [WARN_NOT_PQ_SAFE]],
            'curve448-sha512@libssh.org': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group14-sha1': [['3.9,d0.53,l10.6.0'], [FAIL_SHA1], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group14-sha224@ssh.com': [[], [], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group14-sha256': [['7.3,d2016.73'], [], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group14-sha256@ssh.com': [[], [], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group15-sha256': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group15-sha256@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group15-sha384@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group15-sha512': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group16-sha256': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group16-sha384@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group16-sha512': [['7.3,d2016.73'], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group16-sha512@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group17-sha512': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman_group17-sha512': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group18-sha512': [['7.3'], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group18-sha512@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group1-sha1': [['2.3.0,d0.28,l10.2', '6.6', '6.9'], [FAIL_1024BIT_MODULUS, FAIL_LOGJAM_ATTACK, FAIL_SHA1], [WARN_NOT_PQ_SAFE], [INFO_REMOVED_IN_OPENSSH69]],
            'diffie-hellman-group1-sha256': [[], [FAIL_1024BIT_MODULUS], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group-exchange-sha1': [['2.3.0', '6.6', None], [FAIL_SHA1], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group-exchange-sha224@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group-exchange-sha256': [['4.4'], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group-exchange-sha256@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group-exchange-sha384@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'diffie-hellman-group-exchange-sha512@ssh.com': [[], [], [WARN_NOT_PQ_SAFE]],
            'ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org': [[], [FAIL_NSA_BACKDOORED_CURVE]],
            'ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org': [[], [FAIL_NSA_BACKDOORED_CURVE]],
            'ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org': [[], [FAIL_NSA_BACKDOORED_CURVE]],
            'ecdh-sha2-1.2.840.10045.3.1.1': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-192 / secp192r1
            'ecdh-sha2-1.2.840.10045.3.1.7': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-256 / secp256r1
            'ecdh-sha2-1.3.132.0.10': [[], [], [WARN_NOT_PQ_SAFE]],  # ECDH over secp256k1 (i.e.: the Bitcoin curve)
            'ecdh-sha2-1.3.132.0.16': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],  # sect283k1
            'ecdh-sha2-1.3.132.0.1': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],  # sect163k1
            'ecdh-sha2-1.3.132.0.26': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],  # sect233k1
            'ecdh-sha2-1.3.132.0.27': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # sect233r1
            'ecdh-sha2-1.3.132.0.33': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-224 / secp224r1
            'ecdh-sha2-1.3.132.0.34': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-384 / secp384r1
            'ecdh-sha2-1.3.132.0.35': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-521 / secp521r1
            'ecdh-sha2-1.3.132.0.36': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],  # sect409k1
            'ecdh-sha2-1.3.132.0.37': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # sect409r1
            'ecdh-sha2-1.3.132.0.38': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],  # sect571k1

            # Note: the base64 strings, according to draft 6 of RFC5656, is Base64(MD5(DER(OID))).  The final RFC5656 dropped the base64 strings in favor of plain OID concatenation, but apparently some SSH servers implement them anyway.  See: https://datatracker.ietf.org/doc/html/draft-green-secsh-ecc-06#section-9.2
            'ecdh-sha2-4MHB+NBt3AlaSRQ7MnB4cg==': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],  # sect163k1
            'ecdh-sha2-5pPrSUQtIaTjUSt5VZNBjg==': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-192 / secp192r1
            'ecdh-sha2-9UzNcgwTlEnSCECZa7V1mw==': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-256 / secp256r1
            'ecdh-sha2-brainpoolp256r1@genua.de': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-brainpoolp384r1@genua.de': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-brainpoolp521r1@genua.de': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-curve25519': [[], [], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-D3FefCjYoJ/kfXgAyLddYA==': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # sect409r1
            'ecdh-sha2-h/SsxnLCtRBh7I9ATyeB3A==': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-521 / secp521r1
            'ecdh-sha2-m/FtSAmrV4j/Wy6RVUaK7A==': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],  # sect409k1
            'ecdh-sha2-mNVwCXAoS1HGmHpLvBC94w==': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],  # sect571k1
            'ecdh-sha2-nistb233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistb409': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistk163': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistk233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistk283': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistk409': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistp192': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistp224': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistp256': [['5.7,d2013.62,l10.6.0'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistp384': [['5.7,d2013.62'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistp521': [['5.7,d2013.62'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-nistt571': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ecdh-sha2-qCbG5Cn/jjsZ7nBeR7EnOA==': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # sect233r1
            'ecdh-sha2-qcFQaMAMGhTziMT0z+Tuzw==': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],  # NIST P-384 / secp384r1
            'ecdh-sha2-VqBg4QRPjxx1EXZdV0GdWQ==': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],  # NIST P-224 / secp224r1
            'ecdh-sha2-wiRIU8TKjMZ418sMqlqtvQ==': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],  # sect283k1
            'ecdh-sha2-zD/b3hu/71952ArpUG4OjQ==': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_NOT_PQ_SAFE]],  # sect233k1
            'ecmqv-sha2': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'ext-info-c': [['7.2'], [], [], [INFO_EXTENSION_NEGOTIATION]],  # Extension negotiation (RFC 8308)
            'ext-info-s': [['9.6'], [], [], [INFO_EXTENSION_NEGOTIATION]],  # Extension negotiation (RFC 8308)
            'kex-strict-c-v00@openssh.com': [[], [], [], [INFO_STRICT_KEX]],  # Strict KEX marker (countermeasure for CVE-2023-48795).
            'kex-strict-s-v00@openssh.com': [[], [], [], [INFO_STRICT_KEX]],  # Strict KEX marker (countermeasure for CVE-2023-48795).

            # The GSS kex algorithms get special wildcard handling, since they include variable base64 data after their standard prefixes.
            'gss-13.3.132.0.10-sha256-*': [[], [FAIL_UNKNOWN], [WARN_NOT_PQ_SAFE]],
            'gss-curve25519-sha256-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-curve448-sha512-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-gex-sha1-*': [[], [FAIL_SHA1], [WARN_NOT_PQ_SAFE]],
            'gss-gex-sha256-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-group14-sha1-*': [[], [FAIL_SHA1], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'gss-group14-sha256-*': [[], [], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'gss-group15-sha512-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-group16-sha512-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-group17-sha512-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-group18-sha512-*': [[], [], [WARN_NOT_PQ_SAFE]],
            'gss-group1-sha1-*': [[], [FAIL_1024BIT_MODULUS, FAIL_LOGJAM_ATTACK, FAIL_SHA1], [WARN_NOT_PQ_SAFE]],
            'gss-nistp256-sha256-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'gss-nistp384-sha256-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'gss-nistp384-sha384-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'gss-nistp521-sha512-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'kexAlgoCurve25519SHA256': [[], [], [WARN_NOT_PQ_SAFE]],
            'kexAlgoDH14SHA1': [[], [FAIL_SHA1], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'kexAlgoDH1SHA1': [[], [FAIL_1024BIT_MODULUS, FAIL_LOGJAM_ATTACK, FAIL_SHA1], [WARN_NOT_PQ_SAFE]],
            'kexAlgoECDH256': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'kexAlgoECDH384': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'kexAlgoECDH521': [[], [FAIL_NSA_BACKDOORED_CURVE], [WARN_NOT_PQ_SAFE]],
            'kexguess2@matt.ucc.asn.au': [['d2013.57'], [], [WARN_NOT_PQ_SAFE]],
            'm383-sha384@libassh.org': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'm511-sha512@libassh.org': [[], [FAIL_UNPROVEN], [WARN_NOT_PQ_SAFE]],
            'mlkem768x25519-sha256': [['9.9'], [], [], [INFO_DEFAULT_OPENSSH_KEX_100, INFO_HYBRID_PQ_X25519_KEX]],
            'mlkem768nistp256-sha256': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [INFO_HYBRID_PQ_NISTP_KEX]],
            'mlkem1024nistp384-sha384': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [INFO_HYBRID_PQ_NISTP_KEX]],
            'rsa1024-sha1': [[], [FAIL_1024BIT_MODULUS, FAIL_SHA1], [WARN_NOT_PQ_SAFE]],
            'rsa2048-sha256': [[], [], [WARN_2048BIT_MODULUS, WARN_NOT_PQ_SAFE]],
            'sm2kep-sha2-nistp256': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_UNTRUSTED], [WARN_NOT_PQ_SAFE]],
            'sntrup4591761x25519-sha512@tinyssh.org': [['8.0', '8.4'], [], [WARN_EXPERIMENTAL], [INFO_WITHDRAWN_PQ_ALG]],
            'sntrup761x25519-sha512': [['9.9'], [], [], [INFO_DEFAULT_OPENSSH_KEX_99, INFO_HYBRID_PQ_X25519_KEX]],
            'sntrup761x25519-sha512@openssh.com': [['8.5'], [], [], [INFO_DEFAULT_OPENSSH_KEX_90_TO_98, INFO_HYBRID_PQ_X25519_KEX]],
            'x25519-kyber-512r3-sha256-d00@amazon.com': [[]],
            'x25519-kyber512-sha512@aws.amazon.com': [[]],
        },
        'key': {
            'dsa2048-sha224@libassh.org': [[], [FAIL_UNPROVEN], [WARN_2048BIT_MODULUS]],
            'dsa2048-sha256@libassh.org': [[], [FAIL_UNPROVEN], [WARN_2048BIT_MODULUS]],
            'dsa3072-sha256@libassh.org': [[], [FAIL_UNPROVEN]],
            'ecdsa-sha2-1.3.132.0.10-cert-v01@openssh.com': [[], [FAIL_UNKNOWN]],
            'ecdsa-sha2-1.3.132.0.10': [[], [], [WARN_RNDSIG_KEY]],  # ECDSA over secp256k1 (i.e.: the Bitcoin curve)
            'ecdsa-sha2-curve25519': [[], [], [WARN_RNDSIG_KEY]],  # ECDSA with Curve25519?  Bizarre...
            'ecdsa-sha2-nistb233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistb409': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistk163': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistk233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistk283': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistk409': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp224': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp192': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp256': [['5.7,d2013.62,l10.6.4'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp256-cert-v01@openssh.com': [['5.7'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp384': [['5.7,d2013.62,l10.6.4'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp384-cert-v01@openssh.com': [['5.7'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp521': [['5.7,d2013.62,l10.6.4'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistp521-cert-v01@openssh.com': [['5.7'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'ecdsa-sha2-nistt571': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY]],
            'eddsa-e382-shake256@libassh.org': [[], [FAIL_UNPROVEN]],
            'eddsa-e521-shake256@libassh.org': [[], [FAIL_UNPROVEN]],
            'mldsa-44': [[], [], [], [INFO_NIST_PQC_LEVEL_2]],
            'mldsa-65': [[], [], [], [INFO_NIST_PQC_LEVEL_3]],
            'mldsa-87': [[], [], [], [INFO_NIST_PQC_LEVEL_5]],
            'null': [[], [FAIL_PLAINTEXT]],
            'pgp-sign-dss': [[], [FAIL_1024BIT_MODULUS]],
            'pgp-sign-rsa': [[], [FAIL_1024BIT_MODULUS]],
            'rsa-sha2-256': [['7.2,d2020.79']],
            'rsa-sha2-256-cert-v01@openssh.com': [['7.8']],
            'rsa-sha2-512': [['7.2']],
            'rsa-sha2-512-cert-v01@openssh.com': [['7.8']],
            'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com': [['8.2'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'sk-ecdsa-sha2-nistp256@openssh.com': [['8.2'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY]],
            'sk-ssh-ed25519-cert-v01@openssh.com': [['8.2']],
            'sk-ssh-ed25519@openssh.com': [['8.2']],
            'spi-sign-rsa': [[]],
            'spki-sign-dss': [[], [FAIL_1024BIT_MODULUS]],
            'spki-sign-rsa': [[], [FAIL_1024BIT_MODULUS]],
            'ssh-dsa': [[], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY]],
            'ssh-dss': [['2.1.0,d0.28,l10.2', '6.9'], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [INFO_DISABLED_IN_OPENSSH70]],
            'ssh-dss-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [INFO_DISABLED_IN_OPENSSH70]],
            'ssh-dss-cert-v01@openssh.com': [['5.6', '6.9'], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY]],
            'ssh-dss-sha224@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'ssh-dss-sha256@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'ssh-dss-sha384@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'ssh-dss-sha512@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'ssh-ed25519': [['6.5,d2020.79,l10.7.0']],
            'ssh-ed25519-cert-v01@openssh.com': [['6.5']],
            'ssh-ed448': [[]],
            'ssh-ed448-cert-v01@openssh.com': [[], [], [], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],
            'ssh-gost2001': [[], [FAIL_UNTRUSTED]],
            'ssh-gost2012-256': [[], [FAIL_UNTRUSTED]],
            'ssh-gost2012-512': [[], [FAIL_UNTRUSTED]],
            'ssh-mldsa-44': [[], [], [], [INFO_NIST_PQC_LEVEL_2]],
            'ssh-mldsa-65': [[], [], [], [INFO_NIST_PQC_LEVEL_3]],
            'ssh-mldsa-87': [[], [], [], [INFO_NIST_PQC_LEVEL_5]],
            'ssh-mldsa44': [[], [], [], [INFO_NIST_PQC_LEVEL_2]],
            'ssh-mldsa44-ed25519@openssh.com': [['10.4'], [], [], [INFO_NIST_PQC_LEVEL_2]],
            'ssh-mldsa65': [[], [], [], [INFO_NIST_PQC_LEVEL_3]],
            'ssh-mldsa87': [[], [], [], [INFO_NIST_PQC_LEVEL_5]],
            'ssh-rsa1': [[], [FAIL_SHA1]],
            'ssh-rsa': [['2.5.0,d0.28,l10.2'], [FAIL_SHA1], [], [INFO_DEPRECATED_IN_OPENSSH88]],
            'ssh-rsa-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_SHA1], [], [INFO_REMOVED_IN_OPENSSH70]],
            'ssh-rsa-cert-v01@openssh.com': [['5.6'], [FAIL_SHA1], [], [INFO_DEPRECATED_IN_OPENSSH88]],
            'ssh-rsa-sha224@ssh.com': [[]],
            'ssh-rsa-sha2-256': [[]],
            'ssh-rsa-sha2-512': [[]],
            'ssh-rsa-sha256@ssh.com': [[]],
            'ssh-rsa-sha384@ssh.com': [[]],
            'ssh-rsa-sha512@ssh.com': [[]],
            'ssh-xmss-cert-v01@openssh.com': [['7.7'], [WARN_EXPERIMENTAL]],
            'ssh-xmss@openssh.com': [['7.7'], [WARN_EXPERIMENTAL]],
            'webauthn-sk-ecdsa-sha2-nistp256@openssh.com': [['8.3'], [FAIL_NSA_BACKDOORED_CURVE]],
            'webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com': [['10.3'], [FAIL_NSA_BACKDOORED_CURVE]],
            'x509v3-ecdsa-sha2-1.3.132.0.10': [[], [FAIL_UNKNOWN]],
            'x509v3-ecdsa-sha2-nistp256': [[], [FAIL_NSA_BACKDOORED_CURVE]],
            'x509v3-ecdsa-sha2-nistp384': [[], [FAIL_NSA_BACKDOORED_CURVE]],
            'x509v3-ecdsa-sha2-nistp521': [[], [FAIL_NSA_BACKDOORED_CURVE]],
            'x509v3-rsa2048-sha256': [[]],
            'x509v3-sign-dss': [[], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY]],
            'x509v3-sign-dss-sha1': [[], [FAIL_1024BIT_MODULUS, FAIL_SHA1]],
            'x509v3-sign-dss-sha224@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'x509v3-sign-dss-sha256@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'x509v3-sign-dss-sha384@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'x509v3-sign-dss-sha512@ssh.com': [[], [FAIL_1024BIT_MODULUS]],
            'x509v3-sign-rsa': [[], [FAIL_SHA1]],
            'x509v3-sign-rsa-sha1': [[], [FAIL_SHA1]],
            'x509v3-sign-rsa-sha224@ssh.com': [[]],
            'x509v3-sign-rsa-sha256': [[]],
            'x509v3-sign-rsa-sha256@ssh.com': [[]],
            'x509v3-sign-rsa-sha384@ssh.com': [[]],
            'x509v3-sign-rsa-sha512@ssh.com': [[]],
            'x509v3-ssh-dss': [[], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY]],
            'x509v3-ssh-rsa': [[], [FAIL_SHA1], [], [INFO_DEPRECATED_IN_OPENSSH88]],
        },
        'enc': {
            '3des-cbc': [['1.2.2,d0.28,l10.2', '6.6', None], [FAIL_3DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            '3des-cfb': [[], [FAIL_3DES], [WARN_CIPHER_MODE]],
            '3des-ctr': [['d0.52'], [FAIL_3DES]],
            '3des-ecb': [[], [FAIL_3DES], [WARN_CIPHER_MODE]],
            '3des': [[], [FAIL_3DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            '3des-ofb': [[], [FAIL_3DES], [WARN_CIPHER_MODE]],
            'AEAD_AES_128_GCM': [[]],
            'AEAD_AES_256_GCM': [[]],
            'AEAD_CAMELLIA_128_GCM': [[]],
            'AEAD_CAMELLIA_256_GCM': [[]],
            'aes128-cbc': [['2.3.0,d0.28,l10.2', '6.6', None], [], [WARN_CIPHER_MODE]],
            'aes128-ctr': [['3.7,d0.52,l10.4.1']],
            'aes128-gcm': [[]],
            'aes128-gcm@openssh.com': [['6.2']],
            'aes128-ocb@libassh.org': [[], [], [WARN_CIPHER_MODE]],
            'aes192-cbc': [['2.3.0,l10.2', '6.6', None], [], [WARN_CIPHER_MODE]],
            'aes192-ctr': [['3.7,l10.4.1']],
            'aes192-gcm@openssh.com': [[], [], [], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],
            'aes256-cbc': [['2.3.0,d0.47,l10.2', '6.6', None], [], [WARN_CIPHER_MODE]],
            'aes256-ctr': [['3.7,d0.52,l10.4.1']],
            'aes256-gcm': [[]],
            'aes256-gcm@openssh.com': [['6.2']],
            'arcfour128': [['4.2', '6.6', '7.1'], [FAIL_RC4]],
            'arcfour': [['2.1.0', '6.6', '7.1'], [FAIL_RC4]],
            'arcfour256': [['4.2', '6.6', '7.1'], [FAIL_RC4]],
            'blowfish-cbc': [['1.2.2,d0.28,l10.2', '6.6,d0.52', '7.1,d0.52'], [FAIL_BLOWFISH], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'blowfish-cfb': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE]],
            'blowfish-ctr': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'blowfish-ecb': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE]],
            'blowfish': [[], [FAIL_BLOWFISH], [WARN_BLOCK_SIZE]],
            'blowfish-ofb': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE]],
            'camellia128-cbc@openssh.org': [[], [], [WARN_CIPHER_MODE]],
            'camellia128-cbc': [[], [], [WARN_CIPHER_MODE]],
            'camellia128-ctr': [[]],
            'camellia128-ctr@openssh.org': [[]],
            'camellia192-cbc@openssh.org': [[], [], [WARN_CIPHER_MODE]],
            'camellia192-cbc': [[], [], [WARN_CIPHER_MODE]],
            'camellia192-ctr': [[]],
            'camellia192-ctr@openssh.org': [[]],
            'camellia256-cbc@openssh.org': [[], [], [WARN_CIPHER_MODE]],
            'camellia256-cbc': [[], [], [WARN_CIPHER_MODE]],
            'camellia256-ctr': [[]],
            'camellia256-ctr@openssh.org': [[]],
            'cast128-12-cbc@ssh.com': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-cbc': [['2.1.0', '6.6', '7.1'], [FAIL_CAST], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'cast128-12-cbc': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-12-cfb': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-12-ecb': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-12-ofb': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-cfb': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-ctr': [[], [FAIL_CAST]],
            'cast128-ecb': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'cast128-ofb': [[], [FAIL_CAST], [WARN_CIPHER_MODE]],
            'chacha20-poly1305': [[], [], [], [INFO_DEFAULT_OPENSSH_CIPHER]],
            'chacha20-poly1305@openssh.com': [['6.5,d2020.79'], [], [], [INFO_DEFAULT_OPENSSH_CIPHER]],
            'crypticore128@ssh.com': [[], [FAIL_UNPROVEN]],
            'des-cbc': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'des-cfb': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'des-ecb': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'des-ofb': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'des-cbc-ssh1': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'des-cbc@ssh.com': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'des': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
            'grasshopper-ctr128': [[], [FAIL_UNTRUSTED]],
            'idea-cbc': [[], [FAIL_IDEA], [WARN_CIPHER_MODE]],
            'idea-cfb': [[], [FAIL_IDEA], [WARN_CIPHER_MODE]],
            'idea-ctr': [[], [FAIL_IDEA]],
            'idea-ecb': [[], [FAIL_IDEA], [WARN_CIPHER_MODE]],
            'idea-ofb': [[], [FAIL_IDEA], [WARN_CIPHER_MODE]],
            'none': [['1.2.2,d2013.56,l10.2'], [FAIL_PLAINTEXT]],
            'rijndael128-cbc': [['2.3.0', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70]],
            'rijndael192-cbc': [['2.3.0', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70]],
            'rijndael256-cbc': [['2.3.0', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70]],
            'rijndael-cbc@lysator.liu.se': [['2.3.0', '6.6', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70]],
            'rijndael-cbc@ssh.com': [[], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE]],
            'seed-cbc@ssh.com': [[], [FAIL_SEED], [WARN_CIPHER_MODE]],
            'seed-ctr@ssh.com': [[], [FAIL_SEED]],
            'serpent128-cbc': [[], [FAIL_SERPENT], [WARN_CIPHER_MODE]],
            'serpent128-ctr': [[], [FAIL_SERPENT]],
            'serpent128-gcm@libassh.org': [[], [FAIL_SERPENT]],
            'serpent192-cbc': [[], [FAIL_SERPENT], [WARN_CIPHER_MODE]],
            'serpent192-ctr': [[], [FAIL_SERPENT]],
            'serpent256-cbc': [[], [FAIL_SERPENT], [WARN_CIPHER_MODE]],
            'serpent256-ctr': [[], [FAIL_SERPENT]],
            'serpent256-gcm@libassh.org': [[], [FAIL_SERPENT]],
            'twofish128-cbc': [['d0.47', 'd2014.66'], [], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_DBEAR67]],
            'twofish128-ctr': [['d2015.68']],
            'twofish128-gcm@libassh.org': [[]],
            'twofish192-cbc': [[], [], [WARN_CIPHER_MODE]],
            'twofish192-ctr': [[]],
            'twofish256-cbc': [['d0.47', 'd2014.66'], [], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_DBEAR67]],
            'twofish256-ctr': [['d2015.68']],
            'twofish256-gcm@libassh.org': [[]],
            'twofish-cbc': [['d0.28', 'd2014.66'], [], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_DBEAR67]],
            'twofish-cfb': [[], [], [WARN_CIPHER_MODE]],
            'twofish-ctr': [[]],
            'twofish-ecb': [[], [], [WARN_CIPHER_MODE]],
            'twofish-ofb': [[], [], [WARN_CIPHER_MODE]],
        },
        'mac': {
            'AEAD_AES_128_GCM': [[]],
            'AEAD_AES_256_GCM': [[]],
            'aes128-gcm': [[]],
            'aes256-gcm': [[]],
            'cbcmac-3des': [[], [FAIL_UNPROVEN, FAIL_3DES]],
            'cbcmac-aes': [[], [FAIL_UNPROVEN]],
            'cbcmac-blowfish': [[], [FAIL_UNPROVEN, FAIL_BLOWFISH]],
            'cbcmac-des': [[], [FAIL_UNPROVEN, FAIL_DES]],
            'cbcmac-rijndael': [[], [FAIL_UNPROVEN, FAIL_RIJNDAEL]],
            'cbcmac-twofish': [[], [FAIL_UNPROVEN]],
            'chacha20-poly1305@openssh.com': [[], [], [], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],  # Despite the @openssh.com tag, this was never shipped as a MAC in OpenSSH (only as a cipher); it is only implemented as a MAC in Syncplify.
            'crypticore-mac@ssh.com': [[], [FAIL_UNPROVEN]],
            'hmac-md5': [['2.1.0,d0.28', '6.6', '7.1'], [FAIL_MD5], [WARN_ENCRYPT_AND_MAC]],
            'hmac-md5-96': [['2.5.0', '6.6', '7.1'], [FAIL_MD5], [WARN_ENCRYPT_AND_MAC]],
            'hmac-md5-96-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_MD5]],
            'hmac-md5-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_MD5]],
            'hmac-ripemd160': [['2.5.0', '6.6', '7.1'], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC]],
            'hmac-ripemd160-96': [[], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE]],
            'hmac-ripemd160-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_RIPEMD]],
            'hmac-ripemd160@openssh.com': [['2.1.0', '6.6', '7.1'], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC]],
            'hmac-ripemd': [[], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha1': [['2.1.0,d0.28,l10.2'], [FAIL_SHA1], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha1-96': [['2.5.0,d0.47', '6.6', '7.1'], [FAIL_SHA1], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha1-96-etm@openssh.com': [['6.2', '6.6', None], [FAIL_SHA1]],
            'hmac-sha1-96@openssh.com': [[], [FAIL_SHA1], [WARN_TAG_SIZE, WARN_ENCRYPT_AND_MAC], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],
            'hmac-sha1-etm@openssh.com': [['6.2'], [FAIL_SHA1]],
            'hmac-sha2-224': [[], [], [WARN_TAG_SIZE, WARN_ENCRYPT_AND_MAC]],
            'hmac-sha224@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha2-256': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha2-256-96': [['5.9', '6.0'], [], [WARN_ENCRYPT_AND_MAC], [INFO_REMOVED_IN_OPENSSH61]],
            'hmac-sha2-256-96-etm@openssh.com': [[], [], [WARN_TAG_SIZE_96], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],  # Only ever implemented in AsyncSSH (?).
            'hmac-sha2-256-etm@openssh.com': [['6.2']],
            'hmac-sha2-384': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha2-512': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha2-512-96': [['5.9', '6.0'], [], [WARN_ENCRYPT_AND_MAC], [INFO_REMOVED_IN_OPENSSH61]],
            'hmac-sha2-512-96-etm@openssh.com': [[], [], [WARN_TAG_SIZE_96], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],  # Only ever implemented in AsyncSSH (?).
            'hmac-sha2-512-etm@openssh.com': [['6.2']],
            'hmac-sha256-2@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha256-96@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE]],
            'hmac-sha256-96': [[], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE]],
            'hmac-sha256@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha256': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha2-56': [[], [], [WARN_TAG_SIZE, WARN_ENCRYPT_AND_MAC]],
            'hmac-sha3-224': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha3-256': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha3-384': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha3-512': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha384@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha512@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-sha512': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'hmac-whirlpool': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'md5':  [[], [FAIL_PLAINTEXT]],
            'md5-8':  [[], [FAIL_PLAINTEXT]],
            'none': [['d2013.56'], [FAIL_PLAINTEXT]],
            'ripemd160':  [[], [FAIL_PLAINTEXT]],
            'ripemd160-8':  [[], [FAIL_PLAINTEXT]],
            'sha1':  [[], [FAIL_PLAINTEXT]],
            'sha1-8':  [[], [FAIL_PLAINTEXT]],
            'umac-128': [[], [], [WARN_ENCRYPT_AND_MAC]],
            'umac-128-etm@openssh.com': [['6.2']],
            'umac-128@openssh.com': [['6.2'], [], [WARN_ENCRYPT_AND_MAC]],
            'umac-32@openssh.com': [[], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],
            'umac-64-etm@openssh.com': [['6.2'], [], [WARN_TAG_SIZE]],
            'umac-64@openssh.com': [['4.7'], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE]],
            'umac-96@openssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH]],
        }
    }
    # fmt: on


def version_key(version: str) -> tuple[int, ...]:
    """Sort key for dotted version strings: numeric components as integers.

    Plain string comparison ordered '0.10.4' below '0.7.2' and '10.0' below
    '7.3', which reported CVEs against patched libssh releases and aged
    OpenSSH 10.x below 7.3. Non-digit characters only separate components.
    """
    return tuple(int(part) for part in re.findall(r'\d+', version))


def get_ssh_version(version_desc: str) -> tuple[str, str]:
    if version_desc.startswith('d'):
        return (SSH.Product.DropbearSSH, version_desc[1:])
    elif version_desc.startswith('l1'):
        return (SSH.Product.LibSSH, version_desc[2:])
    else:
        return (SSH.Product.OpenSSH, version_desc)


def get_alg_timeframe(
    versions: list[str | None], result: dict[str, list[str | None]] | None = None
) -> dict[str, list[str | None]]:
    """Merge one algorithm's [since, removed-in-server, removed-in-client] versions into ``result``.

    Versions suffixed with ``C`` only apply to clients and are skipped: this tool audits servers.
    """
    result = result or {}
    vlen = len(versions)
    for i in range(3):
        if i > vlen - 1:
            if i == 2 and vlen > 1:
                cversions = versions[1]
            else:
                continue
        else:
            cversions = versions[i]
        if cversions is None:
            continue
        for v in cversions.split(','):
            ssh_prefix, ssh_version = get_ssh_version(v)
            if not ssh_version or ssh_version.endswith('C'):
                continue
            if ssh_prefix not in result:
                result[ssh_prefix] = [None, None, None]
            prev, push = result[ssh_prefix][i], False
            if prev is None:
                push = True
            elif i == 0 and version_key(prev) < version_key(ssh_version):
                push = True
            elif i > 0 and version_key(prev) > version_key(ssh_version):
                push = True
            if push:
                result[ssh_prefix][i] = ssh_version
    return result


def get_ssh_timeframe(
    alg_pairs: list[tuple[int, AlgorithmDB, list[tuple[str, list[str]]]]],
) -> dict[str, list[str | None]]:
    timeframe: dict[str, list[str | None]] = {}
    for alg_pair in alg_pairs:
        alg_db = alg_pair[1]
        for alg_set in alg_pair[2]:
            alg_type, alg_list = alg_set
            for alg_name in alg_list:
                alg_name_native = alg_name
                alg_desc = alg_db[alg_type].get(alg_name_native)
                if alg_desc is None:
                    continue
                versions = alg_desc[0]
                timeframe = get_alg_timeframe(versions, timeframe)
    return timeframe


def get_alg_since_text(versions: list[str | None]) -> str | None:
    tv = []
    if len(versions) == 0 or versions[0] is None:
        return None
    for v in versions[0].split(','):
        ssh_prefix, ssh_version = get_ssh_version(v)
        if not ssh_version:
            continue
        if ssh_prefix in [SSH.Product.LibSSH]:
            continue
        if ssh_version.endswith('C'):
            ssh_version = f'{ssh_version[:-1]} (client only)'
        tv.append(f'{ssh_prefix} {ssh_version}')
    if len(tv) == 0:
        return None
    return 'available since ' + ', '.join(tv).rstrip(', ')


def get_alg_pairs(
    kex: SSH2.Kex | None, pkm: SSH1.PublicKeyMessage | None
) -> list[tuple[int, AlgorithmDB, list[tuple[str, list[str]]]]]:
    alg_pairs = []
    if pkm is not None:
        alg_pairs.append(
            (
                1,
                SSH1.KexDB.ALGORITHMS,
                [
                    ('key', ['ssh-rsa1']),
                    ('enc', pkm.supported_ciphers),
                    ('aut', pkm.supported_authentications),
                ],
            )
        )
    if kex is not None:
        alg_pairs.append(
            (
                2,
                KexDB.ALGORITHMS,
                [
                    ('kex', kex.kex_algorithms),
                    ('key', kex.key_algorithms),
                    ('enc', kex.server.encryption),
                    ('mac', kex.server.mac),
                ],
            )
        )
    return alg_pairs


def get_alg_recommendations(
    software: SSH.Software | None,
    kex: SSH2.Kex | None,
    pkm: SSH1.PublicKeyMessage | None,
) -> tuple[SSH.Software | None, dict[int, dict[str, dict[str, dict[str, int]]]]]:
    """Algorithms to remove (faults found) and to append (fault-free, supported).

    Follows jtesta/ssh-audit v3.9.0, whose database this tool uses. Only
    OpenSSH, Dropbear SSH and libssh have version data, so for any other or
    unrecognised software nothing is appended: guessing the product from the
    offered algorithms gave wrong advice. Certificate, security-key and
    pseudo-algorithms (ext-info, kex-strict) are never suggested, nor is any
    algorithm without version data. Upstream's "change modulus size" action is
    omitted because this tool does not measure host-key or group sizes.
    """
    alg_pairs = get_alg_pairs(kex, pkm)
    vproducts = [SSH.Product.OpenSSH, SSH.Product.DropbearSSH, SSH.Product.LibSSH]
    known = software if software is not None and software.product in vproducts else None
    rec: dict[int, dict[str, dict[str, dict[str, int]]]] = {}
    for alg_pair in alg_pairs:
        sshv, alg_db = alg_pair[0], alg_pair[1]
        rec[sshv] = {}
        for alg_set in alg_pair[2]:
            alg_type, alg_list = alg_set
            if alg_type == 'aut':
                continue
            rec[sshv][alg_type] = {'add': {}, 'del': {}}
            for n, alg_desc in alg_db[alg_type].items():
                versions = alg_desc[0]
                empty_version = len(versions) == 0 or versions[0] is None
                # Version data only decides what this server could append; an algorithm it
                # already offers is supported regardless of what the version table says.
                if known is not None and n not in alg_list and versions and versions[0] is not None:
                    matches = False
                    for v in versions[0].split(','):
                        ssh_prefix, ssh_version = get_ssh_version(v)
                        if not ssh_version:
                            continue
                        if ssh_prefix != known.product or ssh_version.endswith('C'):
                            continue
                        if known.compare_version(ssh_version) < 0:
                            continue
                        matches = True
                        break
                    if not matches:
                        continue
                adl, faults = len(alg_desc), 0
                for i in range(1, 3):
                    if not adl > i:
                        continue
                    fc = len(alg_desc[i])
                    if fc > 0:
                        faults += pow(10, 2 - i) * fc
                if n not in alg_list:
                    if (
                        faults > 0
                        or empty_version
                        or known is None
                        or (alg_type == 'key' and ('-cert-' in n or n.startswith('sk-')))
                        or (alg_type == 'kex' and n.startswith(('ext-info-', 'kex-strict-')))
                    ):
                        continue
                    rec[sshv][alg_type]['add'][n] = 0
                else:
                    if faults == 0:
                        continue
                    rec[sshv][alg_type]['del'][n] = faults
            add_count = len(rec[sshv][alg_type]['add'])
            del_count = len(rec[sshv][alg_type]['del'])
            new_alg_count = len(alg_list) + add_count - del_count
            # Never recommend removing every algorithm of a type: keep the least-faulty ones.
            if new_alg_count < 1 and del_count > 0:
                mf = min(rec[sshv][alg_type]['del'].values())
                new_del = {}
                for k, cf in rec[sshv][alg_type]['del'].items():
                    if cf != mf:
                        new_del[k] = cf
                rec[sshv][alg_type]['del'] = new_del
                new_alg_count += del_count - len(new_del)
            if new_alg_count < 1:
                del rec[sshv][alg_type]
            else:
                if add_count == 0:
                    del rec[sshv][alg_type]['add']
                if len(rec[sshv][alg_type]['del']) == 0:
                    del rec[sshv][alg_type]['del']
                if len(rec[sshv][alg_type]) == 0:
                    del rec[sshv][alg_type]
        if len(rec[sshv]) == 0:
            del rec[sshv]
    return software, rec


def output_algorithms(
    title: str, alg_db: AlgorithmDB, alg_type: str, algorithms: list[str], maxlen: int
) -> None:
    with OutputBuffer() as obuf:
        for algorithm in algorithms:
            output_algorithm(alg_db, alg_type, algorithm, maxlen)
    if len(obuf) > 0:
        out.head('# ' + title)
        obuf.flush()
        out.sep()


def output_algorithm(alg_db: AlgorithmDB, alg_type: str, alg_name: str, alg_max_len: int) -> None:
    prefix = '(' + alg_type + ') '
    padding = '' if out.batch else ' ' * (alg_max_len - len(alg_name))
    texts = []
    if len(alg_name.strip()) == 0:
        return
    alg_name_native = alg_name
    if alg_name_native in alg_db[alg_type]:
        alg_desc = alg_db[alg_type][alg_name_native]
        ldesc = len(alg_desc)
        for idx, level in enumerate(['fail', 'warn', 'info']):
            if level == 'info':
                versions = alg_desc[0]
                since_text = get_alg_since_text(versions)
                if since_text:
                    texts.append((level, since_text))
            idx = idx + 1
            if ldesc > idx:
                texts.extend((level, t) for t in alg_desc[idx] if t is not None)
        if len(texts) == 0:
            texts.append(('info', ''))
    else:
        texts.append(('warn', 'unknown algorithm'))
    first = True
    for level, text in texts:
        f = getattr(out, level)
        text = '[' + level + '] ' + text
        if first:
            if first and level == 'info':
                f = out.good
            f(prefix + alg_name + padding + ' -- ' + text)
            first = False
        else:
            if out.verbose:
                f(prefix + alg_name + padding + ' -- ' + text)
            else:
                marker = Output.continuation_marker()
                f(' ' * len(prefix + alg_name) + padding + f' {marker} ' + text)


def output_compatibility(kex: SSH2.Kex | None, pkm: SSH1.PublicKeyMessage | None) -> None:
    alg_pairs = get_alg_pairs(kex, pkm)
    ssh_timeframe = get_ssh_timeframe(alg_pairs)
    comp_text = []
    for sshd_name in [SSH.Product.OpenSSH, SSH.Product.DropbearSSH]:
        if sshd_name not in ssh_timeframe:
            continue
        since, until = ssh_timeframe[sshd_name][0], ssh_timeframe[sshd_name][1]
        if until is None:
            comp_text.append(f'{sshd_name} {since}+')
        elif since == until:
            comp_text.append(f'{sshd_name} {since}')
        elif version_key(until) < version_key(since or ''):
            comp_text.append(f'{sshd_name} {since}+ (some functionality from {until})')
        else:
            comp_text.append(f'{sshd_name} {since}-{until}')
    if len(comp_text) > 0:
        out.good('(gen) compatibility: ' + ', '.join(comp_text))


def output_fingerprint(pkm: SSH1.PublicKeyMessage | None, padlen: int = 0) -> None:
    """Print host-key fingerprints. SSH1 only: SSH2 fingerprints need a key
    exchange, which this tool does not perform."""
    with OutputBuffer() as obuf:
        fps = []
        if pkm is not None:
            name = 'ssh-rsa1'
            fp = SSH.Fingerprint(pkm.host_key_fingerprint_data)
            bits = pkm.host_key_bits
            fps.append((name, fp, bits))
        for fpp in fps:
            name, fp, bits = fpp
            p = '' if out.batch else ' ' * (padlen - len(name))
            out.good(f'(fin) {name}{p} -- {bits} {fp.sha256}')
    if len(obuf) > 0:
        out.head('# fingerprints')
        obuf.flush()
        out.sep()


def output_recommendations(
    software: SSH.Software | None,
    kex: SSH2.Kex | None,
    pkm: SSH1.PublicKeyMessage | None,
    padlen: int = 0,
) -> None:
    with OutputBuffer() as obuf:
        software, alg_rec = get_alg_recommendations(software, kex, pkm)
        for sshv in range(2, 0, -1):
            if sshv not in alg_rec:
                continue
            for alg_type in ['kex', 'key', 'enc', 'mac']:
                if alg_type not in alg_rec[sshv]:
                    continue
                for action in ['del', 'add']:
                    if action not in alg_rec[sshv][alg_type]:
                        continue
                    for name in alg_rec[sshv][alg_type][action]:
                        p = '' if out.batch else ' ' * (padlen - len(name))
                        if action == 'del':
                            an, sg, fn = 'remove', '-', out.warn
                            if alg_rec[sshv][alg_type][action][name] >= 10:
                                fn = out.fail
                        else:
                            an, sg, fn = 'append', '+', out.good
                        b = f'(SSH{sshv})' if sshv == 1 else ''
                        fm = '(rec) {0}{1}{2}-- {3} algorithm to {4} {5}'
                        fn(fm.format(sg, name, p, alg_type, an, b))
    if len(obuf) > 0:
        title = f'(for {software.display(False)})' if software else ''
        out.head(f'# algorithm recommendations {title}')
        obuf.flush()
        out.sep()


def output(
    banner: SSH.Banner | None,
    header: list[str],
    kex: SSH2.Kex | None = None,
    pkm: SSH1.PublicKeyMessage | None = None,
) -> None:
    sshv = 1 if pkm else 2
    with OutputBuffer() as obuf:
        if len(header) > 0:
            out.info('(gen) header: ' + '\n'.join(header))
        if banner is not None:
            out.good(f'(gen) banner: {banner}')
            if not banner.valid_ascii:
                # NOTE: RFC 4253, Section 4.2
                out.warn('(gen) banner contains non-printable ASCII')
            if sshv == 1 or banner.protocol[0] == 1:
                out.fail('(gen) protocol SSH1 enabled')
            software = SSH.Software.parse(banner)
            if software is not None:
                out.good(f'(gen) software: {software}')
        else:
            software = None
        output_compatibility(kex, pkm)
        if kex is not None:
            compressions = [x for x in kex.server.compression if x != 'none']
            if len(compressions) > 0:
                cmptxt = f'enabled ({", ".join(compressions)})'
            else:
                cmptxt = 'disabled'
            out.good(f'(gen) compression: {cmptxt}')
    if len(obuf) > 0:
        out.head('# general')
        obuf.flush()
        out.sep()

    def ml(names: list[str]) -> int:
        return max(len(i) for i in names)

    maxlen = 0
    if pkm is not None:
        maxlen = max(ml(pkm.supported_ciphers), ml(pkm.supported_authentications), maxlen)
    if kex is not None:
        maxlen = max(
            ml(kex.kex_algorithms),
            ml(kex.key_algorithms),
            ml(kex.server.encryption),
            ml(kex.server.mac),
            maxlen,
        )
    maxlen += 1
    if pkm is not None:
        adb = SSH1.KexDB.ALGORITHMS
        ciphers = pkm.supported_ciphers
        auths = pkm.supported_authentications
        title, atype = 'SSH1 host-key algorithms', 'key'
        output_algorithms(title, adb, atype, ['ssh-rsa1'], maxlen)
        title, atype = 'SSH1 encryption algorithms (ciphers)', 'enc'
        output_algorithms(title, adb, atype, ciphers, maxlen)
        title, atype = 'SSH1 authentication types', 'aut'
        output_algorithms(title, adb, atype, auths, maxlen)
    if kex is not None:
        adb = KexDB.ALGORITHMS
        title, atype = 'key exchange algorithms', 'kex'
        output_algorithms(title, adb, atype, kex.kex_algorithms, maxlen)
        title, atype = 'host-key algorithms', 'key'
        output_algorithms(title, adb, atype, kex.key_algorithms, maxlen)
        title, atype = 'encryption algorithms (ciphers)', 'enc'
        output_algorithms(title, adb, atype, kex.server.encryption, maxlen)
        title, atype = 'message authentication code algorithms', 'mac'
        output_algorithms(title, adb, atype, kex.server.mac, maxlen)
    output_recommendations(software, kex, pkm, maxlen)
    output_fingerprint(pkm, maxlen)


def unique_seq[T](seq: Sequence[T]) -> tuple[T, ...]:
    """Drop repeated items, keeping the first occurrence's position.

    Order matters: the IP-version sequence encodes precedence, so ``-64``
    must stay ``(6, 4)`` after de-duplication.
    """
    return tuple(dict.fromkeys(seq))


def parse_int(v: Any) -> int:
    """Return ``int(v)``, or 0 when ``v`` is not an integer.

    0 is never a valid port, so callers treat it as "invalid" and report
    the original text instead of a traceback.
    """
    try:
        return int(v)
    except TypeError, ValueError:
        return 0


def audit(aconf: AuditConf, sshv: int | None = None) -> None:
    out.batch = aconf.batch
    out.colors = aconf.colors
    out.verbose = aconf.verbose
    out.minlevel = aconf.minlevel
    if aconf.host is None:
        raise ValueError('audit requires a host')
    if sshv is None:
        sshv = 2 if aconf.ssh2 else 1
    err = None
    kex: SSH2.Kex | None = None
    pkm: SSH1.PublicKeyMessage | None = None
    packet_type, payload = -1, b''
    # Closed before any SSH1 fallback reconnects, and on every sys.exit path.
    with SSH.Socket(aconf.host, aconf.port) as s:
        s.connect(aconf.ipvo)
        banner, header = s.get_banner(sshv)
        if banner is None:
            err = '[exception] did not receive banner.'
        else:
            packet_type, payload = s.read_packet(sshv)
    if err is None:
        if packet_type < 0:
            try:
                payload_txt = payload.decode('utf-8') if payload else 'empty'
            except UnicodeDecodeError:
                payload_txt = '"' + repr(payload).lstrip('b')[1:-1] + '"'
            if payload_txt == 'Protocol major versions differ.':
                if sshv == 2 and aconf.ssh1:
                    audit(aconf, 1)
                    return
            err = f'[exception] error reading packet ({payload_txt})'
        else:
            err_pair = None
            if sshv == 1 and packet_type != SSH.Protocol.SMSG_PUBLIC_KEY:
                err_pair = ('SMSG_PUBLIC_KEY', SSH.Protocol.SMSG_PUBLIC_KEY)
            elif sshv == 2 and packet_type != SSH.Protocol.MSG_KEXINIT:
                err_pair = ('MSG_KEXINIT', SSH.Protocol.MSG_KEXINIT)
            if err_pair is not None:
                fmt = (
                    '[exception] did not receive {0} ({1}), '
                    + 'instead received unknown message ({2})'
                )
                err = fmt.format(err_pair[0], err_pair[1], packet_type)
            else:
                # A correctly framed but truncated message body makes the
                # struct-based readers raise; report it like any other bad packet.
                try:
                    if sshv == 1:
                        pkm = SSH1.PublicKeyMessage.parse(payload)
                    else:
                        kex = SSH2.Kex.parse(payload)
                except struct.error:
                    name = 'SMSG_PUBLIC_KEY' if sshv == 1 else 'MSG_KEXINIT'
                    err = f'[exception] malformed {name} packet'
    if err:
        output(banner, header)
        out.error(err)
        sys.exit(1)
    output(banner, header, kex=kex, pkm=pkm)


class Colors:
    """ANSI colours for the output levels this tool prints; nothing more.

    The standard library has no public API for terminal colours (``_colorize``
    is private), so this covers exactly the four coloured levels. Colour is used
    only on a POSIX terminal, and ``NO_COLOR`` (https://no-color.org) turns it
    off. Windows consoles get plain text: enabling ANSI processing there needs
    console API calls this tool does not make.
    """

    CODES = {'head': 36, 'good': 32, 'warn': 33, 'fail': 31}

    @staticmethod
    def enabled(stream: TextIO) -> bool:
        isatty = getattr(stream, 'isatty', None)
        return os.name == 'posix' and 'NO_COLOR' not in os.environ and bool(isatty and isatty())

    @classmethod
    def paint(cls, level: str, text: str) -> str:
        """Wrap ``text`` in the colour for ``level``; levels without one stay plain."""
        code = cls.CODES.get(level)
        return text if code is None else f'\033[0;{code}m{text}\033[0m'


out = Output()
if __name__ == '__main__':
    conf = AuditConf.from_cmdline(sys.argv[1:], usage)
    audit(conf)
