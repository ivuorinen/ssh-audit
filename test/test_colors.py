import io
import os
import sys
import unittest
from unittest import mock

from helpers import load_ssh_audit

RED, YELLOW, GREEN, CYAN, RESET = '\x1b[0;31m', '\x1b[0;33m', '\x1b[0;32m', '\x1b[0;36m', '\x1b[0m'


class FakeTerminal(io.TextIOWrapper):
    """A byte-backed text stream that claims to be a terminal."""

    def __init__(self, encoding='utf-8'):
        super().__init__(io.BytesIO(), encoding=encoding, newline='\n')

    def isatty(self):
        return True

    def lines(self):
        self.flush()
        return self.buffer.getvalue().decode(self.encoding).splitlines()


class TestColors(unittest.TestCase):
    def setUp(self):
        self.sa = load_ssh_audit()
        self.out = self.sa.out
        self.out.batch, self.out.verbose, self.out.colors = False, False, True
        self.out.minlevel = 'info'
        env = {k: v for k, v in os.environ.items() if k != 'NO_COLOR'}
        patch = mock.patch.dict(os.environ, env, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def test_buffered_algorithm_lines_are_colored_by_level(self):
        # Algorithm sections print through an OutputBuffer; its StringIO is never a
        # terminal, which left every [fail] and [warn] line uncoloured.
        term = FakeTerminal()
        with mock.patch.object(sys, 'stdout', term):
            self.sa.output_algorithms(
                'host-key algorithms', self.sa.KexDB.ALGORITHMS, 'key', ['ssh-rsa'], 8
            )
            self.sa.output_algorithms(
                'kex', self.sa.KexDB.ALGORITHMS, 'kex', ['curve25519-sha256'], 18
            )
            self.sa.output_algorithms('key', self.sa.KexDB.ALGORITHMS, 'key', ['ssh-ed25519'], 11)
        lines = term.lines()
        self.assertIn(f'{CYAN}# host-key algorithms{RESET}', lines)
        self.assertIn(
            f'{RED}(key) ssh-rsa  -- [fail] using broken SHA-1 hash algorithm{RESET}', lines
        )
        warn = f'{YELLOW}(kex) curve25519-sha256  -- [warn] does not provide protection against post-quantum attacks{RESET}'
        self.assertIn(warn, lines)
        self.assertIn(
            f'{GREEN}(key) ssh-ed25519 -- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79{RESET}',
            lines,
        )
        # later [info] notes are informational continuations and stay uncoloured
        info = [line for line in lines if '└─ [info]' in line]
        self.assertTrue(info)
        self.assertFalse([line for line in info if '\x1b' in line])

    def test_no_color_when_redirected_or_opted_out(self):
        pipe = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        with mock.patch.object(sys, 'stdout', pipe):
            self.sa.output_algorithms('t', self.sa.KexDB.ALGORITHMS, 'key', ['ssh-rsa'], 8)
        pipe.flush()
        self.assertNotIn('\x1b', pipe.buffer.getvalue().decode())
        term = FakeTerminal()
        with mock.patch.object(sys, 'stdout', term), mock.patch.dict(os.environ, {'NO_COLOR': '1'}):
            self.sa.output_algorithms('t', self.sa.KexDB.ALGORITHMS, 'key', ['ssh-rsa'], 8)
        self.assertNotIn('\x1b', '\n'.join(term.lines()))
        term = FakeTerminal()
        self.out.colors = False
        with mock.patch.object(sys, 'stdout', term):
            self.sa.output_algorithms('t', self.sa.KexDB.ALGORITHMS, 'key', ['ssh-rsa'], 8)
        self.assertNotIn('\x1b', '\n'.join(term.lines()))

    def test_errors_are_red_on_a_terminal_stderr(self):
        term = FakeTerminal()
        with mock.patch.object(sys, 'stderr', term):
            self.out.error('[exception] boom')
        self.assertEqual(term.lines(), [f'{RED}[exception] boom{RESET}'])


class TestUnencodableOutput(unittest.TestCase):
    """Server text the output encoding cannot represent must not abort the audit."""

    def setUp(self):
        self.sa = load_ssh_audit()
        self.out = self.sa.out
        self.out.batch, self.out.colors = False, False
        self.out.minlevel = 'info'

    def test_unencodable_server_text_is_escaped_not_raised(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding='cp1252', newline='\n')
        with mock.patch.object(sys, 'stdout', stream):
            self.out.info('(gen) header: 中文 ü')
            with self.sa.OutputBuffer() as obuf:
                self.out.warn('(kex) 算法 -- [warn] unknown algorithm')
            obuf.flush()
        stream.flush()
        text = stream.buffer.getvalue().decode('cp1252')
        # ü exists in cp1252 and stays readable; CJK becomes a visible escape
        self.assertIn('(gen) header: \\u4e2d\\u6587 ü', text)
        self.assertIn('(kex) \\u7b97\\u6cd5 -- [warn] unknown algorithm', text)

    def test_unencodable_error_text_is_escaped_not_raised(self):
        stream = io.TextIOWrapper(io.BytesIO(), encoding='ascii', newline='\n')
        with mock.patch.object(sys, 'stderr', stream):
            self.out.error('[exception] error reading packet (é)')
        stream.flush()
        self.assertEqual(stream.buffer.getvalue(), b'[exception] error reading packet (\\xe9)\n')


if __name__ == '__main__':
    unittest.main()
