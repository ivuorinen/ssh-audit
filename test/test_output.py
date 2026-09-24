import os
import sys
import unittest
from unittest import mock

from helpers import capture, load_ssh_audit

LEVELS = ['info', 'head', 'good', 'warn', 'fail']


class TestOutput(unittest.TestCase):
    def setUp(self):
        ssh_audit = load_ssh_audit()
        self.Output = ssh_audit.Output
        self.OutputBuffer = ssh_audit.OutputBuffer

    def _emit_all(self, out):
        """Emit one line per level and return the captured stdout lines."""
        with capture() as output:
            for level in LEVELS:
                getattr(out, level)(f'{level} color')
        return output['out']

    def test_output_buffer_no_lines(self):
        with capture() as output, self.OutputBuffer():
            pass
        self.assertEqual(output['out'], [])
        with capture() as output:
            with self.OutputBuffer() as obuf:
                pass
            obuf.flush()
        self.assertEqual(output['out'], [])

    def test_output_buffer_no_flush(self):
        with capture() as output, self.OutputBuffer():
            print('abc')
        self.assertEqual(output['out'], [])

    def test_output_buffer_flush(self):
        with capture() as output:
            with self.OutputBuffer() as obuf:
                print('abc')
                print()
                print('def')
            obuf.flush()
        self.assertEqual(output['out'], ['abc', '', 'def'])

    def test_output_defaults(self):
        out = self.Output()
        self.assertIs(out.batch, False)
        self.assertIs(out.colors, True)
        self.assertEqual(out.minlevel, 'info')

    def test_output_colors(self):
        out = self.Output()
        out.colors = False
        for level in LEVELS:
            with capture() as output:
                getattr(out, level)(f'{level} color')
            self.assertEqual(output['out'], [f'{level} color'])
        out.colors = True
        expected = {
            'info': 'info color',
            'head': '\x1b[0;36mhead color\x1b[0m',
            'good': '\x1b[0;32mgood color\x1b[0m',
            'warn': '\x1b[0;33mwarn color\x1b[0m',
            'fail': '\x1b[0;31mfail color\x1b[0m',
        }
        with mock.patch.object(self.Output, 'colors_supported', True):
            for level in LEVELS:
                with capture() as output:
                    getattr(out, level)(f'{level} color')
                self.assertEqual(output['out'], [expected[level]])

    def test_colors_supported_only_on_a_terminal(self):
        out = self.Output()
        tty = mock.Mock(isatty=mock.Mock(return_value=True))
        pipe = mock.Mock(isatty=mock.Mock(return_value=False))
        with mock.patch.object(sys, 'stdout', pipe), mock.patch.dict(os.environ, clear=True):
            self.assertIs(out.colors_supported, False)
        with mock.patch.object(sys, 'stdout', tty), mock.patch.dict(os.environ, clear=True):
            self.assertIs(out.colors_supported, True)
        with mock.patch.object(sys, 'stdout', tty), mock.patch.dict(os.environ, {'NO_COLOR': '1'}):
            self.assertIs(out.colors_supported, False)

    def test_error_goes_to_stderr_at_any_level(self):
        out = self.Output()
        out.minlevel = 'invalid level'
        out.colors = False
        with capture() as output:
            out.error('[exception] boom\x1b')
        self.assertEqual(output['out'], [])
        self.assertEqual(output['err'], ['[exception] boom\\x1b'])

    def test_escape_ignores_unknown_stream_encoding(self):
        stream = mock.Mock(encoding='no-such-codec')
        self.assertEqual(self.Output.escape('a\x1bb', stream), 'a\\x1bb')

    def test_output_sep(self):
        out = self.Output()
        with capture() as output:
            out.sep()
            out.sep()
            out.sep()
        self.assertEqual(output['out'], ['', '', ''])

    def test_output_levels(self):
        out = self.Output()
        self.assertEqual(out.getlevel('info'), 0)
        self.assertEqual(out.getlevel('good'), 0)
        self.assertEqual(out.getlevel('warn'), 1)
        self.assertEqual(out.getlevel('fail'), 2)
        self.assertGreater(out.getlevel('unknown'), 2)

    def test_output_minlevel_property(self):
        out = self.Output()
        for name, expected in [
            ('info', 'info'),
            ('good', 'info'),
            ('warn', 'warn'),
            ('fail', 'fail'),
            ('invalid level', 'unknown'),
        ]:
            out.minlevel = name
            self.assertEqual(out.minlevel, expected)

    def test_output_minlevel(self):
        out = self.Output()
        # info: all visible; warn: head, warn, fail; fail: head, fail; invalid: head
        for minlevel, visible in [('info', 5), ('warn', 3), ('fail', 2), ('invalid level', 1)]:
            out.minlevel = minlevel
            self.assertEqual(len(self._emit_all(out)), visible, minlevel)

    def test_output_batch(self):
        out = self.Output()
        out.minlevel = 'info'
        out.batch = False
        self.assertEqual(len(self._emit_all(out)), 5)
        out.batch = True
        self.assertEqual(len(self._emit_all(out)), 4)


if __name__ == '__main__':
    unittest.main()
