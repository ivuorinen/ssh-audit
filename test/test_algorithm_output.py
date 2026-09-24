import io
import sys
import unittest
from unittest import mock

from helpers import capture, load_ssh_audit


class TestAlgorithmOutput(unittest.TestCase):
    def setUp(self):
        self.sa = load_ssh_audit()
        self.sa.out.batch, self.sa.out.verbose, self.sa.out.colors = False, False, False
        self.sa.out.minlevel = 'info'
        self.addCleanup(setattr, self.sa.out, 'batch', False)

    def test_continuation_lines_use_box_drawing_marker(self):
        # ssh-rsa has a fail note followed by two info notes
        with capture() as output:
            self.sa.output_algorithm(self.sa.KexDB.ALGORITHMS, 'key', 'ssh-rsa', 12)
        lines = output['out']
        self.assertEqual(lines[0], '(key) ssh-rsa      -- [fail] using broken SHA-1 hash algorithm')
        self.assertEqual(
            lines[1],
            '                   └─ [info] available since OpenSSH 2.5.0, Dropbear SSH 0.28',
        )
        self.assertEqual(lines[1].index('└─'), lines[0].index('--'))

    def test_continuation_marker_falls_back_when_encoding_lacks_it(self):
        # Windows output redirected to a file uses cp1252, which cannot encode box drawing.
        stream = io.TextIOWrapper(io.BytesIO(), encoding='cp1252')
        with mock.patch.object(sys, 'stdout', stream):
            self.assertEqual(self.sa.Output.continuation_marker(), '`-')
        stream = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        with mock.patch.object(sys, 'stdout', stream):
            self.assertEqual(self.sa.Output.continuation_marker(), '└─')

    def test_buffered_output_uses_the_real_stream_encoding(self):
        # OutputBuffer swaps stdout for a StringIO, which reports no encoding at all;
        # the marker must still match the cp1252 stream the buffer is flushed to.
        real = io.TextIOWrapper(io.BytesIO(), encoding='cp1252')
        with mock.patch.object(sys, 'stdout', real):
            with self.sa.OutputBuffer() as obuf:
                self.sa.output_algorithm(self.sa.KexDB.ALGORITHMS, 'key', 'ssh-rsa', 12)
            obuf.flush()
            real.flush()
            text = real.buffer.getvalue().decode('cp1252')
        self.assertIn('`- [info] available since OpenSSH 2.5.0', text)


if __name__ == '__main__':
    unittest.main()
