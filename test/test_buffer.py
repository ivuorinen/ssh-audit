import re
import unittest

from helpers import load_ssh_audit, write_bool, write_list, write_mpint1, write_string

UTF8_REPLACEMENT = b'\xef\xbf\xbd'


def _b(v):
    """Decode a whitespace-separated hex string into bytes."""
    return bytes.fromhex(re.sub(r'\s', '', v))


class TestBuffer(unittest.TestCase):
    def setUp(self):
        ssh_audit = load_ssh_audit()
        self.rbuf = ssh_audit.ReadBuf
        self.wbuf = ssh_audit.WriteBuf

    def _roundtrip(self, write, read, cases):
        for value, hexdata in cases:
            with self.subTest(value=value):
                self.assertEqual(write(value), _b(hexdata))
                self.assertEqual(read(_b(hexdata)), value)

    def test_unread(self):
        w = self.wbuf().write_byte(1).write_int(2).write_flush()
        r = self.rbuf(w)
        self.assertEqual(r.unread_len, 5)
        r.read_byte()
        self.assertEqual(r.unread_len, 4)
        r.read_int()
        self.assertEqual(r.unread_len, 0)

    def test_byte(self):
        self._roundtrip(
            lambda x: self.wbuf().write_byte(x).write_flush(),
            lambda x: self.rbuf(x).read_byte(),
            [(0x00, '00'), (0x01, '01'), (0x10, '10'), (0xFF, 'ff')],
        )

    def _written(self, write, value):
        """Bytes ``write`` appends to a fresh WriteBuf for ``value``."""
        w = self.wbuf()
        write(w, value)
        return w.write_flush()

    def test_bool(self):
        self._roundtrip(
            lambda x: self._written(write_bool, x),
            lambda x: self.rbuf(x).read_bool(),
            [(True, '01'), (False, '00')],
        )

    def test_int(self):
        self._roundtrip(
            lambda x: self.wbuf().write_int(x).write_flush(),
            lambda x: self.rbuf(x).read_int(),
            [
                (0x00, '00 00 00 00'),
                (0x01, '00 00 00 01'),
                (0xABCD, '00 00 ab cd'),
                (0xFFFFFFFF, 'ff ff ff ff'),
            ],
        )

    def test_string(self):
        w = lambda x: self._written(write_string, x)  # noqa: E731
        for value, hexdata in [
            ('abc1', '00 00 00 04 61 62 63 31'),
            (b'abc2', '00 00 00 04 61 62 63 32'),
        ]:
            self.assertEqual(w(value), _b(hexdata))

    def test_list(self):
        self._roundtrip(
            lambda x: self._written(write_list, x),
            lambda x: self.rbuf(x).read_list(),
            [(['d', 'ef', 'ault'], '00 00 00 09 64 2c 65 66 2c 61 75 6c 74')],
        )

    def test_list_nonutf8(self):
        src = _b('00 00 00 04 de ad be ef')
        dst = [(b'\xde\xad' + UTF8_REPLACEMENT + UTF8_REPLACEMENT).decode('utf-8')]
        self.assertEqual(self.rbuf(src).read_list(), dst)

    def test_line(self):
        src = _b('65 78 61 6d 70 6c 65 20 6c 69 6e 65 0d 0a')
        self.assertEqual(self.rbuf(src).read_line(), 'example line')

    def test_line_nonutf8(self):
        src = _b('de ad be af')
        dst = (b'\xde\xad' + UTF8_REPLACEMENT + UTF8_REPLACEMENT).decode('utf-8')
        self.assertEqual(self.rbuf(src).read_line(), dst)

    def test_mpint1(self):
        self._roundtrip(
            lambda x: self._written(write_mpint1, x),
            lambda x: self.rbuf(x).read_mpint1(),
            [
                (0x0, '00 00'),
                (0x1234, '00 0d 12 34'),
                (0x12345, '00 11 01 23 45'),
                (0xDEADBEEF, '00 20 de ad be ef'),
                # SSH1 mpints are unsigned: a set top bit needs no leading zero byte
                (0x80, '00 08 80'),
                (0x9A378F9B2E332A7FF, '00 44 09 a3 78 f9 b2 e3 32 a7 ff'),
            ],
        )


if __name__ == '__main__':
    unittest.main()
