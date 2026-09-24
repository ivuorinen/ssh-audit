"""The audited server is untrusted input: malformed or hostile data must end in
a reported error, never a traceback, an unbounded read, or terminal control."""

import struct
import unittest
from unittest import mock

from helpers import VirtualSocketTestCase, capture, load_ssh_audit
from test_ssh2 import create_ssh2_packet, kex_payload

BANNER = b'SSH-2.0-OpenSSH_7.3 ssh-audit-test\r\n'


class TestHostileServer(VirtualSocketTestCase):
    def setUp(self):
        super().setUp()
        self.sa = load_ssh_audit()

    def _conf(self, colors=False):
        conf = self.sa.AuditConf('localhost', 22)
        conf.colors = colors
        conf.batch = True
        conf.verbose = True
        conf.ssh1, conf.ssh2 = False, True
        return conf

    def _audit_fails(self):
        with self.assertRaises(SystemExit) as raised, capture() as output:
            self.sa.audit(self._conf())
        self.assertEqual(raised.exception.code, 1)
        return output['out'] + output['err']

    def test_empty_payload_packet_is_reported(self):
        # length 4 with 3 bytes of padding leaves a zero-byte payload (no message type)
        self.vsocket.rdata += [BANNER, struct.pack('>IB', 4, 3) + b'\x00' * 3]
        lines = self._audit_fails()
        self.assertIn('invalid ssh packet', lines[-1])

    def test_padding_shorter_than_rfc_minimum_is_reported(self):
        packet = struct.pack('>IB', 12, 2) + b'\x14' + b'\x00' * 9 + b'\x00' * 2
        self.vsocket.rdata += [BANNER, packet]
        lines = self._audit_fails()
        self.assertIn('invalid ssh packet', lines[-1])

    def test_oversized_packet_length_reads_are_bounded(self):
        received = []

        def endless(size, flags=0):
            chunk = b'\x00' * size
            received.append(len(chunk))
            if sum(received) > 4 * 1024 * 1024:
                self.fail('read more than 4 MiB for one invalid packet')
            return chunk

        self.vsocket.rdata.append(BANNER)
        # 4 + length is a multiple of 8, so only a length check can stop the read
        self.vsocket.rdata.append(struct.pack('>IB', 0x7FFFFFF4, 4))
        with mock.patch.object(
            self.vsocket,
            'recv',
            side_effect=lambda *a: self.vsocket.rdata.pop(0) if self.vsocket.rdata else endless(*a),
        ):
            lines = self._audit_fails()
        self.assertIn('error reading packet', lines[-1])

    def test_packet_not_aligned_to_block_size_is_reported(self):
        # 4 + 5 = 9 bytes is not a multiple of the 8-byte block size
        self.vsocket.rdata += [BANNER, struct.pack('>IB', 5, 4) + b'\x14' * 4]
        lines = self._audit_fails()
        self.assertEqual(lines[-1], '[exception] invalid ssh packet (block size)')

    def test_blank_lines_and_partial_banner_after_a_header_line(self):
        w = self.sa.WriteBuf()
        w.write_byte(self.sa.SSH.Protocol.MSG_KEXINIT)
        w.write(kex_payload())
        self.vsocket.rdata += [
            b'\r\n\r\nwelcome\nSSH-2.0-Open',
            b'SSH_7.3 ssh-audit-test\r\n',
            create_ssh2_packet(w.write_flush()),
        ]
        with capture() as output:
            self.sa.audit(self._conf())
        self.assertEqual(
            output['out'][:2],
            ['(gen) header: welcome', '(gen) banner: SSH-2.0-OpenSSH_7.3 ssh-audit-test'],
        )

    def test_every_header_line_is_prefixed(self):
        # Joined with newlines, every line after the first printed as bare server
        # text, so a server could forge lines that read like audit results.
        w = self.sa.WriteBuf()
        w.write_byte(self.sa.SSH.Protocol.MSG_KEXINIT)
        w.write(kex_payload())
        self.vsocket.rdata += [
            b'welcome\r\n(kex) mlkem768x25519-sha256 -- [info] available since OpenSSH 9.9\r\n',
            BANNER,
            create_ssh2_packet(w.write_flush()),
        ]
        with capture() as output:
            self.sa.audit(self._conf())
        self.assertEqual(
            output['out'][:2],
            [
                '(gen) header: welcome',
                '(gen) header: (kex) mlkem768x25519-sha256 -- [info] available since OpenSSH 9.9',
            ],
        )
        self.assertFalse([line for line in output['out'] if line.startswith('(kex) mlkem')])

    def test_truncated_kexinit_is_reported(self):
        self.vsocket.rdata += [BANNER, create_ssh2_packet(b'\x14' + b'\x00' * 3)]
        lines = self._audit_fails()
        self.assertIn('malformed', lines[-1])

    def test_banner_split_across_segments(self):
        w = self.sa.WriteBuf()
        w.write_byte(self.sa.SSH.Protocol.MSG_KEXINIT)
        w.write(kex_payload())
        self.vsocket.rdata += [
            b'SSH-2.0-Open',
            b'SSH_7.3 ssh-audit-test\r\n',
            create_ssh2_packet(w.write_flush()),
        ]
        with capture() as output:
            self.sa.audit(self._conf())
        self.assertIn('(gen) banner: SSH-2.0-OpenSSH_7.3 ssh-audit-test', output['out'])

    def test_endless_pre_banner_lines_stop(self):
        self.vsocket.rdata += [b'x' * 100 + b'\r\n'] * 5000
        lines = self._audit_fails()
        self.assertIn('did not receive banner (too many pre-banner lines)', lines[-1])
        self.assertGreater(len(self.vsocket.rdata), 0, 'all 5000 header lines were consumed')

    def test_slow_pre_banner_lines_hit_deadline(self):
        self.vsocket.rdata += [b'tarpit\r\n'] * 100
        clock = iter(range(0, 100000, 10))
        with mock.patch.object(self.sa.time, 'monotonic', side_effect=lambda: next(clock)):
            lines = self._audit_fails()
        self.assertIn('did not receive banner (timeout)', lines[-1])
        self.assertGreater(len(self.vsocket.rdata), 80)

    def test_slow_partial_line_hits_deadline(self):
        # bytes keep arriving but never complete a line: the read loop itself must stop
        self.vsocket.rdata += [b'x'] * 100
        clock = iter(range(0, 100000, 10))
        with mock.patch.object(self.sa.time, 'monotonic', side_effect=lambda: next(clock)):
            lines = self._audit_fails()
        self.assertIn('did not receive banner (timeout)', lines[-1])

    def test_trickled_packet_hits_deadline(self):
        # one byte per recv, each inside the socket timeout: only the packet deadline ends it
        self.vsocket.rdata += [BANNER, *(bytes([b]) for b in struct.pack('>IB', 1020, 4))]
        self.vsocket.rdata += [b'\x14'] * 1000
        clock = iter(range(0, 100000, 4))
        with mock.patch.object(self.sa.time, 'monotonic', side_effect=lambda: next(clock)):
            lines = self._audit_fails()
        self.assertEqual(lines[-1], '[exception] error reading packet (timeout)')
        self.assertGreater(len(self.vsocket.rdata), 900)

    def test_trickled_oversized_packet_drain_hits_deadline(self):
        self.vsocket.rdata += [BANNER, struct.pack('>IB', 0x7FFFFFF4, 4)] + [b'\x00'] * 1000
        clock = iter(range(0, 100000, 4))
        with mock.patch.object(self.sa.time, 'monotonic', side_effect=lambda: next(clock)):
            lines = self._audit_fails()
        self.assertIn('error reading packet', lines[-1])
        self.assertGreater(len(self.vsocket.rdata), 900)

    def test_server_control_characters_are_escaped(self):
        self.vsocket.rdata += [
            b'\x1b[2J\x1b]0;pwned\x07header\rspoof\r\n',
            b'SSH-2.0-OpenSSH_7.3\x1b[1A\r\n',
            OSError(54, 'Connection reset by peer'),
        ]
        with self.assertRaises(SystemExit), capture() as output:
            self.sa.audit(self._conf())
        text = '\n'.join(output['out'] + output['err'])
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\x07', text)
        self.assertNotIn('\r', text)
        self.assertIn('\\x1b[2J\\x1b]0;pwned\\x07header\\x0dspoof', text)

    def test_colors_still_applied_around_escaped_text(self):
        self.vsocket.rdata += [b'SSH-2.0-OpenSSH_7.3\x1b[1A\r\n', OSError(54, 'reset')]
        conf = self._conf(colors=True)
        with (
            mock.patch.object(self.sa.Output, 'colors_supported', True),
            self.assertRaises(SystemExit),
            capture() as output,
        ):
            self.sa.audit(conf)
        banner_line = next(line for line in output['out'] if 'banner' in line)
        self.assertTrue(banner_line.startswith('\x1b[0;32m'))
        self.assertIn('\\x1b[1A', banner_line)


if __name__ == '__main__':
    unittest.main()
