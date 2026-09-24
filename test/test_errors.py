import errno
import socket
import unittest
from unittest import mock

from helpers import VirtualSocketTestCase, capture, load_ssh_audit


class TestErrors(VirtualSocketTestCase):
    def setUp(self):
        super().setUp()
        ssh_audit = load_ssh_audit()
        self.AuditConf = ssh_audit.AuditConf
        self.audit = ssh_audit.audit

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        return conf

    def _audit_fails(self, conf=None):
        """Run an audit that must exit, returning the captured output lines."""
        with self.assertRaises(SystemExit), capture() as output:
            self.audit(conf or self._conf())
        # The failure itself goes to stderr; whatever was audited stays on stdout.
        self.assertEqual(len(output['err']), 1, output)
        self.assertIn('[exception]', output['err'][0])
        return output['out'] + output['err']

    def test_failed_connect_closes_socket(self):
        # shutdown() raises on a never-connected socket; close() must still run
        self.vsocket.connect = mock.Mock(side_effect=OSError(61, 'Connection refused'))
        self._audit_fails()
        self.assertTrue(self.vsocket.closed)

    def _resolve(self, ipvo, addrinfo):
        """Addresses Socket._resolve yields for ``ipvo`` and the family it asked the resolver for."""
        calls = []

        def getaddrinfo(host, port, family, socktype):
            calls.append(family)
            return addrinfo

        with mock.patch.object(socket, 'getaddrinfo', getaddrinfo):
            result = list(load_ssh_audit().SSH.Socket('localhost', 22)._resolve(ipvo))
        return result, calls[0]

    def test_resolve_orders_by_requested_ip_version(self):
        v4 = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 22))
        v6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 22, 0, 0))
        both = [v6, v4]
        result, family = self._resolve((), both)
        self.assertEqual(family, socket.AF_UNSPEC)
        # no preference: resolver order kept
        self.assertEqual(result, [(socket.AF_INET6, v6[4]), (socket.AF_INET, v4[4])])
        result, _ = self._resolve((4, 6), both)
        self.assertEqual([af for af, _ in result], [socket.AF_INET, socket.AF_INET6])
        result, _ = self._resolve((6, 4), [v4, v6])
        self.assertEqual([af for af, _ in result], [socket.AF_INET6, socket.AF_INET])
        _, family = self._resolve((6,), [v6])
        self.assertEqual(family, socket.AF_INET6)
        _, family = self._resolve((4,), [v4])
        self.assertEqual(family, socket.AF_INET)

    def test_name_resolution_failure(self):
        error = socket.gaierror(-2, 'Name or service not known')
        with mock.patch.object(socket, 'getaddrinfo', side_effect=error):
            lines = self._audit_fails()
        self.assertEqual(lines, ['[exception] [Errno -2] Name or service not known'])

    def test_host_without_addresses(self):
        with mock.patch.object(socket, 'getaddrinfo', return_value=[]):
            lines = self._audit_fails()
        self.assertEqual(lines, ['[exception] host localhost has no DNS records'])

    def test_idna_invalid_host_name(self):
        # a label over 63 characters makes the IDNA codec raise UnicodeError, not OSError
        error = UnicodeError("encoding with 'idna' codec failed (UnicodeError: label too long)")
        with mock.patch.object(socket, 'getaddrinfo', side_effect=error):
            lines = self._audit_fails()
        self.assertEqual(lines, [f'[exception] {error}'])

    def test_banner_read_timeout(self):
        self.vsocket.rdata.append(TimeoutError('timed out'))
        lines = self._audit_fails()
        self.assertEqual(lines, ['[exception] did not receive banner (timeout).'])
        # our identification went out even though the server stayed silent
        self.assertEqual(len(self.vsocket.sdata), 1)

    def test_client_identification_is_sent_before_reading(self):
        # RFC 4253 4.2 lets a server wait for the client's identification before sending its own.
        sent_before_each_recv = []
        real_recv = self.vsocket.recv

        def recv(bufsize, flags=0):
            """Record how many sends preceded this read, then read as usual."""
            sent_before_each_recv.append(len(self.vsocket.sdata))
            return real_recv(bufsize, flags)

        self.vsocket.recv = recv
        self.vsocket.rdata.append(b'SSH-2.0-OpenSSH_9.9\r\n')
        lines = self._audit_fails()
        self.assertEqual(lines[0], '(gen) banner: SSH-2.0-OpenSSH_9.9')
        self.assertEqual(sent_before_each_recv[0], 1)

    def test_would_block_is_retried(self):
        self.vsocket.rdata += [
            OSError(errno.EAGAIN, 'Resource temporarily unavailable'),
            b'SSH-2.0-OpenSSH_9.9\r\n',
        ]
        lines = self._audit_fails()
        self.assertEqual(lines[0], '(gen) banner: SSH-2.0-OpenSSH_9.9')
        self.assertIn('error reading packet (empty)', lines[-1])

    def test_failed_client_banner_send_does_not_abort(self):
        self.vsocket.errors['send'] = OSError(32, 'Broken pipe')
        self.vsocket.rdata.append(b'SSH-2.0-OpenSSH_9.9\r\n')
        lines = self._audit_fails()
        self.assertEqual(lines[0], '(gen) banner: SSH-2.0-OpenSSH_9.9')
        self.assertIn('error reading packet (empty)', lines[-1])

    def test_reads_before_connect_report_not_connected(self):
        sock = load_ssh_audit().SSH.Socket('localhost', 22)
        self.assertEqual(sock.recv(), (-1, 'not connected'))

    def test_audit_requires_host(self):
        with self.assertRaisesRegex(ValueError, 'requires a host'):
            self.audit(self.AuditConf())

    def test_connection_refused(self):
        self.vsocket.errors['connect'] = OSError(61, 'Connection refused')
        lines = self._audit_fails()
        self.assertEqual(len(lines), 1)
        self.assertIn('Connection refused', lines[-1])

    def test_connection_closed_before_banner(self):
        self.vsocket.rdata.append(OSError(54, 'Connection reset by peer'))
        lines = self._audit_fails()
        self.assertEqual(lines, ['[exception] did not receive banner (Connection reset by peer).'])

    def test_connection_closed_after_header(self):
        self.vsocket.rdata.append(b'header line 1\n')
        self.vsocket.rdata.append(b'header line 2\n')
        lines = self._audit_fails()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[-1], '[exception] did not receive banner (connection closed).')

    def test_connection_closed_after_banner(self):
        self.vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        self.vsocket.rdata.append(OSError(54, 'Connection reset by peer'))
        lines = self._audit_fails()
        self.assertEqual(len(lines), 2)
        self.assertIn('error reading packet', lines[-1])
        self.assertIn('reset by peer', lines[-1])

    def test_empty_data_after_banner(self):
        self.vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        lines = self._audit_fails()
        self.assertEqual(len(lines), 2)
        self.assertIn('error reading packet', lines[-1])
        self.assertIn('empty', lines[-1])

    def test_wrong_data_after_banner(self):
        self.vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        self.vsocket.rdata.append(b'xxx\n')
        lines = self._audit_fails()
        self.assertEqual(len(lines), 2)
        self.assertIn('error reading packet', lines[-1])
        self.assertIn('xxx', lines[-1])

    def test_non_ascii_banner(self):
        self.vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\xc3\xbc\r\n')
        lines = self._audit_fails()
        self.assertEqual(len(lines), 3)
        self.assertIn('error reading packet', lines[-1])
        self.assertIn('ASCII', lines[-2])
        self.assertTrue(lines[-3].endswith('SSH-2.0-ssh-audit-test?'))

    def test_nonutf8_data_after_banner(self):
        self.vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        self.vsocket.rdata.append(b'\x81\xff\n')
        lines = self._audit_fails()
        self.assertEqual(len(lines), 2)
        self.assertIn('error reading packet', lines[-1])
        self.assertIn('\\x81\\xff', lines[-1])

    def test_protocol_mismatch_by_conf(self):
        self.vsocket.rdata.append(b'SSH-1.3-ssh-audit-test\r\n')
        self.vsocket.rdata.append(b'Protocol major versions differ.\n')
        conf = self._conf()
        conf.ssh1, conf.ssh2 = True, False
        lines = self._audit_fails(conf)
        self.assertEqual(len(lines), 3)
        self.assertIn('error reading packet', lines[-1])
        self.assertIn('major versions differ', lines[-1])


if __name__ == '__main__':
    unittest.main()
