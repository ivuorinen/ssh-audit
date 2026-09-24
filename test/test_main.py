"""The script entry point, run the way ``./ssh-audit.py`` runs it."""

import runpy
import socket
import sys
import unittest
from unittest import mock

import test_ssh2
from helpers import SCRIPT, VirtualSocketTestCase, capture
from test_ssh2 import create_ssh2_packet


class TestMain(VirtualSocketTestCase):
    def _run(self, *args):
        with mock.patch.object(sys, 'argv', ['ssh-audit.py', *args]), capture() as output:
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return output

    def test_no_arguments_prints_usage_and_exits_1(self):
        with self.assertRaises(SystemExit) as raised:
            self._run()
        self.assertEqual(raised.exception.code, 1)

    def test_audits_the_host_given_on_the_command_line(self):
        kex = test_ssh2.TestSSH2('test_kex_read')
        kex.wbuf = self.load().WriteBuf
        w = kex.wbuf()
        w.write_byte(self.load().SSH.Protocol.MSG_KEXINIT)
        w.write(kex._kex_payload())
        self.vsocket.rdata += [b'SSH-2.0-OpenSSH_7.3\r\n', create_ssh2_packet(w.write_flush())]
        looked_up = []
        real_getaddrinfo = socket.getaddrinfo

        def getaddrinfo(host, port, *args):
            looked_up.append((host, port))
            return real_getaddrinfo(host, port, *args)

        with mock.patch.object(socket, 'getaddrinfo', getaddrinfo):
            output = self._run('-n', '-b', '-p', '2222', 'example.test')
        self.assertEqual(looked_up, [('example.test', 2222)])
        self.assertIn('(gen) banner: SSH-2.0-OpenSSH_7.3', output['out'])
        self.assertEqual(output['err'], [])

    @staticmethod
    def load():
        from helpers import load_ssh_audit

        return load_ssh_audit()


if __name__ == '__main__':
    unittest.main()
