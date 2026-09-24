"""The script entry point, run the way ``./ssh-audit.py`` runs it."""

import io
import runpy
import socket
import sys
import unittest
from unittest import mock

from helpers import SCRIPT, VirtualSocketTestCase, capture
from test_ssh2 import create_ssh2_packet, kex_payload


class TestMain(VirtualSocketTestCase):
    def _run(self, *args):
        with mock.patch.object(sys, 'argv', ['ssh-audit.py', *args]), capture() as output:
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return output

    def test_no_arguments_prints_usage_and_exits_1(self):
        with self.assertRaises(SystemExit) as raised:
            self._run()
        self.assertEqual(raised.exception.code, 1)

    def test_help_exits_0(self):
        with self.assertRaises(SystemExit) as raised:
            self._run('--help')
        self.assertEqual(raised.exception.code, 0)

    def test_audits_the_host_given_on_the_command_line(self):
        kexinit = bytes([self.load().SSH.Protocol.MSG_KEXINIT]) + kex_payload()
        self.vsocket.rdata += [b'SSH-2.0-OpenSSH_7.3\r\n', create_ssh2_packet(kexinit)]
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

    def test_reader_closing_the_pipe_exits_quietly(self):
        # `ssh-audit.py host | head -1`: the report is done, and a traceback
        # over the user's output is not an audit failure.
        class ClosedPipe(io.StringIO):
            """stdout whose writes fail the way a pipe with no reader does.

            close() swallows the failure: the real stdout stays referenced by
            ``sys.__stdout__`` and is never finalized mid-run, but this fake is
            collected as soon as the patch is undone, and its finalizer would
            report the very error the test asserts is absent.
            """

            def write(self, s):
                raise BrokenPipeError(32, 'Broken pipe')

            def close(self):
                pass

        kexinit = bytes([self.load().SSH.Protocol.MSG_KEXINIT]) + kex_payload()
        self.vsocket.rdata += [b'SSH-2.0-OpenSSH_7.3\r\n', create_ssh2_packet(kexinit)]
        with self.assertRaises(SystemExit) as raised, capture() as output:
            with mock.patch.object(sys, 'stdout', ClosedPipe()):
                with mock.patch.object(sys, 'argv', ['ssh-audit.py', '-n', 'example.test']):
                    runpy.run_path(str(SCRIPT), run_name='__main__')
        self.assertEqual(raised.exception.code, 141)
        self.assertEqual(output['err'], [])

    @staticmethod
    def load():
        from helpers import load_ssh_audit

        return load_ssh_audit()


if __name__ == '__main__':
    unittest.main()
