"""Shared stdlib-only test support for ssh-audit.

The program lives in a hyphenated single file (``ssh-audit.py``) that the
import system cannot name, so it is loaded by path once and cached in
``sys.modules``. Network access is replaced by ``VirtualSocket`` so no test
touches DNS or a real port.
"""

import contextlib
import importlib.util
import io
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / 'ssh-audit.py'


def load_ssh_audit():
    """Return the ssh-audit module, loading it by file path on first use.

    Cached so every test shares one module object, matching how the program
    shares its module-level ``out`` and ``utils`` singletons at runtime.
    """
    module = sys.modules.get('ssh_audit')
    if module is None:
        spec = importlib.util.spec_from_file_location('ssh_audit', SCRIPT)
        if spec is None or spec.loader is None:
            raise ImportError(f'cannot load {SCRIPT}')
        module = importlib.util.module_from_spec(spec)
        sys.modules['ssh_audit'] = module
        spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def capture():
    """Capture stdout and stderr as lists of lines.

    Yields a dict whose ``out`` and ``err`` keys are filled on exit, so
    assertions after a ``SystemExit`` still see what was printed before it.
    """
    result = {'out': [], 'err': []}
    stdout, stderr = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            yield result
    finally:
        result['out'] = stdout.getvalue().splitlines()
        result['err'] = stderr.getvalue().splitlines()


class VirtualSocket:
    """In-memory stand-in for a connected TCP socket.

    ``rdata`` is consumed one item per ``recv``; an ``Exception`` item is raised
    instead of returned, which simulates resets and timeouts at an exact point
    in the exchange. ``errors`` maps a method name to an exception it raises.
    """

    def __init__(self):
        self.sock_address = ('127.0.0.1', 0)
        self.peer_address = None
        self._connected = False
        self.closed = False
        self.timeout = -1.0
        self.rdata = []
        self.sdata = []
        self.errors = {}

    def _check_err(self, method):
        method_error = self.errors.get(method)
        if method_error:
            raise method_error

    def connect(self, address):
        self.peer_address = address
        self._connected = True
        self._check_err('connect')

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def recv(self, bufsize, flags=0):
        if not self._connected:
            raise OSError(54, 'Connection reset by peer')
        if not self.rdata:
            return b''
        data = self.rdata.pop(0)
        if isinstance(data, Exception):
            raise data
        return data

    def send(self, data):
        if self.peer_address is None or not self._connected:
            raise OSError(32, 'Broken pipe')
        self._check_err('send')
        self.sdata.append(data)

    def shutdown(self, how):
        if not self._connected:
            raise OSError(57, 'Socket is not connected')

    def close(self):
        self.closed = True


class VirtualSocketTestCase(unittest.TestCase):
    """TestCase that routes all socket creation and name resolution to memory.

    ``getaddrinfo`` is patched as well as ``socket.socket``: without it the
    tests would resolve ``localhost`` through the host resolver and fail on
    machines where that lookup is slow or broken.
    """

    def setUp(self):
        super().setUp()
        self.vsocket = VirtualSocket()
        addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 22))]
        patches = [
            mock.patch.object(socket, 'socket', lambda *args, **kwargs: self.vsocket),
            mock.patch.object(socket, 'getaddrinfo', lambda *args, **kwargs: addrinfo),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
