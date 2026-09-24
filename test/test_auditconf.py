import unittest

from helpers import capture, load_ssh_audit


class TestAuditConf(unittest.TestCase):
    def setUp(self):
        ssh_audit = load_ssh_audit()
        self.AuditConf = ssh_audit.AuditConf
        self.usage = ssh_audit.usage

    def _test_conf(self, conf, **kwargs):
        options = {
            'host': None,
            'port': 22,
            'ssh1': True,
            'ssh2': True,
            'batch': False,
            'colors': True,
            'verbose': False,
            'minlevel': 'info',
            'ipv4': True,
            'ipv6': True,
            'ipvo': (),
        }
        options.update(kwargs)
        self.assertEqual(conf.host, options['host'])
        self.assertEqual(conf.port, options['port'])
        self.assertIs(conf.ssh1, options['ssh1'])
        self.assertIs(conf.ssh2, options['ssh2'])
        self.assertIs(conf.batch, options['batch'])
        self.assertIs(conf.colors, options['colors'])
        self.assertIs(conf.verbose, options['verbose'])
        self.assertEqual(conf.minlevel, options['minlevel'])
        self.assertEqual(conf.ipv4, options['ipv4'])
        self.assertEqual(conf.ipv6, options['ipv6'])
        self.assertEqual(conf.ipvo, options['ipvo'])

    def _cmdline(self, args):
        with capture():
            return self.AuditConf.from_cmdline(args.split(), self.usage)

    def _assert_exits(self, args):
        with self.assertRaises(SystemExit, msg=args), capture():
            self.AuditConf.from_cmdline(args.split(), self.usage)

    def test_audit_conf_defaults(self):
        self._test_conf(self.AuditConf())

    def test_audit_conf_booleans(self):
        conf = self.AuditConf()
        for p in ['ssh1', 'ssh2', 'batch', 'colors', 'verbose']:
            for v in [True, 1]:
                setattr(conf, p, v)
                self.assertIs(getattr(conf, p), True)
            for v in [False, 0]:
                setattr(conf, p, v)
                self.assertIs(getattr(conf, p), False)

    def test_audit_conf_port(self):
        conf = self.AuditConf()
        for port in [22, 2222]:
            conf.port = port
            self.assertEqual(conf.port, port)
        for port in [-1, 0, 65536, 99999]:
            with self.assertRaisesRegex(ValueError, r'.*invalid port.*'):
                conf.port = port

    def test_audit_conf_ipvo(self):
        # ipv4-only
        conf = self.AuditConf()
        conf.ipv4 = True
        self.assertIs(conf.ipv4, True)
        self.assertIs(conf.ipv6, False)
        self.assertEqual(conf.ipvo, (4,))
        # ipv6-only
        conf = self.AuditConf()
        conf.ipv6 = True
        self.assertIs(conf.ipv4, False)
        self.assertIs(conf.ipv6, True)
        self.assertEqual(conf.ipvo, (6,))
        # ipv4-only (by removing ipv6)
        conf = self.AuditConf()
        conf.ipv6 = False
        self.assertIs(conf.ipv4, True)
        self.assertIs(conf.ipv6, False)
        self.assertEqual(conf.ipvo, (4,))
        # ipv6-only (by removing ipv4)
        conf = self.AuditConf()
        conf.ipv4 = False
        self.assertIs(conf.ipv4, False)
        self.assertIs(conf.ipv6, True)
        self.assertEqual(conf.ipvo, (6,))
        # ipv4-preferred
        conf = self.AuditConf()
        conf.ipv4 = True
        conf.ipv6 = True
        self.assertIs(conf.ipv4, True)
        self.assertIs(conf.ipv6, True)
        self.assertEqual(conf.ipvo, (4, 6))
        # ipv6-preferred
        conf = self.AuditConf()
        conf.ipv6 = True
        conf.ipv4 = True
        self.assertIs(conf.ipv4, True)
        self.assertIs(conf.ipv6, True)
        self.assertEqual(conf.ipvo, (6, 4))
        # ipvo empty
        conf = self.AuditConf()
        conf.ipvo = ()
        self.assertIs(conf.ipv4, True)
        self.assertIs(conf.ipv6, True)
        self.assertEqual(conf.ipvo, ())
        # ipvo validation
        conf = self.AuditConf()
        conf.ipvo = (1, 2, 3, 4, 5, 6)
        self.assertEqual(conf.ipvo, (4, 6))
        conf.ipvo = (4, 4, 4, 6, 6)
        self.assertEqual(conf.ipvo, (4, 6))

    def test_audit_conf_rejects_unknown_attributes(self):
        conf = self.AuditConf()
        with self.assertRaisesRegex(AttributeError, 'colours'):
            conf.colours = False
        with self.assertRaisesRegex(ValueError, 'ipvo'):
            conf.ipvo = 4

    def test_audit_conf_minlevel(self):
        conf = self.AuditConf()
        for level in ['info', 'warn', 'fail']:
            conf.minlevel = level
            self.assertEqual(conf.minlevel, level)
        for level in ['head', 'good', 'unknown', None]:
            with self.assertRaisesRegex(ValueError, r'.*invalid level.*'):
                conf.minlevel = level

    def test_audit_conf_cmdline(self):
        for args in ['', '-x', '-h', '--help', ':', ':22']:
            self._assert_exits(args)
        self._test_conf(self._cmdline('localhost'), host='localhost')
        self._test_conf(self._cmdline('github.com'), host='github.com')
        self._test_conf(self._cmdline('localhost:2222'), host='localhost', port=2222)
        self._test_conf(self._cmdline('-p 2222 localhost'), host='localhost', port=2222)
        self._test_conf(self._cmdline('--port=2222 localhost'), host='localhost', port=2222)
        self._test_conf(self._cmdline('--port 2222 localhost'), host='localhost', port=2222)
        self._assert_exits('--port=abc localhost')
        for args in [
            'localhost:',
            'localhost:abc',
            '-p abc localhost',
            'localhost:-22',
            '-p -22 localhost',
            'localhost:99999',
            '-p 99999 localhost',
        ]:
            self._assert_exits(args)
        self._test_conf(self._cmdline('-1 localhost'), host='localhost', ssh1=True, ssh2=False)
        self._test_conf(self._cmdline('-2 localhost'), host='localhost', ssh1=False, ssh2=True)
        self._test_conf(self._cmdline('-12 localhost'), host='localhost', ssh1=True, ssh2=True)
        self._test_conf(
            self._cmdline('-4 localhost'), host='localhost', ipv4=True, ipv6=False, ipvo=(4,)
        )
        self._test_conf(
            self._cmdline('-6 localhost'), host='localhost', ipv4=False, ipv6=True, ipvo=(6,)
        )
        self._test_conf(
            self._cmdline('-46 localhost'), host='localhost', ipv4=True, ipv6=True, ipvo=(4, 6)
        )
        self._test_conf(
            self._cmdline('-64 localhost'), host='localhost', ipv4=True, ipv6=True, ipvo=(6, 4)
        )
        self._test_conf(self._cmdline('-b localhost'), host='localhost', batch=True, verbose=True)
        self._test_conf(self._cmdline('-n localhost'), host='localhost', colors=False)
        self._test_conf(self._cmdline('-v localhost'), host='localhost', verbose=True)
        for level in ['info', 'warn', 'fail']:
            self._test_conf(
                self._cmdline(f'-l {level} localhost'), host='localhost', minlevel=level
            )
        self._assert_exits('-l something localhost')


if __name__ == '__main__':
    unittest.main()
