import unittest

from helpers import load_ssh_audit


class TestBanner(unittest.TestCase):
    def setUp(self):
        self.parse = load_ssh_audit().SSH.Banner.parse

    def test_simple_banners(self):
        b = self.parse('SSH-2.0-OpenSSH_7.3')
        self.assertEqual(b.protocol, (2, 0))
        self.assertEqual(b.software, 'OpenSSH_7.3')
        self.assertIsNone(b.comments)
        self.assertEqual(str(b), 'SSH-2.0-OpenSSH_7.3')
        b = self.parse('SSH-1.99-Sun_SSH_1.1.3')
        self.assertEqual(b.protocol, (1, 99))
        self.assertEqual(b.software, 'Sun_SSH_1.1.3')
        self.assertIsNone(b.comments)
        self.assertEqual(str(b), 'SSH-1.99-Sun_SSH_1.1.3')
        b = self.parse('SSH-1.5-Cisco-1.25')
        self.assertEqual(b.protocol, (1, 5))
        self.assertEqual(b.software, 'Cisco-1.25')
        self.assertIsNone(b.comments)
        self.assertEqual(str(b), 'SSH-1.5-Cisco-1.25')

    def test_repr_without_software_or_comments(self):
        self.assertEqual(repr(self.parse('SSH-2.0')), '<Banner(protocol=2.0)>')

    def test_invalid_banners(self):
        self.assertIsNone(self.parse('Something'))
        self.assertIsNone(self.parse('SSH-XXX-OpenSSH_7.3'))

    def test_banners_with_spaces(self):
        b = self.parse
        s = 'SSH-2.0-OpenSSH_4.3p2'
        self.assertEqual(str(b('SSH-2.0-OpenSSH_4.3p2    ')), s)
        self.assertEqual(str(b('SSH-2.0-    OpenSSH_4.3p2')), s)
        self.assertEqual(str(b('SSH-2.0-  OpenSSH_4.3p2  ')), s)
        s = 'SSH-2.0-OpenSSH_4.3p2 Debian-9etch3 on i686-pc-linux-gnu'
        self.assertEqual(str(b('SSH-2.0-  OpenSSH_4.3p2 Debian-9etch3   on i686-pc-linux-gnu')), s)
        self.assertEqual(str(b('SSH-2.0-OpenSSH_4.3p2 Debian-9etch3 on i686-pc-linux-gnu  ')), s)
        self.assertEqual(
            str(b('SSH-2.0-  OpenSSH_4.3p2 Debian-9etch3   on   i686-pc-linux-gnu  ')), s
        )

    def test_banners_without_software(self):
        b = self.parse
        self.assertEqual(b('SSH-2.0').protocol, (2, 0))
        self.assertIsNone(b('SSH-2.0').software)
        self.assertIsNone(b('SSH-2.0').comments)
        self.assertEqual(str(b('SSH-2.0')), 'SSH-2.0')
        self.assertEqual(b('SSH-2.0-').protocol, (2, 0))
        self.assertEqual(b('SSH-2.0-').software, '')
        self.assertIsNone(b('SSH-2.0-').comments)
        self.assertEqual(str(b('SSH-2.0-')), 'SSH-2.0-')

    def test_banners_with_comments(self):
        b = self.parse
        self.assertEqual(
            repr(b('SSH-2.0-OpenSSH_7.2p2 Ubuntu-1')),
            '<Banner(protocol=2.0, software=OpenSSH_7.2p2, comments=Ubuntu-1)>',
        )
        self.assertEqual(
            repr(b('SSH-1.99-OpenSSH_3.4p1 Debian 1:3.4p1-1.woody.3')),
            '<Banner(protocol=1.99, software=OpenSSH_3.4p1, comments=Debian 1:3.4p1-1.woody.3)>',
        )
        self.assertEqual(
            repr(b('SSH-1.5-1.3.7 F-SECURE SSH')),
            '<Banner(protocol=1.5, software=1.3.7, comments=F-SECURE SSH)>',
        )

    def test_banners_with_multiple_protocols(self):
        b = self.parse
        self.assertEqual(str(b('SSH-1.99-SSH-1.99-OpenSSH_3.6.1p2')), 'SSH-1.99-OpenSSH_3.6.1p2')
        self.assertEqual(
            str(b('SSH-2.0-SSH-2.0-OpenSSH_4.3p2 Debian-9')), 'SSH-2.0-OpenSSH_4.3p2 Debian-9'
        )
        self.assertEqual(str(b('SSH-1.99-SSH-2.0-dropbear_0.5')), 'SSH-1.99-dropbear_0.5')
        self.assertEqual(
            str(b('SSH-2.0-SSH-1.99-OpenSSH_4.2p1 SSH Secure Shell (non-commercial)')),
            'SSH-1.99-OpenSSH_4.2p1 SSH Secure Shell (non-commercial)',
        )
        self.assertEqual(
            str(b('SSH-1.99-SSH-1.99-SSH-1.99-OpenSSH_3.9p1')), 'SSH-1.99-OpenSSH_3.9p1'
        )


if __name__ == '__main__':
    unittest.main()
