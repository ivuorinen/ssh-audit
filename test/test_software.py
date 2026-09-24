import unittest

from helpers import load_ssh_audit


class TestSoftware(unittest.TestCase):
    def setUp(self):
        self.ssh = load_ssh_audit().SSH

    def ps(self, banner):
        return self.ssh.Software.parse(self.ssh.Banner.parse(banner))

    def _check(self, banner, vendor, product, version, patch, text, short, rep):
        """Assert every public view of the software parsed from ``banner``.

        ``short`` is ``display(False)``; the full display must equal ``str``.
        """
        s = self.ps(banner)
        self.assertEqual(s.vendor, vendor)
        self.assertEqual(s.product, product)
        self.assertEqual(s.version, version)
        self.assertEqual(s.patch, patch)
        self.assertIsNone(s.os)
        self.assertEqual(str(s), text)
        self.assertEqual(str(s), s.display())
        self.assertEqual(s.display(True), str(s))
        self.assertEqual(s.display(False), short)
        self.assertEqual(repr(s), rep)

    def _check_os(self, banner, os_name, text, rep):
        s = self.ps(banner)
        self.assertEqual(s.os, os_name)
        self.assertEqual(str(s), text)
        self.assertEqual(repr(s), rep)

    def test_unknown_software(self):
        self.assertIsNone(self.ps('SSH-1.5'))
        self.assertIsNone(self.ps('SSH-1.99-AlfaMegaServer'))
        self.assertIsNone(self.ps('SSH-2.0-BetaMegaServer 0.0.1'))

    def test_openssh_software(self):
        o = 'OpenSSH'
        # common
        self._check('SSH-2.0-OpenSSH_7.3', None, o, '7.3', None,
                    'OpenSSH 7.3', 'OpenSSH 7.3',
                    '<Software(product=OpenSSH, version=7.3)>')  # fmt: skip
        # common, portable
        self._check('SSH-2.0-OpenSSH_7.2p1', None, o, '7.2', 'p1',
                    'OpenSSH 7.2p1', 'OpenSSH 7.2',
                    '<Software(product=OpenSSH, version=7.2, patch=p1)>')  # fmt: skip
        # dot instead of underline
        self._check('SSH-2.0-OpenSSH.6.6', None, o, '6.6', None,
                    'OpenSSH 6.6', 'OpenSSH 6.6',
                    '<Software(product=OpenSSH, version=6.6)>')  # fmt: skip
        # dash instead of underline
        self._check('SSH-2.0-OpenSSH-3.9p1', None, o, '3.9', 'p1',
                    'OpenSSH 3.9p1', 'OpenSSH 3.9',
                    '<Software(product=OpenSSH, version=3.9, patch=p1)>')  # fmt: skip
        # patch prefix with dash
        self._check('SSH-2.0-OpenSSH_7.2-hpn14v5', None, o, '7.2', 'hpn14v5',
                    'OpenSSH 7.2 (hpn14v5)', 'OpenSSH 7.2',
                    '<Software(product=OpenSSH, version=7.2, patch=hpn14v5)>')  # fmt: skip
        # patch prefix with underline
        self._check('SSH-1.5-OpenSSH_6.6.1_hpn13v11', None, o, '6.6.1', 'hpn13v11',
                    'OpenSSH 6.6.1 (hpn13v11)', 'OpenSSH 6.6.1',
                    '<Software(product=OpenSSH, version=6.6.1, patch=hpn13v11)>')  # fmt: skip
        # patch prefix with dot
        self._check('SSH-2.0-OpenSSH_5.9.CASPUR', None, o, '5.9', 'CASPUR',
                    'OpenSSH 5.9 (CASPUR)', 'OpenSSH 5.9',
                    '<Software(product=OpenSSH, version=5.9, patch=CASPUR)>')  # fmt: skip

    def test_dropbear_software(self):
        d = 'Dropbear SSH'
        # common
        self._check('SSH-2.0-dropbear_2016.74', None, d, '2016.74', None,
                    'Dropbear SSH 2016.74', 'Dropbear SSH 2016.74',
                    '<Software(product=Dropbear SSH, version=2016.74)>')  # fmt: skip
        # common, patch
        self._check('SSH-2.0-dropbear_0.44test4', None, d, '0.44', 'test4',
                    'Dropbear SSH 0.44 (test4)', 'Dropbear SSH 0.44',
                    '<Software(product=Dropbear SSH, version=0.44, patch=test4)>')  # fmt: skip
        # patch prefix with dash
        self._check('SSH-2.0-dropbear_0.44-Freesco-p49', None, d, '0.44', 'Freesco-p49',
                    'Dropbear SSH 0.44 (Freesco-p49)', 'Dropbear SSH 0.44',
                    '<Software(product=Dropbear SSH, version=0.44, patch=Freesco-p49)>')  # fmt: skip
        # patch prefix with underline
        self._check('SSH-2.0-dropbear_2014.66_agbn_1', None, d, '2014.66', 'agbn_1',
                    'Dropbear SSH 2014.66 (agbn_1)', 'Dropbear SSH 2014.66',
                    '<Software(product=Dropbear SSH, version=2014.66, patch=agbn_1)>')  # fmt: skip

    def test_libssh_software(self):
        # pre-0.7 releases used a hyphen
        self._check('SSH-2.0-libssh-0.2', None, 'libssh', '0.2', None,
                    'libssh 0.2', 'libssh 0.2',
                    '<Software(product=libssh, version=0.2)>')  # fmt: skip
        self._check('SSH-2.0-libssh-0.7.3', None, 'libssh', '0.7.3', None,
                    'libssh 0.7.3', 'libssh 0.7.3',
                    '<Software(product=libssh, version=0.7.3)>')  # fmt: skip
        # what libssh actually sends: CLIENT_BANNER_SSH2 is "SSH-2.0-libssh_<version>"
        self._check('SSH-2.0-libssh_0.9.6', None, 'libssh', '0.9.6', None,
                    'libssh 0.9.6', 'libssh 0.9.6',
                    '<Software(product=libssh, version=0.9.6)>')  # fmt: skip
        self._check('SSH-2.0-libssh_0.11.1', None, 'libssh', '0.11.1', None,
                    'libssh 0.11.1', 'libssh 0.11.1',
                    '<Software(product=libssh, version=0.11.1)>')  # fmt: skip

    def test_romsshell_software(self):
        self._check('SSH-2.0-RomSShell_5.40', 'Allegro Software', 'RomSShell', '5.40', None,
                    'Allegro Software RomSShell 5.40', 'Allegro Software RomSShell 5.40',
                    '<Software(vendor=Allegro Software, product=RomSShell, version=5.40)>')  # fmt: skip

    def test_hp_ilo_software(self):
        p = 'iLO (Integrated Lights-Out) sshd'
        self._check('SSH-2.0-mpSSH_0.2.1', 'HP', p, '0.2.1', None,
                    f'HP {p} 0.2.1', f'HP {p} 0.2.1',
                    f'<Software(vendor=HP, product={p}, version=0.2.1)>')  # fmt: skip

    def test_cisco_software(self):
        self._check('SSH-1.5-Cisco-1.25', 'Cisco', 'IOS/PIX sshd', '1.25', None,
                    'Cisco IOS/PIX sshd 1.25', 'Cisco IOS/PIX sshd 1.25',
                    '<Software(vendor=Cisco, product=IOS/PIX sshd, version=1.25)>')  # fmt: skip

    def test_software_os(self):
        # unknown
        self.assertIsNone(self.ps('SSH-2.0-OpenSSH_3.7.1 MegaOperatingSystem 123').os)
        cases = [
            # NetBSD
            ('SSH-1.99-OpenSSH_2.5.1 NetBSD_Secure_Shell-20010614', 'NetBSD (2001-06-14)',
             'OpenSSH 2.5.1 running on NetBSD (2001-06-14)',
             '<Software(product=OpenSSH, version=2.5.1, os=NetBSD (2001-06-14))>'),
            ('SSH-1.99-OpenSSH_5.0 NetBSD_Secure_Shell-20080403+-hpn13v1', 'NetBSD (2008-04-03)',
             'OpenSSH 5.0 running on NetBSD (2008-04-03)',
             '<Software(product=OpenSSH, version=5.0, os=NetBSD (2008-04-03))>'),
            ('SSH-2.0-OpenSSH_6.6.1_hpn13v11 NetBSD-20100308', 'NetBSD (2010-03-08)',
             'OpenSSH 6.6.1 (hpn13v11) running on NetBSD (2010-03-08)',
             '<Software(product=OpenSSH, version=6.6.1, patch=hpn13v11, os=NetBSD (2010-03-08))>'),
            ('SSH-2.0-OpenSSH_4.4 NetBSD', 'NetBSD',
             'OpenSSH 4.4 running on NetBSD',
             '<Software(product=OpenSSH, version=4.4, os=NetBSD)>'),
            ('SSH-2.0-OpenSSH_3.0.2 NetBSD Secure Shell', 'NetBSD',
             'OpenSSH 3.0.2 running on NetBSD',
             '<Software(product=OpenSSH, version=3.0.2, os=NetBSD)>'),
            # FreeBSD
            ('SSH-2.0-OpenSSH_7.2 FreeBSD-20160310', 'FreeBSD (2016-03-10)',
             'OpenSSH 7.2 running on FreeBSD (2016-03-10)',
             '<Software(product=OpenSSH, version=7.2, os=FreeBSD (2016-03-10))>'),
            ('SSH-1.99-OpenSSH_2.9 FreeBSD localisations 20020307', 'FreeBSD (2002-03-07)',
             'OpenSSH 2.9 running on FreeBSD (2002-03-07)',
             '<Software(product=OpenSSH, version=2.9, os=FreeBSD (2002-03-07))>'),
            ('SSH-2.0-OpenSSH_2.3.0 green@FreeBSD.org 20010321', 'FreeBSD (2001-03-21)',
             'OpenSSH 2.3.0 running on FreeBSD (2001-03-21)',
             '<Software(product=OpenSSH, version=2.3.0, os=FreeBSD (2001-03-21))>'),
            ('SSH-1.99-OpenSSH_4.4p1 FreeBSD-openssh-portable-overwrite-base-4.4.p1_1,1', 'FreeBSD',
             'OpenSSH 4.4p1 running on FreeBSD',
             '<Software(product=OpenSSH, version=4.4, patch=p1, os=FreeBSD)>'),
            ('SSH-2.0-OpenSSH_7.2-OVH-rescue FreeBSD', 'FreeBSD',
             'OpenSSH 7.2 (OVH-rescue) running on FreeBSD',
             '<Software(product=OpenSSH, version=7.2, patch=OVH-rescue, os=FreeBSD)>'),
            # Windows
            ('SSH-2.0-OpenSSH_3.7.1 in RemotelyAnywhere 5.21.422',
             'Microsoft Windows (RemotelyAnywhere 5.21.422)',
             'OpenSSH 3.7.1 running on Microsoft Windows (RemotelyAnywhere 5.21.422)',
             '<Software(product=OpenSSH, version=3.7.1, os=Microsoft Windows (RemotelyAnywhere 5.21.422))>'),
            ('SSH-2.0-OpenSSH_3.8 in DesktopAuthority 7.1.091',
             'Microsoft Windows (DesktopAuthority 7.1.091)',
             'OpenSSH 3.8 running on Microsoft Windows (DesktopAuthority 7.1.091)',
             '<Software(product=OpenSSH, version=3.8, os=Microsoft Windows (DesktopAuthority 7.1.091))>'),
            ('SSH-2.0-OpenSSH_3.8 in RemoteSupportManager 1.0.023',
             'Microsoft Windows (RemoteSupportManager 1.0.023)',
             'OpenSSH 3.8 running on Microsoft Windows (RemoteSupportManager 1.0.023)',
             '<Software(product=OpenSSH, version=3.8, os=Microsoft Windows (RemoteSupportManager 1.0.023))>'),
        ]  # fmt: skip
        for banner, os_name, text, rep in cases:
            with self.subTest(banner=banner):
                self._check_os(banner, os_name, text, rep)


if __name__ == '__main__':
    unittest.main()
