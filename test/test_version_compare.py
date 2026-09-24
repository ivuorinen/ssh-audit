import unittest

from helpers import load_ssh_audit


class TestVersionCompare(unittest.TestCase):
    def setUp(self):
        self.ssh = load_ssh_audit().SSH

    def _software(self, banner):
        return self.ssh.Software.parse(self.ssh.Banner.parse(banner))

    def get_dropbear_software(self, v):
        return self._software(f'SSH-2.0-dropbear_{v}')

    def get_openssh_software(self, v):
        return self._software(f'SSH-2.0-OpenSSH_{v}')

    def get_libssh_software(self, v):
        return self._software(f'SSH-2.0-libssh_{v}')

    def _assert_sequential(self, factory, versions):
        """Each version equals itself, is newer than its predecessor and older than its successor."""
        for i, v in enumerate(versions):
            with self.subTest(version=v):
                s = factory(v)
                self.assertEqual(s.compare_version(v), 0)
                if i > 0:
                    self.assertGreater(s.compare_version(versions[i - 1]), 0)
                if i + 1 < len(versions):
                    self.assertLess(s.compare_version(versions[i + 1]), 0)

    def test_dropbear_compare_version_pre_years(self):
        s = self.get_dropbear_software('0.44')
        self.assertEqual(s.compare_version(None), 1)
        self.assertEqual(s.compare_version(''), 1)
        self.assertGreater(s.compare_version('0.43'), 0)
        self.assertEqual(s.compare_version('0.44'), 0)
        self.assertEqual(s.compare_version(s), 0)
        self.assertLess(s.compare_version('0.45'), 0)

    def test_dropbear_compare_version_with_years(self):
        s = self.get_dropbear_software('2015.71')
        self.assertEqual(s.compare_version(None), 1)
        self.assertEqual(s.compare_version(''), 1)
        self.assertGreater(s.compare_version('2014.66'), 0)
        self.assertEqual(s.compare_version('2015.71'), 0)
        self.assertEqual(s.compare_version(s), 0)
        self.assertLess(s.compare_version('2016.74'), 0)

    def test_dropbear_compare_version_mixed(self):
        s = self.get_dropbear_software('0.53.1')
        self.assertEqual(s.compare_version(None), 1)
        self.assertEqual(s.compare_version(''), 1)
        self.assertGreater(s.compare_version('0.53'), 0)
        self.assertEqual(s.compare_version('0.53.1'), 0)
        self.assertEqual(s.compare_version(s), 0)
        self.assertLess(s.compare_version('2011.54'), 0)

    def test_dropbear_compare_version_patchlevel(self):
        s1 = self.get_dropbear_software('0.44')
        s2 = self.get_dropbear_software('0.44test3')
        self.assertEqual(s1.compare_version(None), 1)
        self.assertEqual(s1.compare_version(''), 1)
        self.assertEqual(s1.compare_version('0.44'), 0)
        self.assertEqual(s1.compare_version(s1), 0)
        self.assertGreater(s1.compare_version('0.43'), 0)
        self.assertGreater(s1.compare_version('0.44test4'), 0)
        self.assertEqual(s2.compare_version(None), 1)
        self.assertEqual(s2.compare_version(''), 1)
        self.assertEqual(s2.compare_version('0.44test3'), 0)
        self.assertEqual(s2.compare_version(s2), 0)
        self.assertLess(s2.compare_version('0.44'), 0)
        self.assertLess(s2.compare_version('0.44test4'), 0)
        self.assertGreater(s1.compare_version(s2), 0)
        self.assertLess(s2.compare_version(s1), 0)

    def test_dropbear_compare_version_sequential(self):
        versions = [f'0.{i}' for i in range(28, 44)]
        versions += [f'0.44test{i}' for i in range(1, 5)]
        versions += [f'0.{i}' for i in range(44, 49)]
        versions += ['0.48.1']
        versions += [f'0.{i}' for i in range(49, 54)]
        versions += ['0.53.1', '2011.54', '2012.55']
        versions += [f'2013.{i}' for i in range(56, 61)]
        versions += ['2013.61test', '2013.62']
        versions += [f'2014.{i}' for i in range(63, 67)]
        versions += [f'2015.{i}' for i in range(67, 72)]
        versions += [f'2016.{i}' for i in range(72, 75)]
        self._assert_sequential(self.get_dropbear_software, versions)

    def test_openssh_compare_version_simple(self):
        s = self.get_openssh_software('3.7.1')
        self.assertEqual(s.compare_version(None), 1)
        self.assertEqual(s.compare_version(''), 1)
        self.assertGreater(s.compare_version('3.7'), 0)
        self.assertEqual(s.compare_version('3.7.1'), 0)
        self.assertEqual(s.compare_version(s), 0)
        self.assertLess(s.compare_version('3.8'), 0)

    def test_openssh_compare_version_patchlevel(self):
        s1 = self.get_openssh_software('2.1.1')
        s2 = self.get_openssh_software('2.1.1p2')
        self.assertEqual(s1.compare_version(s1), 0)
        self.assertEqual(s2.compare_version(s2), 0)
        self.assertEqual(s1.compare_version('2.1.1p1'), 0)
        self.assertEqual(s1.compare_version('2.1.1p2'), 0)
        self.assertEqual(s2.compare_version('2.1.1'), 0)
        self.assertGreater(s2.compare_version('2.1.1p1'), 0)
        self.assertLess(s2.compare_version('2.1.1p3'), 0)
        self.assertEqual(s1.compare_version(s2), 0)
        self.assertEqual(s2.compare_version(s1), 0)

    def test_openbsd_compare_version_sequential(self):
        versions = ['1.2.3', '2.1.0', '2.1.1', '2.2.0', '2.3.0']
        versions += ['2.5.0', '2.5.1', '2.5.2', '2.9', '2.9.9']
        versions += ['3.0', '3.0.1', '3.0.2', '3.1', '3.2.2', '3.2.3']
        versions += [f'3.{i}' for i in range(3, 7)]
        versions += ['3.6.1', '3.7.0', '3.7.1']
        versions += [f'3.{i}' for i in range(8, 10)]
        versions += [f'4.{i}' for i in range(10)]
        versions += [f'5.{i}' for i in range(10)]
        versions += [f'6.{i}' for i in range(10)]
        versions += [f'7.{i}' for i in range(4)]
        self._assert_sequential(self.get_openssh_software, versions)

    def test_libssh_compare_version_simple(self):
        s = self.get_libssh_software('0.3')
        self.assertEqual(s.compare_version(None), 1)
        self.assertEqual(s.compare_version(''), 1)
        self.assertGreater(s.compare_version('0.2'), 0)
        self.assertEqual(s.compare_version('0.3'), 0)
        self.assertEqual(s.compare_version(s), 0)
        self.assertLess(s.compare_version('0.3.1'), 0)

    def test_multi_digit_components_compare_numerically(self):
        # String comparison ordered '0.10.4' below '0.7.2' and '10.0' below '7.3'.
        libssh = self.get_libssh_software('0.10.4')
        self.assertGreater(libssh.compare_version('0.7.2'), 0)
        openssh = self.get_openssh_software('10.0p2')
        self.assertGreater(openssh.compare_version('9.9'), 0)
        self.assertGreater(openssh.compare_version('7.3'), 0)
        self.assertLess(self.get_openssh_software('9.9').compare_version('10.0'), 0)
        self._assert_sequential(self.get_openssh_software, ['7.9', '8.0', '9.9', '10.0', '10.2'])
        self._assert_sequential(
            self.get_libssh_software, ['0.7.9', '0.8.0', '0.9.8', '0.10.0', '0.11.1']
        )

    def test_libssh_compare_version_sequential(self):
        versions = ['0.2', '0.3']
        versions += [f'0.3.{i}' for i in range(1, 5)]
        versions += [f'0.4.{i}' for i in range(9)]
        versions += [f'0.5.{i}' for i in range(6)]
        versions += [f'0.6.{i}' for i in range(6)]
        versions += [f'0.7.{i}' for i in range(4)]
        self._assert_sequential(self.get_libssh_software, versions)


if __name__ == '__main__':
    unittest.main()
