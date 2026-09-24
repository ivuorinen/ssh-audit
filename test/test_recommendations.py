import unittest

from helpers import load_ssh_audit


class TestRecommendations(unittest.TestCase):
    def setUp(self):
        self.sa = load_ssh_audit()

    def _kex(self, kex=(), key=(), enc=(), mac=()):
        party = self.sa.SSH2.KexParty(list(enc), list(mac), ['none'], [])
        return self.sa.SSH2.Kex(b'\x00' * 16, list(kex), list(key), party, party, False)

    def _recs(self, banner, **algs):
        software = self.sa.SSH.Software.parse(self.sa.SSH.Banner.parse(banner))
        return self.sa.get_alg_recommendations(software, self._kex(**algs), None)[1].get(2, {})

    def test_modern_openssh_gets_pq_kex_appended_and_classical_removed(self):
        rec = self._recs('SSH-2.0-OpenSSH_10.0', kex=['curve25519-sha256', 'ecdh-sha2-nistp256'])
        self.assertIn('mlkem768x25519-sha256', rec['kex']['add'])
        self.assertIn('sntrup761x25519-sha512', rec['kex']['add'])
        self.assertIn('ecdh-sha2-nistp256', rec['kex']['del'])
        self.assertIn('curve25519-sha256', rec['kex']['del'])

    def test_pseudo_certificate_and_security_key_algorithms_never_appended(self):
        rec = self._recs('SSH-2.0-OpenSSH_10.0', kex=['mlkem768x25519-sha256'], key=['ssh-ed25519'])
        added = set(rec.get('kex', {}).get('add', {})) | set(rec.get('key', {}).get('add', {}))
        self.assertFalse(
            {n for n in added if n.startswith(('ext-info-', 'kex-strict-', 'sk-'))}, added
        )
        self.assertFalse({n for n in added if '-cert-' in n}, added)

    def test_algorithm_newer_than_server_is_not_appended(self):
        rec = self._recs('SSH-2.0-OpenSSH_8.0', kex=['curve25519-sha256'])
        self.assertNotIn('mlkem768x25519-sha256', rec.get('kex', {}).get('add', {}))

    def test_unknown_software_gets_no_appends_but_still_removals(self):
        rec = self._recs(
            'SSH-2.0-SomeVendorSSH_1.0', kex=['diffie-hellman-group1-sha1', 'curve25519-sha256']
        )
        self.assertNotIn('add', rec['kex'])
        self.assertIn('diffie-hellman-group1-sha1', rec['kex']['del'])

    def test_unversioned_algorithm_with_faults_is_removed_not_appended(self):
        # 'diffie-hellman-group1-sha256' has no version data but a 1024-bit fault
        rec = self._recs(
            'SSH-2.0-OpenSSH_10.0', kex=['diffie-hellman-group1-sha256', 'mlkem768x25519-sha256']
        )
        self.assertIn('diffie-hellman-group1-sha256', rec['kex']['del'])
        # 'ssh-rsa-sha2-256' is fault-free but has no version data, so it is never suggested
        self.assertEqual(self.sa.KexDB.ALGORITHMS['key']['ssh-rsa-sha2-256'], [[]])
        rec = self._recs('SSH-2.0-OpenSSH_10.0', key=['ssh-ed25519'])
        self.assertNotIn('ssh-rsa-sha2-256', rec.get('key', {}).get('add', {}))

    def test_every_database_note_sits_in_its_level_slot(self):
        # Upstream put WARN_EXPERIMENTAL in the XMSS fail slot, printing a warning as [fail].
        db = self.sa.KexDB
        names = {v: k for k, v in vars(db).items() if k.isupper() and isinstance(v, str)}
        misplaced = [
            (alg_type, alg, names.get(text, text))
            for alg_type, algs in db.ALGORITHMS.items()
            for alg, desc in algs.items()
            for slot, prefix in ((1, 'FAIL_'), (2, 'WARN_'), (3, 'INFO_'))
            for text in (desc[slot] if len(desc) > slot else [])
            if not names.get(text, '').startswith(prefix)
        ]
        self.assertEqual(misplaced, [])

    def test_never_recommends_removing_every_algorithm_of_a_type(self):
        rec = self._recs(
            'SSH-2.0-OpenSSH_7.3', kex=['ecdh-sha2-nistp256', 'curve25519-sha256@libssh.org']
        )
        kept = {'ecdh-sha2-nistp256', 'curve25519-sha256@libssh.org'} - set(rec['kex']['del'])
        self.assertEqual(kept, {'curve25519-sha256@libssh.org'})


if __name__ == '__main__':
    unittest.main()
