import os
import struct
import unittest

from helpers import VirtualSocketTestCase, capture, load_ssh_audit

COOKIE = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
KEX_ALGS = ['curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha1']  # fmt: skip
KEY_ALGS = ['ssh-rsa', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519']
ENC_ALGS = ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc']  # fmt: skip
MAC_ALGS = ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1']  # fmt: skip
COMPRESSION = ['none', 'zlib@openssh.com']


def create_ssh2_packet(payload):
    """Frame ``payload`` as an unencrypted SSH2 binary packet (RFC 4253 §6)."""
    padding = -(len(payload) + 5) % 8
    if padding < 4:
        padding += 8
    plen = len(payload) + padding + 1
    return struct.pack('>Ib', plen, padding) + payload + b'\x00' * padding


class TestSSH2(VirtualSocketTestCase):
    def setUp(self):
        super().setUp()
        ssh_audit = load_ssh_audit()
        self.ssh = ssh_audit.SSH
        self.ssh2 = ssh_audit.SSH2
        self.wbuf = ssh_audit.WriteBuf
        self.audit = ssh_audit.audit
        self.AuditConf = ssh_audit.AuditConf

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.verbose = True
        conf.ssh1 = False
        conf.ssh2 = True
        return conf

    def _kex_payload(
        self, kex=KEX_ALGS, key=KEY_ALGS, enc=ENC_ALGS, mac=MAC_ALGS, compression=COMPRESSION
    ):
        w = self.wbuf()
        w.write(COOKIE)
        w.write_list(kex)
        w.write_list(key)
        w.write_list(enc)
        w.write_list(enc)
        w.write_list(mac)
        w.write_list(mac)
        w.write_list(compression)
        w.write_list(compression)
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return w.write_flush()

    def _audit_server(self, banner, **algs):
        """Audit a server sending ``banner`` and a KEXINIT built from ``algs``; return stdout lines."""
        w = self.wbuf()
        w.write_byte(self.ssh.Protocol.MSG_KEXINIT)
        w.write(self._kex_payload(**algs))
        self.vsocket.rdata += [banner + b'\r\n', create_ssh2_packet(w.write_flush())]
        with capture() as output:
            self.audit(self._conf())
        return output['out']

    def test_kex_read(self):
        kex = self.ssh2.Kex.parse(self._kex_payload())
        self.assertIsNotNone(kex)
        self.assertEqual(kex.cookie, COOKIE)
        self.assertEqual(kex.kex_algorithms, KEX_ALGS)
        self.assertEqual(kex.key_algorithms, KEY_ALGS)
        self.assertIsNotNone(kex.client)
        self.assertIsNotNone(kex.server)
        self.assertEqual(kex.client.encryption, ENC_ALGS)
        self.assertEqual(kex.server.encryption, ENC_ALGS)
        self.assertEqual(kex.client.mac, MAC_ALGS)
        self.assertEqual(kex.server.mac, MAC_ALGS)
        self.assertEqual(kex.client.compression, COMPRESSION)
        self.assertEqual(kex.server.compression, COMPRESSION)
        self.assertEqual(kex.client.languages, [''])
        self.assertEqual(kex.server.languages, [''])
        self.assertIs(kex.follows, False)
        self.assertEqual(kex.unused, 0)

    def _get_empty_kex(self, cookie=None):
        cli = self.ssh2.KexParty([], [], ['none'], [])
        srv = self.ssh2.KexParty([], [], ['none'], [])
        if cookie is None:
            cookie = os.urandom(16)
        return self.ssh2.Kex(cookie, [], [], cli, srv, 0)

    def _get_kex_variat1(self):
        kex = self._get_empty_kex(COOKIE)
        kex.kex_algorithms.extend(KEX_ALGS)
        kex.key_algorithms.extend(KEY_ALGS)
        kex.server.encryption.extend(ENC_ALGS)
        kex.server.mac.extend(MAC_ALGS)
        kex.server.compression.append('zlib@openssh.com')
        kex.client.encryption.extend(kex.server.encryption)
        kex.client.mac.extend(kex.server.mac)
        kex.client.compression.extend(a for a in kex.server.compression if a != 'none')
        return kex

    def test_key_payload(self):
        kex1 = self._get_kex_variat1()
        kex2 = self.ssh2.Kex.parse(self._kex_payload())
        self.assertEqual(kex1.payload, kex2.payload)

    def _serve(self, payload):
        self.vsocket.rdata.append(b'SSH-2.0-OpenSSH_7.3 ssh-audit-test\r\n')
        self.vsocket.rdata.append(create_ssh2_packet(payload))

    def test_ssh2_server_simple(self):
        w = self.wbuf()
        w.write_byte(self.ssh.Protocol.MSG_KEXINIT)
        w.write(self._kex_payload())
        self._serve(w.write_flush())
        with capture() as output:
            self.audit(self._conf())
        lines = output['out']
        self.assertEqual(len(lines), 75)
        self.assertEqual(output['err'], [])
        self.assertTrue(self.vsocket.closed, 'socket left open after a completed audit')
        self.assertEqual(lines[:4], [
            '(gen) banner: SSH-2.0-OpenSSH_7.3 ssh-audit-test',
            '(gen) software: OpenSSH 7.3',
            '(gen) compatibility: OpenSSH 7.2+ (some functionality from 6.6), Dropbear SSH 2020.79+',
            '(gen) compression: enabled (zlib@openssh.com)',
        ])  # fmt: skip
        self.assertIn('(kex) ecdh-sha2-nistp256 -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency', lines)  # fmt: skip
        self.assertIn('(key) ssh-rsa -- [fail] using broken SHA-1 hash algorithm', lines)
        self.assertIn('(enc) aes128-cbc -- [warn] using weak cipher mode', lines)
        self.assertIn('(rec) -aes128-cbc-- enc algorithm to remove ', lines)
        self.assertIn('(rec) -ssh-rsa-- key algorithm to remove ', lines)
        # every kex offered has a fault and OpenSSH 7.3 supports no fault-free one,
        # so the least-faulty ones are kept rather than advising removal of all
        recs = [line for line in lines if line.startswith('(rec)')]
        self.assertNotIn('(rec) -curve25519-sha256@libssh.org-- kex algorithm to remove ', recs)
        self.assertNotIn(
            '(rec) -diffie-hellman-group-exchange-sha256-- kex algorithm to remove ', recs
        )
        self.assertFalse(any(line.startswith('(rec) +') for line in recs), recs)

    def test_no_version_based_cve_output(self):
        # CVE matching by banner version was removed: distro backports made it wrong.
        w = self.wbuf()
        w.write_byte(self.ssh.Protocol.MSG_KEXINIT)
        w.write(self._kex_payload())
        self.vsocket.rdata.append(b'SSH-2.0-libssh-0.7.2\r\n')
        self.vsocket.rdata.append(create_ssh2_packet(w.write_flush()))
        with capture() as output:
            self.audit(self._conf())
        self.assertFalse([line for line in output['out'] if line.startswith(('(cve)', '(sec)'))])

    def test_unknown_unversioned_and_empty_algorithm_names(self):
        lines = self._audit_server(
            b'SSH-2.0-OpenSSH_9.6',
            kex=['vendor-kex@example.com', 'curve25519-sha256'],
            key=['ssh-rsa-sha2-256'],
            enc=['aes128-ctr'],
            mac=[''],
            compression=['none'],
        )
        self.assertIn('(gen) compression: disabled', lines)
        self.assertIn('(kex) vendor-kex@example.com -- [warn] unknown algorithm', lines)
        # an algorithm with no notes and no version data still gets a line
        self.assertIn('(key) ssh-rsa-sha2-256 -- [info] ', lines)
        # an empty MAC list prints no MAC section at all
        self.assertFalse([line for line in lines if line.startswith('(mac)')])
        # the unknown algorithm is ignored when working out compatibility
        self.assertIn('(gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2018.76+', lines)

    def test_recommendations_append_and_skip_types_without_advice(self):
        lines = self._audit_server(
            b'SSH-2.0-OpenSSH_10.0',
            kex=['curve25519-sha256'],
            key=['ssh-ed25519'],
            enc=['chacha20-poly1305@openssh.com'],
            mac=['hmac-sha2-512-etm@openssh.com'],
        )
        recs = [line for line in lines if line.startswith('(rec)')]
        self.assertIn('(rec) +mlkem768x25519-sha256-- kex algorithm to append ', recs)
        self.assertIn('(rec) -curve25519-sha256-- kex algorithm to remove ', recs)
        # unknown software: removals only, and only for types with a faulty algorithm
        self.vsocket.rdata.clear()
        lines = self._audit_server(
            b'SSH-2.0-VendorSSH_1.0',
            kex=['ecdh-sha2-nistp256', 'mlkem768x25519-sha256'],
            key=['ssh-ed25519'],
            enc=['chacha20-poly1305@openssh.com'],
            mac=['hmac-sha2-512-etm@openssh.com'],
        )
        recs = [line for line in lines if line.startswith('(rec)')]
        self.assertEqual(recs, ['(rec) -ecdh-sha2-nistp256-- kex algorithm to remove '])

    def test_ssh2_server_invalid_first_packet(self):
        w = self.wbuf()
        w.write_byte(self.ssh.Protocol.MSG_KEXINIT + 1)
        self._serve(w.write_flush())
        with self.assertRaises(SystemExit), capture() as output:
            self.audit(self._conf())
        lines = output['out'] + output['err']
        self.assertEqual(len(lines), 3)
        self.assertIn('unknown message', lines[-1])


if __name__ == '__main__':
    unittest.main()
