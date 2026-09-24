import struct
import unittest

from helpers import (
    VirtualSocketTestCase,
    capture,
    load_ssh_audit,
    serialize_pkm,
    write_mpint1,
)

COOKIE = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
SERVER_KEY = (1024, 0x10001, 0xee6552da432e0ac2c422df1a51287507748bfe3b5e3e4fa989a8f49fdc163a17754939ef18ef8a667ea3b71036a151fcd7f5e01ceef1e4439864baf3ac569047582c69d6c128212e0980dcb3168f00d371004039983f6033cd785b8b8f85096c7d9405cbfdc664e27c966356a6b4eb6ee20ad43414b50de18b22829c1880b551)  # fmt: skip
HOST_KEY = (2048, 0x10001, 0xdfa20cd2a530ccc8c870aa60d9feb3b35deeab81c3215a96557abbd683d21f4600f38e475d87100da9a4404220eeb3bb5584e5a2b5b48ffda58530ea19104a32577d7459d91e76aa711b241050f4cc6d5327ccce254f371acad3be56d46eb5919b73f20dbdb1177b700f00891c5bf4ed128bb90ed541b778288285bcfa28432ab5cbcb8321b6e24760e998e0daa519f093a631e44276d7dd252ce0c08c75e2ab28a7349ead779f97d0f20a6d413bf3623cd216dc35375f6366690bcc41e3b2d5465840ec7ee0dc7e3f1c101d674a0c7dbccbc3942788b111396add2f8153b46a0e4b50d66e57ee92958f1c860dd97cc0e40e32febff915343ed53573142bdf4b)  # fmt: skip
SHA256_FP = 'SHA256:vZdx3mhzbvVJmn08t/ruv8WDhJ9jfKYsCTuSzot+QIs'


class TestSSH1(VirtualSocketTestCase):
    def setUp(self):
        super().setUp()
        ssh_audit = load_ssh_audit()
        self.ssh = ssh_audit.SSH
        self.ssh1 = ssh_audit.SSH1
        self.wbuf = ssh_audit.WriteBuf
        self.audit = ssh_audit.audit
        self.AuditConf = ssh_audit.AuditConf

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.verbose = True
        conf.ssh1 = True
        conf.ssh2 = False
        return conf

    def _create_ssh1_packet(self, payload, valid_crc=True):
        padding = -(len(payload) + 4) % 8
        plen = len(payload) + 4
        pad_bytes = b'\x00' * padding
        cksum = self.ssh1.crc32(pad_bytes + payload) if valid_crc else 0
        return struct.pack('>I', plen) + pad_bytes + payload + struct.pack('>I', cksum)

    def _pkm_payload(self, cmask=72):
        w = self.wbuf()
        w.write(COOKIE)
        b, e, m = SERVER_KEY
        w.write_int(b)
        write_mpint1(w, e)
        write_mpint1(w, m)
        b, e, m = HOST_KEY
        w.write_int(b)
        write_mpint1(w, e)
        write_mpint1(w, m)
        w.write_int(2)
        w.write_int(cmask)
        w.write_int(36)
        return w.write_flush()

    def _serve(self, message_type, valid_crc=True, cmask=72):
        w = self.wbuf()
        w.write_byte(message_type)
        w.write(self._pkm_payload(cmask))
        self.vsocket.rdata.append(b'SSH-1.5-OpenSSH_7.2 ssh-audit-test\r\n')
        self.vsocket.rdata.append(self._create_ssh1_packet(w.write_flush(), valid_crc))

    def test_crc32(self):
        self.assertEqual(self.ssh1.crc32(b''), 0x00)
        self.assertEqual(
            self.ssh1.crc32(b'The quick brown fox jumps over the lazy dog'), 0xB9C60808
        )

    def test_fingerprint(self):
        b, e, m = HOST_KEY
        fpd = self.wbuf._create_mpint(m)
        fpd += self.wbuf._create_mpint(e)
        fp = self.ssh.Fingerprint(fpd)
        self.assertEqual(b, 2048)
        self.assertEqual(fp.sha256, SHA256_FP)

    def test_pkm_read(self):
        pkm = self.ssh1.PublicKeyMessage.parse(self._pkm_payload())
        self.assertIsNotNone(pkm)
        self.assertEqual(pkm.cookie, COOKIE)
        b, e, m = SERVER_KEY
        self.assertEqual(pkm.server_key_bits, b)
        self.assertEqual(pkm.server_key_public_exponent, e)
        self.assertEqual(pkm.server_key_public_modulus, m)
        b, e, m = HOST_KEY
        self.assertEqual(pkm.host_key_bits, b)
        self.assertEqual(pkm.host_key_public_exponent, e)
        self.assertEqual(pkm.host_key_public_modulus, m)
        fp = self.ssh.Fingerprint(pkm.host_key_fingerprint_data)
        self.assertEqual(pkm.protocol_flags, 2)
        self.assertEqual(pkm.supported_ciphers_mask, 72)
        self.assertEqual(pkm.supported_ciphers, ['3des', 'blowfish'])
        self.assertEqual(pkm.supported_authentications_mask, 36)
        self.assertEqual(pkm.supported_authentications, ['rsa', 'tis'])
        self.assertEqual(fp.sha256, SHA256_FP)

    def test_pkm_payload(self):
        pkm1 = self.ssh1.PublicKeyMessage(COOKIE, SERVER_KEY, HOST_KEY, 2, 72, 36)
        pkm2 = self.ssh1.PublicKeyMessage.parse(self._pkm_payload())
        self.assertEqual(serialize_pkm(pkm1), serialize_pkm(pkm2))
        self.assertEqual(serialize_pkm(pkm1), self._pkm_payload())

    def test_ssh1_server_simple(self):
        self._serve(self.ssh.Protocol.SMSG_PUBLIC_KEY)
        with capture() as output:
            self.audit(self._conf())
        self.assertEqual(output['out'], [
            '(gen) banner: SSH-1.5-OpenSSH_7.2 ssh-audit-test',
            '(gen) protocol SSH1 enabled',
            '(gen) software: OpenSSH 7.2',
            '(gen) compatibility: OpenSSH 1.2.2+',
            '(key) ssh-rsa1 -- [info] available since OpenSSH 1.2.2',
            '(enc) 3des -- [info] available since OpenSSH 1.2.2',
            '(enc) blowfish -- [info] available since OpenSSH 1.2.2',
            '(aut) rsa -- [info] available since OpenSSH 1.2.2',
            '(aut) tis -- [info] available since OpenSSH 1.2.2',
            f'(fin) ssh-rsa1 -- 2048 {SHA256_FP}',
        ])  # fmt: skip
        self.assertEqual(output['err'], [])

    def test_ciphers_with_incomplete_version_data(self):
        # idea: no version; des: client-only version; tss: empty version; rc4: no versions at all
        cmask = sum(1 << self.ssh1.CIPHERS.index(c) for c in ('idea', 'des', 'tss', 'rc4'))
        self._serve(self.ssh.Protocol.SMSG_PUBLIC_KEY, cmask=cmask)
        with capture() as output:
            self.audit(self._conf())
        lines = output['out']
        for expected in [
            '(enc) idea -- [info] cipher used by commercial SSH',
            '(enc) des -- [fail] not implemented in OpenSSH (server), unsafe algorithm',
            '(enc) des -- [info] available since OpenSSH 2.3.0 (client only)',
            '(enc) tss -- [fail] not implemented in OpenSSH, broken algorithm',
            '(enc) rc4 -- [fail] not implemented in OpenSSH, broken algorithm',
            # client-only and version-less entries must not hide an offered faulty cipher
            '(rec) -des-- enc algorithm to remove (SSH1)',
            '(rec) -tss-- enc algorithm to remove (SSH1)',
            '(rec) -rc4-- enc algorithm to remove (SSH1)',
        ]:
            self.assertIn(expected, lines)
        # a client-only version says nothing about which servers support des
        self.assertIn('(gen) compatibility: OpenSSH 1.2.2+', lines)

    def test_no_known_cipher_bits_is_reported_not_crashed(self):
        # The padding width came from max() over the offered ciphers, which raised on an empty list.
        self._serve(self.ssh.Protocol.SMSG_PUBLIC_KEY, cmask=1 << 7)
        with capture() as output:
            self.audit(self._conf())
        self.assertIn('(aut) rsa -- [info] available since OpenSSH 1.2.2', output['out'])
        self.assertFalse([line for line in output['out'] if line.startswith('(enc)')])
        self.assertEqual(output['err'], [])

    def test_falls_back_to_ssh1_when_server_rejects_ssh2(self):
        conf = self._conf()
        conf.ssh2 = True
        w = self.wbuf()
        w.write_byte(self.ssh.Protocol.SMSG_PUBLIC_KEY)
        w.write(self._pkm_payload())
        self.vsocket.rdata += [
            b'SSH-1.5-OpenSSH_7.2 ssh-audit-test\r\n',
            b'Protocol major versions differ.\n',
            OSError(104, 'Connection reset by peer'),
            b'SSH-1.5-OpenSSH_7.2 ssh-audit-test\r\n',
            self._create_ssh1_packet(w.write_flush()),
        ]
        with capture() as output:
            self.audit(conf)
        self.assertIn('(fin) ssh-rsa1 -- 2048 ' + SHA256_FP, output['out'])
        self.assertEqual(output['err'], [])
        self.assertEqual(
            [data.split(b'-OpenSSH')[0] for data in self.vsocket.sdata], [b'SSH-2.0', b'SSH-1.5']
        )

    def test_ssh1_server_invalid_first_packet(self):
        self._serve(self.ssh.Protocol.SMSG_PUBLIC_KEY + 1)
        with self.assertRaises(SystemExit), capture() as output:
            self.audit(self._conf())
        lines = output['out'] + output['err']
        self.assertEqual(len(lines), 4)
        self.assertIn('unknown message', lines[-1])

    def test_ssh1_server_invalid_checksum(self):
        self._serve(self.ssh.Protocol.SMSG_PUBLIC_KEY + 1, valid_crc=False)
        with self.assertRaises(SystemExit), capture() as output:
            self.audit(self._conf())
        lines = output['out'] + output['err']
        self.assertEqual(len(lines), 1)
        self.assertIn('checksum', lines[-1])


if __name__ == '__main__':
    unittest.main()
