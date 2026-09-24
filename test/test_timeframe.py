import unittest
from unittest import mock

from helpers import capture, load_ssh_audit


class TestTimeframe(unittest.TestCase):
    def setUp(self):
        self.sa = load_ssh_audit()

    def test_alg_timeframe_orders_versions_numerically(self):
        # 'available since' keeps the newest version, 'removed' keeps the oldest.
        tf = self.sa.get_alg_timeframe(['9.9', '10.1'])
        tf = self.sa.get_alg_timeframe(['10.0', '9.8'], tf)
        self.assertEqual(tf['OpenSSH'], ['10.0', '9.8', '9.8'])

    def test_compatibility_when_first_and_last_version_match(self):
        timeframe = {'OpenSSH': ['7.0', '7.0', None]}
        with (
            mock.patch.object(self.sa, 'get_ssh_timeframe', return_value=timeframe),
            capture() as output,
        ):
            self.sa.output_compatibility(None, None)
        self.assertEqual(output['out'], ['(gen) compatibility: OpenSSH 7.0'])

    def test_compatibility_range_orders_versions_numerically(self):
        timeframe = {'OpenSSH': ['9.9', '10.0', None]}
        with (
            mock.patch.object(self.sa, 'get_ssh_timeframe', return_value=timeframe),
            capture() as output,
        ):
            self.sa.output_compatibility(None, None)
        self.assertEqual(output['out'], ['(gen) compatibility: OpenSSH 9.9-10.0'])


if __name__ == '__main__':
    unittest.main()
