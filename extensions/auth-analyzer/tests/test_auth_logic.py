import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from AuthLogic import AuthLogic
from entropy_utils import calculate_shannon_entropy

class TestAuthLogic(unittest.TestCase):
    def setUp(self):
        self.logic = AuthLogic()

    def test_jwt_decode(self):
        # Fake JWT (header.payload.sig)
        # header: {"alg": "none"} -> eyJhbGciOiAibm9uZSJ9
        # payload: {"user": "admin"} -> eyJ1c2VyIjogImFkbWluIn0
        token = "eyJhbGciOiAibm9uZSJ9.eyJ1c2VyIjogImFkbWluIn0.sig"
        header, payload, sig = self.logic.decode_jwt(token)
        self.assertEqual(header['alg'], 'none')
        self.assertEqual(payload['user'], 'admin')

    def test_jwt_vulnerability_none(self):
        token = "eyJhbGciOiAibm9uZSJ9.eyJ1c2VyIjogImFkbWluIn0.sig"
        findings = self.logic.analyze_jwt(token)
        self.assertTrue(any(f['name'] == 'JWT alg:none Accepted' for f in findings))

    def test_entropy(self):
        low_entropy = "aaaaa"
        high_entropy = "aB1!8#kL9z"
        self.assertLess(calculate_shannon_entropy(low_entropy), calculate_shannon_entropy(high_entropy))

    def test_mutate_id_params(self):
        params = {'userId': '100', 'other': 'val'}
        mutations = self.logic.mutate_id_params(params)
        self.assertTrue(any(m.get('userId') == '101' for m in mutations))

    def test_analyze_token_collection(self):
        tokens = ["token1", "token1", "token2"]
        stats = self.logic.analyze_token_collection(tokens)
        self.assertEqual(stats['count'], 3)
        self.assertEqual(stats['unique'], 2)
        self.assertEqual(stats['predictability'], "High")

if __name__ == '__main__':
    unittest.main()
