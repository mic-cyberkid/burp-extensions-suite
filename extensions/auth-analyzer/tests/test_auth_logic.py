import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from AuthLogic import AuthLogic

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
        self.assertLess(self.logic.calculate_entropy(low_entropy), self.logic.calculate_entropy(high_entropy))

    def test_mutate_id_params(self):
        params = {'userId': '100', 'other': 'val'}
        mutations = self.logic.mutate_id_params(params)
        self.assertTrue(any(m.get('userId') == '101' for m in mutations))

if __name__ == '__main__':
    unittest.main()
