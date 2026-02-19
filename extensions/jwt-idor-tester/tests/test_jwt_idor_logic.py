import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from JWTIDORLogic import JWTIDORLogic

class TestJWTIDORLogic(unittest.TestCase):
    def setUp(self):
        self.logic = JWTIDORLogic()

    def test_decode_jwt(self):
        # Header: {"alg":"HS256","typ":"JWT"}
        # Payload: {"id":"123"}
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyJ9.sig"
        header, payload, sig = self.logic.decode_jwt(token)
        self.assertEqual(payload['id'], '123')

    def test_mutation_generation(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyJ9.sig"
        mutations = self.logic.generate_mutations(token)
        self.assertTrue(len(mutations) > 0)
        # Check if alg:none strategy is present
        self.assertTrue(any(m['strategy'] == 'alg:none' for m in mutations))
        # Check if mutated id is present (e.g. 124)
        self.assertTrue(any(str(m['mutated']) == '124' for m in mutations))

    def test_hex_mutation(self):
        # Test the user's specific hex example type
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4ZTU4ODk1NDY2MTJiMGU3MjdhMDFmNSJ9.sig"
        mutations = self.logic.generate_mutations(token)
        # 68e5889546612b0e727a01f5 -> ends in 5, should mutated to 0 or 1 based on my logic
        self.assertTrue(any(m['mutated'].startswith("68e58895") for m in mutations))

if __name__ == '__main__':
    unittest.main()
