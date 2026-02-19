import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from JSMinerLogic import JSMinerLogic

class TestJSMinerLogic(unittest.TestCase):
    def setUp(self):
        self.logic = JSMinerLogic()

    def test_extract_aws_key(self):
        content = 'var key = "AKIAJ2E2BEXAMPLE1234";'
        findings = self.logic.extract_secrets(content)
        self.assertTrue(any(s['name'] == 'AWS API Key' for s in findings))

    def test_extract_endpoints(self):
        content = 'fetch("/api/v1/user/login").then(...);'
        endpoints = self.logic.extract_endpoints(content)
        self.assertIn('/api/v1/user/login', endpoints)

    def test_extract_relative_endpoints(self):
        content = 'const path = "./config.json";'
        endpoints = self.logic.extract_endpoints(content)
        self.assertIn('./config.json', endpoints)

if __name__ == '__main__':
    unittest.main()
