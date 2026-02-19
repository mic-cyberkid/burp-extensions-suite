import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from APIMinerLogic import APIMinerLogic

class TestAPIMinerLogic(unittest.TestCase):
    def setUp(self):
        self.logic = APIMinerLogic()

    def test_is_api_doc(self):
        self.assertTrue(self.logic.is_api_doc("http://test.com/swagger.json"))
        self.assertTrue(self.logic.is_api_doc("http://test.com/v2/api-docs"))
        self.assertFalse(self.logic.is_api_doc("http://test.com/index.html"))

    def test_extract_endpoints(self):
        body = '{"paths": {"/user/login": {}, "/admin/panel": {}}}'
        endpoints = self.logic.extract_endpoints(body)
        self.assertIn("/user/login", endpoints)
        self.assertIn("/admin/panel", endpoints)

    def test_analyze_response(self):
        url = "http://test.com/swagger.json"
        body = '{"paths": {"/api": {}}}'
        findings = self.logic.analyze_response(url, body)
        self.assertTrue(any("API Documentation Discovered" in f['name'] for f in findings))

if __name__ == '__main__':
    unittest.main()
