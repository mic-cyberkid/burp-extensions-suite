import unittest
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ScannerLogic import ScannerLogic

class TestScannerLogic(unittest.TestCase):
    def setUp(self):
        self.logic = ScannerLogic()

    def test_missing_csp(self):
        headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff'
        }
        findings = self.logic.analyze_response('http://example.com', 200, headers)
        names = [f['name'] for f in findings]
        self.assertIn('Missing Content-Security-Policy', names)

    def test_permissive_cors(self):
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Security-Policy': "default-src 'self'"
        }
        findings = self.logic.analyze_response('http://example.com', 200, headers)
        names = [f['name'] for f in findings]
        self.assertIn('Permissive CORS Policy', names)

    def test_correct_headers(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY'
        }
        findings = self.logic.analyze_response('http://example.com', 200, headers)
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()
