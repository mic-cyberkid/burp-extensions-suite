import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../common/python'))

from ResetOtpLogic import ResetOtpLogic

class TestResetOtpLogic(unittest.TestCase):
    def setUp(self):
        self.logic = ResetOtpLogic()

    def test_interesting_endpoint(self):
        self.assertTrue(self.logic.is_interesting_endpoint("http://example.com/api/v1/password-reset"))
        self.assertTrue(self.logic.is_interesting_endpoint("http://example.com/verify-otp"))
        self.assertFalse(self.logic.is_interesting_endpoint("http://example.com/static/js/main.js"))

    def test_weak_token(self):
        url = "http://example.com/reset?token=123"
        findings = self.logic.analyze_message(url, {}, "")
        self.assertTrue(any(f['name'] == 'Weak Reset/OTP Token Entropy' for f in findings))

    def test_email_exposure(self):
        url = "http://example.com/reset?token=admin@example.com"
        findings = self.logic.analyze_message(url, {}, "")
        self.assertTrue(any(f['name'] == 'Email Exposure in Reset Token' for f in findings))

    def test_short_otp(self):
        url = "http://example.com/verify"
        body = '{"otp": "1234"}'
        findings = self.logic.analyze_message(url, {}, body)
        self.assertTrue(any(f['name'] == 'Short/Numeric OTP Detected' for f in findings))

    def test_host_poisoning(self):
        self.assertTrue(self.logic.check_host_poisoning("attacker.com", "Visit http://attacker.com/reset to continue"))
        self.assertFalse(self.logic.check_host_poisoning("attacker.com", "Visit http://victim.com/reset to continue"))

if __name__ == '__main__':
    unittest.main()
