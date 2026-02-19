import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from TakeoverLogic import TakeoverLogic

class TestTakeoverLogic(unittest.TestCase):
    def setUp(self):
        self.logic = TakeoverLogic()

    def test_github_takeover(self):
        body = "There isn't a GitHub Pages site here."
        findings = self.logic.analyze_response("http://blog.test.com", body)
        self.assertTrue(any("GitHub Pages" in f['name'] for f in findings))

    def test_heroku_takeover(self):
        body = "no such app"
        findings = self.logic.analyze_response("http://app.test.com", body)
        self.assertTrue(any("Heroku" in f['name'] for f in findings))

    def test_no_takeover(self):
        body = "Welcome to my website!"
        findings = self.logic.analyze_response("http://test.com", body)
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()
