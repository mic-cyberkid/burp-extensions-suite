import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from TechStackLogic import TechStackLogic

class TestTechStackLogic(unittest.TestCase):
    def setUp(self):
        self.logic = TechStackLogic()

    def test_apache_detect(self):
        headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        detected = self.logic.analyze_message(headers, "")
        self.assertIn("Apache", detected)

    def test_wordpress_detect(self):
        body = '<html><head><link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css"></head></html>'
        detected = self.logic.analyze_message({}, body)
        self.assertIn("WordPress", detected)

    def test_laravel_cookie(self):
        headers = {"Set-Cookie": "laravel_session=xyz123; path=/; HttpOnly"}
        detected = self.logic.analyze_message(headers, "")
        self.assertIn("Laravel", detected)

if __name__ == '__main__':
    unittest.main()
