import unittest
import os
import json
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ReportLogic import ReportLogic

class TestReportLogic(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_findings.json"
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        self.logic = ReportLogic(self.test_file)

    def tearDown(self):
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_add_finding(self):
        self.logic.add_finding("Issue1", "High", "Certain", "http://test.com", "Desc", "Remed")
        self.assertEqual(len(self.logic.findings), 1)
        self.assertEqual(self.logic.findings[0]['name'], "Issue1")

    def test_persistence(self):
        self.logic.add_finding("Issue1", "High", "Certain", "http://test.com", "Desc", "Remed")
        new_logic = ReportLogic(self.test_file)
        self.assertEqual(len(new_logic.findings), 1)

    def test_markdown_gen(self):
        self.logic.add_finding("Issue1", "High", "Certain", "http://test.com", "Desc", "Remed")
        md = self.logic.generate_markdown()
        self.assertIn("# Vulnerability Assessment Report", md)
        self.assertIn("Issue1", md)

if __name__ == '__main__':
    unittest.main()
