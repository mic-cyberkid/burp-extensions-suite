import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from CloudHunterLogic import CloudHunterLogic

class TestCloudHunterLogic(unittest.TestCase):
    def setUp(self):
        self.logic = CloudHunterLogic()

    def test_aws_metadata(self):
        content = 'The metadata IP is 169.254.169.254.'
        findings = self.logic.analyze_content("http://test.com", content)
        self.assertTrue(any("AWS Metadata" in f['name'] for f in findings))

    def test_s3_bucket(self):
        content = 'Download files from my-bucket.s3.amazonaws.com'
        findings = self.logic.analyze_content("http://test.com", content)
        self.assertTrue(any("AWS S3 Bucket" in f['name'] for f in findings))

    def test_no_leak(self):
        content = 'Standard response with no cloud references.'
        findings = self.logic.analyze_content("http://test.com", content)
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()
