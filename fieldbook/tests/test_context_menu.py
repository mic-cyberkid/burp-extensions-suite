"""
Unit tests for context menu request snapshot extraction logic.
"""

import unittest
from fieldbook.src.integration.context_menu import extract_request_snapshot

class MockHttpService(object):
    def getHost(self):
        return "api.test.com"
    def getPort(self):
        return 443
    def getProtocol(self):
        return "https"

class MockRequestInfo(object):
    def getMethod(self):
        return "POST"
    def getUrl(self):
        class MockUrl(object):
            def toString(self):
                return "https://api.test.com/v1/user"
        return MockUrl()

class MockResponseInfo(object):
    def getStatusCode(self):
        return 201

class MockHelpers(object):
    def analyzeRequest(self, service_or_req, req_bytes=None):
        return MockRequestInfo()
    def analyzeResponse(self, resp_bytes):
        return MockResponseInfo()
    def bytesToString(self, b):
        return b if isinstance(b, str) else str(b)

class MockHttpRequestResponse(object):
    def getHttpService(self):
        return MockHttpService()
    def getRequest(self):
        return "POST /v1/user HTTP/1.1\r\nHost: api.test.com\r\n\r\n"
    def getResponse(self):
        return "HTTP/1.1 201 Created\r\n\r\n"

class TestContextMenu(unittest.TestCase):
    def test_extract_request_snapshot(self):
        msg = MockHttpRequestResponse()
        helpers = MockHelpers()
        snapshot = extract_request_snapshot(helpers, msg)

        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["method"], "POST")
        self.assertEqual(snapshot["host"], "api.test.com")
        self.assertEqual(snapshot["url"], "https://api.test.com/v1/user")
        self.assertEqual(snapshot["raw_response_status"], 201)
        self.assertIn("POST", snapshot["label"])
        self.assertIn("api.test.com", snapshot["label"])

if __name__ == "__main__":
    unittest.main()
