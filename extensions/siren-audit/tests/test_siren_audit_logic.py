# -*- coding: utf-8 -*-
"""
Unit tests for Siren Audit extension logic.
"""

import sys
import unittest
import re

# Sensitive headers test
SENSITIVE_HEADERS = set(["authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"])

BODY_SECRET_KEY_RE = re.compile(
    r'(?i)("?\b(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|'
    r'access[_-]?token|refresh[_-]?token|session[_-]?id|jwt|bearer)\b"?\s*[:=]\s*)'
    r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^&\s,}]+)'
)

BINARY_CONTENT_TYPE_PREFIXES = ("image/", "audio/", "video/", "font/")
BINARY_CONTENT_TYPES_EXACT = set([
    "application/octet-stream", "application/pdf", "application/zip",
    "application/gzip", "application/x-gzip", "application/x-tar",
    "application/x-rar-compressed", "application/x-7z-compressed",
    "application/wasm", "application/x-shockwave-flash",
])
BINARY_CONTENT_TYPE_VND_RE = re.compile(r'(?i)^application/vnd\.')


class TestSirenAuditLogic(unittest.TestCase):

    def test_sensitive_headers(self):
        self.assertIn("authorization", SENSITIVE_HEADERS)
        self.assertIn("cookie", SENSITIVE_HEADERS)
        self.assertIn("set-cookie", SENSITIVE_HEADERS)

    def test_body_secret_key_re(self):
        sample = '{"username": "admin", "password": "secret123", "token": "abc123xyz"}'
        redacted = BODY_SECRET_KEY_RE.sub(lambda m: m.group(1) + '"REDACTED"', sample)
        self.assertIn('"password": "REDACTED"', redacted)
        self.assertIn('"token": "REDACTED"', redacted)
        self.assertIn('"username": "admin"', redacted)

    def test_redact_headers(self):
        headers = {
            "Host": "example.com",
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "User-Agent": "Mozilla/5.0"
        }
        out = {}
        for k, v in headers.items():
            if k.lower() in SENSITIVE_HEADERS:
                out[k] = "REDACTED (%d chars)" % len(v)
            else:
                out[k] = v
        self.assertEqual(out["Host"], "example.com")
        self.assertEqual(out["User-Agent"], "Mozilla/5.0")
        self.assertTrue(out["Authorization"].startswith("REDACTED"))
        self.assertTrue(out["Cookie"].startswith("REDACTED"))

    def test_truncate(self):
        text = "Hello World!"
        max_chars = 5
        truncated = text[:max_chars] + ("\n...[truncated, showing %d of %d chars]" % (max_chars, len(text)))
        self.assertTrue(truncated.startswith("Hello"))
        self.assertIn("truncated", truncated)

    def test_is_binary_content_type(self):
        def is_binary(content_type):
            if not content_type:
                return False
            ct = content_type.split(";")[0].strip().lower()
            if ct in BINARY_CONTENT_TYPES_EXACT:
                return True
            if BINARY_CONTENT_TYPE_VND_RE.match(ct):
                return True
            for prefix in BINARY_CONTENT_TYPE_PREFIXES:
                if ct.startswith(prefix):
                    return True
            return False

        self.assertTrue(is_binary("image/png"))
        self.assertTrue(is_binary("application/pdf"))
        self.assertFalse(is_binary("application/json"))
        self.assertFalse(is_binary("text/html"))


if __name__ == "__main__":
    unittest.main()
