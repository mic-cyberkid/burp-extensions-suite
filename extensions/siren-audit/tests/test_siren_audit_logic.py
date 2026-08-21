# -*- coding: utf-8 -*-
"""
Unit tests for Siren Audit extension logic, Markdown parser, and HTML activity formatting.
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


def markdown_to_html(text, dark=True):
    if not text:
        return ""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _code_block(m):
        code = m.group(1)
        bg = "#1e293b" if dark else "#f1f5f9"
        fg = "#f8fafc" if dark else "#0f172a"
        return "<pre style=\"background-color: " + bg + "; color: " + fg + "; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 11px;\">" + code + "</pre>"
    text = re.sub(r"```(?:[a-zA-Z0-9_]+)?\n?(.*?)```", _code_block, text, flags=re.DOTALL)

    def _inline_code(m):
        code = m.group(1)
        bg = "#334155" if dark else "#e2e8f0"
        fg = "#f8fafc" if dark else "#0f172a"
        return "<code style=\"background-color: " + bg + "; color: " + fg + "; padding: 2px 4px; font-family: monospace; font-size: 11px;\">" + code + "</code>"
    text = re.sub(r"`([^`]+)`", _inline_code, text)

    h_color = "#60a5fa" if dark else "#2563eb"
    def _h4(m): return "<h4 style=\"margin: 6px 0; color: " + h_color + "; font-size: 13px;\">" + m.group(1) + "</h4>"
    def _h3(m): return "<h3 style=\"margin: 8px 0; color: " + h_color + "; font-size: 14px;\">" + m.group(1) + "3</h3>"
    def _h2(m): return "<h2 style=\"margin: 10px 0; color: " + h_color + "; font-size: 16px;\">" + m.group(1) + "</h2>"

    text = re.sub(r"(?m)^###\s+(.*)$", _h4, text)
    text = re.sub(r"(?m)^##\s+(.*)$", _h3, text)
    text = re.sub(r"(?m)^#\s+(.*)$", _h2, text)

    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", text)

    def _li(m): return "<li style=\"margin-left: 12px;\">" + m.group(1) + "</li>"
    text = re.sub(r"(?m)^\s*[\-\*]\s+(.*)$", _li, text)

    lines = text.split("\n")
    out = []
    in_pre = False
    for l in lines:
        if "<pre" in l: in_pre = True
        if "</pre>" in l: in_pre = False
        if not in_pre and not l.startswith("<h") and not l.startswith("<li") and not l.startswith("<div"):
            if l.strip() == "":
                out.append("<br/>")
            else:
                out.append(l + "<br/>")
        else:
            out.append(l)
    return "".join(out)


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

    def test_markdown_to_html(self):
        md = "### Header\n**Bold Text** and `code`"
        html = markdown_to_html(md, dark=True)
        self.assertIn("<h4", html)
        self.assertIn("<b>Bold Text</b>", html)
        self.assertIn("<code", html)

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
