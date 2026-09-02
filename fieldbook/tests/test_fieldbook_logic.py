# -*- coding: utf-8 -*-
"""
test_fieldbook_logic.py - Unit tests for Fieldbook logic, data layer, search/filtering,
Markdown parsing, export generation, and persistence recovery.
"""

import os
import sys
import time
import shutil
import tempfile
import unittest

# Ensure src/ is in python path
sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from FieldbookLogic import (
    FieldbookEntry,
    FieldbookStore,
    MarkdownParser,
    FieldbookExporter,
    ENTRY_TYPES
)

class TestFieldbookEntry(unittest.TestCase):
    def test_entry_creation_defaults(self):
        entry = FieldbookEntry()
        self.assertIsNotNone(entry.id)
        self.assertEqual(entry.type, "NOTE")
        self.assertEqual(entry.content, "")
        self.assertEqual(entry.target, "")
        self.assertEqual(entry.tags, [])
        self.assertEqual(entry.linked_requests, [])

    def test_entry_serialization_roundtrip(self):
        req = {
            "id": 1,
            "method": "POST",
            "host": "api.example.com",
            "path": "/v1/login",
            "url": "https://api.example.com/v1/login",
            "request_bytes_b64": "UE9TVCAvdmExL2xvZ2luIEhUVFAvMS4x",
            "response_bytes_b64": "SFRUUC8xLjEgMjAwIE9L"
        }
        entry = FieldbookEntry(
            entry_type="HYPOTHESIS",
            content="Testing BOLA on login endpoint",
            target="Acme Inc",
            tags=["auth", "bola"],
            linked_requests=[req]
        )
        data = entry.to_dict()
        restored = FieldbookEntry.from_dict(data)

        self.assertEqual(restored.id, entry.id)
        self.assertEqual(restored.type, "HYPOTHESIS")
        self.assertEqual(restored.content, "Testing BOLA on login endpoint")
        self.assertEqual(restored.target, "Acme Inc")
        self.assertEqual(restored.tags, ["auth", "bola"])
        self.assertEqual(len(restored.linked_requests), 1)
        self.assertEqual(restored.linked_requests[0]["method"], "POST")


class TestFieldbookStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "notebook.json")
        self.store = FieldbookStore(filepath=self.db_path, debounce_interval=0.05)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_crud_operations(self):
        # Create
        e1 = FieldbookEntry(entry_type="NOTE", content="First note", target="TargetA", tags=["t1"])
        self.store.add_entry(e1, immediate=True)
        self.assertIsNotNone(self.store.get_entry(e1.id))

        # Read
        all_entries = self.store.get_all_entries()
        self.assertEqual(len(all_entries), 1)

        # Update
        updated = self.store.update_entry(e1.id, content="Updated first note", tags=["t1", "t2"], immediate=True)
        self.assertIsNotNone(updated)
        self.assertEqual(self.store.get_entry(e1.id).content, "Updated first note")
        self.assertEqual(self.store.get_entry(e1.id).tags, ["t1", "t2"])

        # Targets and Tags lists
        self.assertIn("TargetA", self.store.get_targets())
        self.assertIn("t1", self.store.get_tags())
        self.assertIn("t2", self.store.get_tags())

        # Delete
        self.store.delete_entry(e1.id, immediate=True)
        self.assertIsNone(self.store.get_entry(e1.id))
        self.assertEqual(len(self.store.get_all_entries()), 0)

    def test_search_and_filtering(self):
        e1 = FieldbookEntry(entry_type="NOTE", content="Check SQL injection in search", target="TargetAlpha", tags=["sqli", "p1"])
        e2 = FieldbookEntry(entry_type="EVIDENCE", content="Found XSS payload in profile bio", target="TargetBeta", tags=["xss", "p2"])
        e3 = FieldbookEntry(entry_type="OBSERVATION", content="IDOR vulnerability on order receipt #req:1", target="TargetAlpha", tags=["idor", "p1"])

        self.store.add_entry(e1, immediate=True)
        self.store.add_entry(e2, immediate=True)
        self.store.add_entry(e3, immediate=True)

        # Query substring search
        res = self.store.search_entries(query="sql")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].id, e1.id)

        # Entry type filter
        res = self.store.search_entries(entry_type="EVIDENCE")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].id, e2.id)

        # Target filter
        res = self.store.search_entries(target="TargetAlpha")
        self.assertEqual(len(res), 2)

        # Tag filter
        res = self.store.search_entries(tag="p1")
        self.assertEqual(len(res), 2)

        # Combined filter
        res = self.store.search_entries(query="IDOR", entry_type="OBSERVATION", target="TargetAlpha", tag="idor")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].id, e3.id)

    def test_persistence_roundtrip(self):
        e1 = FieldbookEntry(entry_type="TEST_RESULT", content="Password reset token leak", target="SecCorp", tags=["auth"])
        self.store.add_entry(e1, immediate=True)

        # Load new store instance from same file
        new_store = FieldbookStore(filepath=self.db_path)
        retrieved = new_store.get_entry(e1.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.type, "TEST_RESULT")
        self.assertEqual(retrieved.content, "Password reset token leak")
        self.assertEqual(retrieved.target, "SecCorp")

    def test_corrupt_file_recovery(self):
        # Write corrupted JSON to file
        with open(self.db_path, "w") as f:
            f.write("{ INVALID JSON payload ...")

        # Load store with corrupt file
        corrupt_store = FieldbookStore(filepath=self.db_path)
        self.assertEqual(len(corrupt_store.get_all_entries()), 0)

        # Verify bad file was backed up as .bak
        bak_path = self.db_path + ".bak"
        self.assertTrue(os.path.exists(bak_path))
        with open(bak_path, "r") as f:
            content = f.read()
            self.assertIn("INVALID JSON", content)


class TestMarkdownParser(unittest.TestCase):
    def test_markdown_to_html_formatting(self):
        md = "# Heading 1\n## Heading 2\n**bold text** and *italic text*\n- item 1\n- item 2\n`code span`\n#req:2"
        html = MarkdownParser.to_html(md)

        self.assertIn("<h1>Heading 1</h1>", html)
        self.assertIn("<h2>Heading 2</h2>", html)
        self.assertIn("<b>bold text</b>", html)
        self.assertIn("<i>italic text</i>", html)
        self.assertIn("<li>item 1</li>", html)
        self.assertIn("<code>code span</code>", html)
        # Check #req:2 reference parsing
        self.assertIn('<a href="req:2">#req:2</a>', html)

    def test_code_block_and_links(self):
        md = "```\n<script>alert(1)</script>\n```\nCheck [Google](https://google.com)"
        html = MarkdownParser.to_html(md)

        self.assertIn("<pre><code>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn('<a href="https://google.com">Google</a>', html)


class TestFieldbookExporter(unittest.TestCase):
    def test_markdown_export(self):
        req1 = {"id": 1, "method": "GET", "host": "app.com", "path": "/api/users", "url": "https://app.com/api/users"}
        e1 = FieldbookEntry(entry_type="OBSERVATION", content="Enumerated user endpoint", target="AppTarget", tags=["enum"], linked_requests=[req1])
        e2 = FieldbookEntry(entry_type="EVIDENCE", content="Exposed PII data", target="AppTarget", tags=["pii"])

        exported_md = FieldbookExporter.export_markdown([e1, e2])

        self.assertIn("# Fieldbook Research Report", exported_md)
        self.assertIn("## Target: AppTarget", exported_md)
        self.assertIn("### [OBSERVATION]", exported_md)
        self.assertIn("Enumerated user endpoint", exported_md)
        self.assertIn("> **#req:1:** `GET app.com/api/users`", exported_md)

    def test_json_export(self):
        e1 = FieldbookEntry(entry_type="NOTE", content="JSON export test", target="TargetX")
        json_str = FieldbookExporter.export_json([e1])

        self.assertIn("JSON export test", json_str)
        self.assertIn("TargetX", json_str)


if __name__ == "__main__":
    unittest.main()
