"""
Unit tests for Fieldbook NotebookEntry and NotebookStore.
"""

import os
import glob
import shutil
import tempfile
import unittest

from fieldbook.src.model.notebook import NotebookEntry, NotebookStore, ENTRY_TYPES

class TestNotebookModel(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fieldbook_test_")
        self.db_path = os.path.join(self.test_dir, "sub_dir", "test_notebook.json")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_entry_creation_and_dict_conversion(self):
        entry = NotebookEntry(
            entry_type="HYPOTHESIS",
            text="Testing IDOR in password reset",
            tags=["idor", "auth"],
            target="example.com",
            pinned=True
        )
        self.assertEqual(entry.entry_type, "HYPOTHESIS")
        self.assertEqual(entry.text, "Testing IDOR in password reset")
        self.assertIn("idor", entry.tags)
        self.assertTrue(entry.pinned)

        data = entry.to_dict()
        restored = NotebookEntry.from_dict(data)
        self.assertEqual(restored.id, entry.id)
        self.assertEqual(restored.entry_type, entry.entry_type)
        self.assertEqual(restored.text, entry.text)
        self.assertEqual(restored.tags, entry.tags)
        self.assertEqual(restored.target, entry.target)
        self.assertEqual(restored.pinned, entry.pinned)

    def test_crud_operations(self):
        store = NotebookStore(filepath=self.db_path)
        self.assertEqual(len(store.get_all_entries()), 0)

        # Create
        entry1 = store.create_entry(
            entry_type="NOTE",
            text="Initial findings",
            tags=["recon"],
            target="target.org"
        )
        self.assertIsNotNone(entry1.id)
        self.assertEqual(len(store.get_all_entries()), 1)

        # Read
        fetched = store.get_entry(entry1.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.text, "Initial findings")

        # Update
        updated = store.update_entry(entry1.id, text="Updated findings", pinned=True)
        self.assertEqual(updated.text, "Updated findings")
        self.assertTrue(updated.pinned)

        # Delete
        deleted = store.delete_entry(entry1.id)
        self.assertTrue(deleted)
        self.assertIsNone(store.get_entry(entry1.id))
        self.assertEqual(len(store.get_all_entries()), 0)

    def test_persistence_roundtrip(self):
        store = NotebookStore(filepath=self.db_path)
        e1 = store.create_entry(
            entry_type="OBSERVATION",
            text="Open redirect on /login?next=",
            tags=["redirect", "vuln"],
            target="shop.target.com",
            linked_requests=[{
                "label": "GET /login?next=https://evil.com",
                "method": "GET",
                "url": "https://shop.target.com/login?next=https://evil.com",
                "host": "shop.target.com",
                "raw_request": "GET /login?next=https://evil.com HTTP/1.1\r\nHost: shop.target.com\r\n\r\n",
                "raw_response_status": 302,
                "raw_response_headers_and_body_or_reference": "HTTP/1.1 302 Found\r\nLocation: https://evil.com\r\n\r\n",
                "captured_at": "2023-10-01T12:00:00Z"
            }]
        )

        # Re-open store from disk
        store2 = NotebookStore(filepath=self.db_path)
        self.assertEqual(len(store2.get_all_entries()), 1)
        restored_e1 = store2.get_entry(e1.id)
        self.assertIsNotNone(restored_e1)
        self.assertEqual(restored_e1.text, e1.text)
        self.assertEqual(restored_e1.target, "shop.target.com")
        self.assertEqual(len(restored_e1.linked_requests), 1)
        self.assertEqual(restored_e1.linked_requests[0]["raw_response_status"], 302)

    def test_corrupt_file_recovery(self):
        # Create corrupted file
        os.makedirs(os.path.dirname(self.db_path))
        with open(self.db_path, "w") as f:
            f.write("{ invalid json corrupted content ...")

        # Load store with corrupted file
        store = NotebookStore(filepath=self.db_path)
        self.assertIsNotNone(store.corrupt_warning)
        self.assertEqual(len(store.get_all_entries()), 0)

        # Check backup file created
        backups = glob.glob(self.db_path + ".corrupt.*")
        self.assertGreaterEqual(len(backups), 1)

        # Verify new saves work cleanly
        store.create_entry(text="Fresh note after corruption")
        self.assertEqual(len(store.get_all_entries()), 1)

        # Re-open store to verify persistence of new note
        store2 = NotebookStore(filepath=self.db_path)
        self.assertEqual(len(store2.get_all_entries()), 1)
        self.assertIsNone(store2.corrupt_warning)

    def test_search_and_filter(self):
        store = NotebookStore(filepath=self.db_path)
        e1 = store.create_entry(entry_type="TODO", text="Check JWT secret", tags=["jwt"], target="api.target.com", pinned=False)
        e2 = store.create_entry(entry_type="HYPOTHESIS", text="Race condition in coupon code", tags=["race"], target="shop.target.com", pinned=True)
        e3 = store.create_entry(entry_type="EVIDENCE", text="JWT weak secret HMAC key found", tags=["jwt", "crypto"], target="api.target.com", pinned=False)

        # Search query
        jwt_results = store.search_and_filter(query="jwt")
        self.assertEqual(len(jwt_results), 2)

        # Filter entry_type
        todo_results = store.search_and_filter(entry_type="TODO")
        self.assertEqual(len(todo_results), 1)
        self.assertEqual(todo_results[0].id, e1.id)

        # Filter target
        shop_results = store.search_and_filter(target="shop.target.com")
        self.assertEqual(len(shop_results), 1)
        self.assertEqual(shop_results[0].id, e2.id)

        # Filter tag
        crypto_results = store.search_and_filter(tag="crypto")
        self.assertEqual(len(crypto_results), 1)

        # Pinned only
        pinned_results = store.search_and_filter(pinned_only=True)
        self.assertEqual(len(pinned_results), 1)
        self.assertEqual(pinned_results[0].id, e2.id)

        # Check sorting: pinned should come first in all_results
        all_results = store.search_and_filter()
        self.assertEqual(all_results[0].id, e2.id)

    def test_backlinks_and_autocompletion(self):
        store = NotebookStore(filepath=self.db_path)
        e1 = store.create_entry(text="Root vulnerability note", tags=["vulnerability"], target="app.local")
        e2 = store.create_entry(text="Follow-up note", tags=["followup"], target="app.local", linked_note_ids=[e1.id])
        e3 = store.create_entry(text="Referencing note text " + e1.id, tags=["vulnerability"], target="app.local")

        tags = store.get_all_tags()
        self.assertEqual(tags, ["followup", "vulnerability"])

        targets = store.get_all_targets()
        self.assertEqual(targets, ["app.local"])

        backlinks = store.get_backlinks(e1.id)
        backlink_ids = [b.id for b in backlinks]
        self.assertIn(e2.id, backlink_ids)
        self.assertIn(e3.id, backlink_ids)

if __name__ == "__main__":
    unittest.main()
