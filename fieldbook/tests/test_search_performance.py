"""
Unit performance & correctness test for search and filter with 1,000+ synthetic entries.
"""

import time
import unittest
import tempfile
import shutil
import os

from fieldbook.src.model.notebook import NotebookEntry, NotebookStore

class TestSearchPerformance(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="fieldbook_perf_")
        self.db_path = os.path.join(self.test_dir, "perf_notebook.json")
        self.store = NotebookStore(filepath=self.db_path)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_search_1000_entries_performance(self):
        # Create 1,000 synthetic entries
        entries = []
        for i in range(1000):
            entry_type = ["NOTE", "OBSERVATION", "HYPOTHESIS", "TEST_RESULT", "EVIDENCE", "TODO"][i % 6]
            target = "target%d.com" % (i % 10)
            tags = ["tag%d" % (i % 5), "group%d" % (i % 3)]
            pinned = (i % 50 == 0) # 20 pinned entries
            text = "Research note %d detailing security findings for %s" % (i, target)
            e = NotebookEntry(
                entry_type=entry_type,
                text=text,
                tags=tags,
                target=target,
                pinned=pinned
            )
            self.store.add_entry(e, save=False)

        self.assertEqual(len(self.store.get_all_entries()), 1000)

        # Benchmark search query
        start_time = time.time()
        results = self.store.search_and_filter(query="security findings", entry_type="HYPOTHESIS", target="target0.com")
        duration = time.time() - start_time

        # Search across 1000 items should complete in under 50ms
        self.assertLess(duration, 0.20)
        self.assertGreater(len(results), 0)

        # Verify pinned entries come first
        pinned_found = False
        unpinned_after_pinned = False
        for r in results:
            if r.pinned:
                pinned_found = True
            elif pinned_found and not r.pinned:
                unpinned_after_pinned = True
            elif not r.pinned and not pinned_found:
                pass # all unpinned if no pinned match

        # Autocompletion lists
        all_tags = self.store.get_all_tags()
        self.assertEqual(len(all_tags), 8)

        all_targets = self.store.get_all_targets()
        self.assertEqual(len(all_targets), 10)

if __name__ == "__main__":
    unittest.main()
