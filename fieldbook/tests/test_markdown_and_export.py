"""
Unit tests for Fieldbook Markdown rendering and export functions.
"""

import json
import unittest

from fieldbook.src.model.notebook import NotebookEntry, NotebookStore
from fieldbook.src.util.markdown_util import markdown_to_html
from fieldbook.src.util.export_util import export_to_json, export_to_markdown

class TestMarkdownAndExport(unittest.TestCase):
    def test_markdown_to_html_formatting(self):
        md = """# Heading 1
## Heading 2
### Heading 3

This is **bold** text and *italic* text and `code` text.

- Item 1
- Item 2 with #req:1 reference

Check out [Link](https://example.com) and #note:abcd-1234.

```
code block content
```"""

        html = markdown_to_html(md)
        self.assertIn("<h1", html)
        self.assertIn("Heading 1</h1>", html)
        self.assertIn("<b>bold</b>", html)
        self.assertIn("<i>italic</i>", html)
        self.assertIn("<code>code</code>", html)
        self.assertIn("<li>Item 1</li>", html)
        self.assertIn('href="req:1"', html)
        self.assertIn('#req:1', html)
        self.assertIn('href="note:abcd-1234"', html)
        self.assertIn('<pre', html)

    def test_export_to_json(self):
        entries = [
            NotebookEntry(entry_type="NOTE", text="Note 1", tags=["tag1"], target="target1.com"),
            NotebookEntry(entry_type="TODO", text="Todo 1", tags=["tag2"], target="target2.com")
        ]
        json_str = export_to_json(entries)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["version"], 1)
        self.assertEqual(len(parsed["entries"]), 2)
        self.assertEqual(parsed["entries"][0]["text"], "Note 1")
        self.assertEqual(parsed["entries"][1]["entry_type"], "TODO")

    def test_export_to_markdown(self):
        entry = NotebookEntry(
            entry_type="HYPOTHESIS",
            text="Testing GraphQL introspection vulnerability",
            tags=["graphql", "api"],
            target="api.target.com",
            linked_requests=[{
                "label": "POST /graphql",
                "method": "POST",
                "url": "https://api.target.com/graphql",
                "raw_response_status": 200,
                "raw_request": "POST /graphql HTTP/1.1\r\n\r\n{\"query\":\"{__schema{types{name}}}\"}",
                "raw_response_headers_and_body_or_reference": "HTTP/1.1 200 OK\r\n\r\n{\"data\":{}}"
            }]
        )
        md_report = export_to_markdown([entry], title="GraphQL Audit")
        self.assertIn("# GraphQL Audit", md_report)
        self.assertIn("[HYPOTHESIS]", md_report)
        self.assertIn("api.target.com", md_report)
        self.assertIn("Testing GraphQL introspection vulnerability", md_report)
        self.assertIn("Request #req:1", md_report)
        self.assertIn("POST /graphql", md_report)

if __name__ == "__main__":
    unittest.main()
