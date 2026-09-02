# Fieldbook — Research Notebook for Bug Bounty Hunters

Fieldbook is an independent, low-friction research notebook Burp Suite extension built to eliminate note-taking friction during active pentests and bug bounty hunting.

---

## Highlights & Key Features

- **Fast Capture (< 5 seconds):**
  - **Context Menu Integration:** Right-click any request/response in Proxy History, Repeater, Target Site Map, or Logger and choose `"Send to Fieldbook"`. Select multiple requests to capture them into a single note as linked HTTP request snapshots!
  - **Global Hotkey:** Press `Ctrl+Shift+N` (or `Cmd+Shift+N` on macOS) anywhere inside Burp Suite to instantly open the Quick Capture dialog.
  - **Ctrl+Enter Quick Save:** Type thoughts in Quick Capture or Main Compose and press `Ctrl+Enter` to save immediately.

- **Split-Pane Research Dashboard:**
  - **Live Multi-Factor Filter:** Filter notes instantly by keyword query, entry type (`NOTE`, `OBSERVATION`, `HYPOTHESIS`, `TEST_RESULT`, `EVIDENCE`, `TODO`), target host, tag, or pinned status.
  - **Color-Coded Chips:** Visual color badges for entry types to scan notes quickly.
  - **Off-EDT Performance:** Asynchronous thread queries remain butter-smooth even with 1,000+ notes.

- **Markdown & HTTP Request Inspector:**
  - **Lightweight Markdown Rendering:** Automatic HTML rendering for headings, bold, italics, code blocks, lists, and links.
  - **Deep Linking Tokens:** `#req:N` tokens automatically link directly to attached HTTP request/response snapshots.
  - **HTTP Request Viewer:** Click attached request summaries to inspect raw request & response headers and body.

- **Thread-Safe & Lossless Storage:**
  - Persistent JSON file stored at `~/.fieldbook/notebook.json` (outside the repository).
  - Atomic temporary file writes to prevent corruption on crash.
  - Automatic corrupted file backup (`.corrupt.TIMESTAMP`) and clean recovery.

---

## Installation & Setup in Burp Suite

### Prerequisites
- Burp Suite Community or Professional.
- Jython Standalone JAR (version 2.7.x): [Download Jython 2.7.3 Standalone JAR](https://www.jython.org/download).

### Loading Fieldbook
1. Open Burp Suite.
2. Go to **Extensions** > **Options** (or **Extender** > **Options**).
3. Under **Python Environment**, click **Select file ...** and select your downloaded `jython-standalone-2.7.x.jar`.
4. Go to **Extensions** > **Installed** (or **Extender** > **Extensions**).
5. Click **Add**.
6. Set **Extension type** to **Python**.
7. Click **Select file ...** and choose `fieldbook/src/FieldbookExtender.py` from this repository.
8. Click **Next**. You should see `"Fieldbook Research Notebook loaded successfully!"` in the output window.
9. A new tab named **Fieldbook** will appear in Burp Suite.

---

## Keyboard Shortcuts

| Shortcut | Description |
|---|---|
| `Ctrl+Shift+N` / `Cmd+Shift+N` | Open Quick Capture Dialog from any Burp tab |
| `Ctrl+Enter` / `Cmd+Enter` | Save Note in Quick Capture or Edit view |
| `Up / Down` | Navigate note list in Fieldbook tab |
| `Enter` | Open selected note detail in Fieldbook tab |

---

## Testing & Automation

Run Fieldbook unit tests headlessly via Python 3:
```bash
PYTHONPATH=. python3 fieldbook/tests/test_notebook_model.py
PYTHONPATH=. python3 fieldbook/tests/test_markdown_and_export.py
PYTHONPATH=. python3 fieldbook/tests/test_context_menu.py
PYTHONPATH=. python3 fieldbook/tests/test_search_performance.py
```
Or run the full test suite script:
```bash
./scripts/test-all.sh
```
