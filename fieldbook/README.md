# Fieldbook - Research Notebook for Bug Bounty Hunters

Fieldbook is a fast, standalone Jython 2.7 Burp Suite extension research notebook designed for bug bounty hunters and penetration testers. Fieldbook enables seamless note-taking and evidence-linking during live testing without context-switching.

## Product Vision

Fieldbook prioritizes minimum friction to capture thoughts, hypotheses, observations, test results, and evidence. A researcher can instantly log findings and link HTTP requests directly from Proxy history, Repeater, Target site map, Logger, or Intruder.

## Key Features

1. **Context-Aware Quick Capture (`Send to Fieldbook`)**:
   - Right-click any HTTP request in Proxy history, Repeater, Target, Logger, or Intruder and select **Send to Fieldbook**.
   - Opens an always-on-top popup pre-populated with METHOD host/path request chips.
   - Text area is immediately focused. Save with `Ctrl+Enter` or cancel with `Esc`.

2. **Always Available Freestanding Quick Capture**:
   - Reachable via **Extensions > New Fieldbook Note** menu or the persistent **+ New Note** button on the Fieldbook tab.

3. **Entry Taxonomy**:
   - Color-coded entry types: `NOTE`, `OBSERVATION`, `HYPOTHESIS`, `TEST_RESULT`, and `EVIDENCE`.

4. **HTTP Request Linking & Inline References (`#req:N`)**:
   - Link zero or more HTTP requests to any note.
   - Clickable request chips open full raw HTTP request/response details in Burp's message editor.
   - Supports inline `#req:N` syntax in Markdown text, which renders as interactive jump-to-request hyperlinks in HTML preview.

5. **Live Search & Multi-Criteria Filtering**:
   - Instant live substring search across content, target, tags, and entry types.
   - Filter dropdowns by entry type, program/company target, and tags.

6. **Markdown Support & HTML Preview**:
   - Edit notes in raw Markdown (headers, bold/italic, lists, code blocks, links).
   - Render notes as styled HTML in one click.

7. **Debounced Atomic Persistence**:
   - Persists notes as a human-readable JSON file (default: `~/.fieldbook/notebook.json`).
   - Debounced auto-saving (~1s) using atomic file replacement (`.tmp` write then replace) to prevent corruption.
   - Corrupt file resilience: backs up corrupted files as `notebook.json.bak` and starts fresh without losing bad data.

8. **One-Click Export**:
   - Export notes as a structured Markdown bug report skeleton (grouped by target, chronological, quoted request references).
   - Backup notes as raw JSON.

## Technical Requirements

- **Runtime**: Jython 2.7 under Burp Suite.
- **Dependencies**: None (100% pure Python, zero C-extensions, no `sqlite3`). Completely standalone.

## Installation Instructions

1. Open **Burp Suite**.
2. Go to **Extensions** > **Installed** > **Add**.
3. Set **Extension type** to `Python`.
4. Select `fieldbook/src/Fieldbook.py` (or `fieldbook/src/FieldbookUI.py`).
5. Click **Next**. The **Fieldbook** tab will appear in Burp Suite.

## Testing

Run unit tests via CLI:
```bash
python3 fieldbook/tests/test_fieldbook_logic.py
```
Or run full suite test runner:
```bash
./scripts/test-all.sh
```
