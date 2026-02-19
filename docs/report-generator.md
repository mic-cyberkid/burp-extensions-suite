# Report Generator and Vulnerability Tracker

The Report Generator and Vulnerability Tracker is a central tool for managing, tracking, and reporting security findings during a penetration test.

## Features
- **Vulnerability Tracking**: Persistently stores findings across Burp sessions using a JSON file.
- **Aggregation**: Collects findings from other extensions or manual entry.
- **Reporting**:
    - **Markdown**: Generates a clean, professional report in Markdown format.
    - **HTML**: Generates an interactive HTML report with summary tables and detailed descriptions.
- **Management UI**: A dedicated "Tracker" tab to view, refresh, and clear findings.
- **Persistence**: Automatically saves findings to `~/burp_vuln_tracker.json`.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `ITab`, `IExtensionStateListener`).
- **Storage**: Local JSON file.

## How to Use
1. Load the extension via `extensions/report-generator/src/ReportGenerator.py`.
2. As vulnerabilities are identified (either automatically by other extensions or through manual analysis), they can be tracked here.
3. Open the **Tracker** tab to see all recorded findings.
4. Click **Export Markdown** or **Export HTML** to generate a report for the client.
