# JS Link & Secret Miner

This extension passively scans JavaScript files to identify hidden endpoints, hardcoded API keys, and sensitive secrets.

## Features
- **Secret Extraction**: Automatically detects common patterns for secrets including AWS keys, Google API keys, Slack webhooks, Stripe keys, and more.
- **Endpoint Discovery**: Extracts relative and absolute paths from JS files to help map the application's attack surface.
- **Passive Monitoring**: Works in the background as you browse the application.
- **Custom Tab**: Displays all discovered secrets and endpoints in a dedicated "JS Miner" tab.
- **Reporting**: Integrates with the global **Report Generator** to log high-severity findings for detected secrets.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `ITab`).
- **Regex-based**: Uses a curated list of regular expressions for high-fidelity detection.

## How to Use
1. Load the extension via `extensions/js-miner/src/JSMiner.py`.
2. Browse the target application.
3. Check the **JS Miner** tab for discovered assets.
4. Review the extension console or the **Tracker** tab for any high-severity secret findings.
