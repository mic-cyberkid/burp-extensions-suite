# Auth Bypass and Session Analyzer

The Auth Bypass and Session Analyzer focuses on identifying vulnerabilities in authentication mechanisms and session management.

## Features
- **JWT Analysis**:
    - Automatically decodes JWTs from headers and cookies.
    - Flags dangerous configurations like `alg: none`.
    - Detects potential key confusion vulnerabilities.
- **Session Entropy Analysis**:
    - Calculates Shannon entropy for all detected session tokens.
    - Flags low-entropy or sequential tokens that might be predictable.
- **IDOR Simulation**:
    - Adds a context menu to Burp (Proxy history/Editor) to "Generate IDOR Mutants".
    - Automatically identifies ID-like parameters (`id`, `user_id`, etc.) and suggests mutations for testing (e.g., increment/decrement).
- **Consolidated UI**: Displays analysis results in a dedicated "Auth Analyzer" tab.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `IContextMenuFactory`, `ITab`).
- **Logic**: Pure Python implementation for JWT decoding and entropy calculation.

## How to Use
1. Load the extension via `extensions/auth-analyzer/src/AuthAnalyzer.py`.
2. As you browse, check the "Auth Analyzer" tab for token analysis results.
3. Right-click any request in Proxy or Repeater and select "Generate IDOR Mutants" to see suggested IDOR test cases in the extension console/alerts.
