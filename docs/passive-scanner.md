# Passive Vulnerability Scanner

The Passive Vulnerability Scanner automatically analyzes HTTP responses captured by Burp's Proxy to identify missing or weak security headers and common misconfigurations.

## Features
- **Automatic Analysis**: Works in the background without user intervention.
- **Security Header Checks**:
    - Missing `Content-Security-Policy` (CSP)
    - Missing `Strict-Transport-Security` (HSTS)
    - Missing `X-Frame-Options` (Clickjacking protection)
    - Missing/Incorrect `X-Content-Type-Options` (MIME sniffing)
    - Permissive `Access-Control-Allow-Origin: *` (CORS)
- **Custom Tab**: Displays all findings in a dedicated "Passive Scanner" tab with details on severity, confidence, and remediation tips.
- **Alert Integration**: Sends alerts to Burp's "Alerts" tab for quick notification.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `ITab`).
- **UI**: Java Swing components.

## How to Use
1. Load the extension by selecting `extensions/passive-scanner/src/PassiveScanner.py` in Burp's Extender tab.
2. Browse the target application through Burp's Proxy.
3. Check the "Passive Scanner" tab for findings.
