# Subdomain Takeover & CNAME Hunter

This extension passively scans HTTP responses for signatures indicating that a subdomain is pointing to an unclaimed or misconfigured cloud service, which could allow for a subdomain takeover.

## Features
- **Service Fingerprinting**: Detects common error pages and strings associated with GitHub Pages, Heroku, AWS S3, Azure, Fastly, and more.
- **High-Severity Alerts**: Generates Burp alerts for potential takeover vulnerabilities.
- **Passive Monitoring**: Works automatically as you browse the target application and its subdomains.
- **Reporting**: Feeds findings to the global **Report Generator**.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`).
- **Signature-based**: Uses a list of known patterns for various cloud providers.

## How to Use
1. Load the extension via `extensions/subdomain-hunter/src/SubdomainHunter.py`.
2. Browse the application and any associated subdomains.
3. Check Burp's **Alerts** tab or the extension **Tracker** for potential takeover findings.
