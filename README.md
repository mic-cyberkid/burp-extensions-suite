# Burp Suite Extensions Suite

A collection of five custom Burp Suite extensions designed for high-grade web application vulnerability assessment. This suite includes tools for passive scanning, parameter fuzzing, auth analysis, custom decoding, and reporting.

## Extensions Overview

1.  **Passive Vulnerability Scanner** (Python/Legacy API): Analyzes responses for missing/weak security headers and misconfigurations.
2.  **Automated Parameter Fuzzer** (Java/Montoya API): Smart fuzzing for injection vulnerabilities like SQLi and XSS with anomaly detection.
3.  **Auth Bypass and Session Analyzer** (Python/Legacy API): Enhanced with a Multi-Session Role Matrix and Token Oracle for bulk predictability analysis.
4.  **Custom Decoder/Encoder** (Java/Montoya API): A flexible framework for handling non-standard data formats (XOR, Custom Base64, etc.) with auto-detection.
5.  **Report Generator and Vulnerability Tracker** (Python/Legacy API): Aggregates findings from all extensions, tracks them across sessions, and exports reports in Markdown/HTML.
6.  **Reset/OTP Weakness & Poisoning Analyzer** (Python/Legacy API): Specialized tool for identifying flaws in password reset and OTP flows, including Host header poisoning.
7.  **Logic Flaw & State Machine Visualizer** (Java/Montoya API): Visualizes application state transitions to identify logical bypasses and step-skipping vulnerabilities.
8.  **JS Link & Secret Miner** (Python/Legacy API): Extracts endpoints and sensitive secrets (API keys, tokens) from JavaScript files.
9.  **Cloud Metadata & Bucket Hunter** (Python/Legacy API): Identifies leaked cloud infrastructure details and metadata service endpoints.
10. **Fingerprinting & Tech Stack Detector** (Python/Legacy API): Automatically identifies the application's technology stack from headers, cookies, and content.
11. **GraphQL Security Auditor** (Python/Legacy API): Scans for common GraphQL misconfigurations (introspection enabled) and sensitive field exposure.
12. **API Documentation & Swagger Miner** (Python/Legacy API): Automatically discovers and maps API documentation (Swagger/OpenAPI) and extracts endpoints.
13. **Subdomain Takeover & CNAME Hunter** (Python/Legacy API): Passively checks for CNAMEs pointing to potentially unclaimed services (e.g., S3, Heroku, Github Pages).

## Project Structure

```text
burp-extensions-suite/
├── docs/                   # Detailed documentation for each extension
├── common/                 # Shared utilities for Java and Python
├── extensions/             # Core extension source code
├── scripts/                # Build and test scripts
└── .github/                # CI/CD workflows
```

## Installation

### Java Extensions (Montoya API)
Requires Maven and JDK 17+.
1. Navigate to the extension directory (e.g., `extensions/param-fuzzer`).
2. Run `mvn package`.
3. In Burp: `Extensions` > `Installed` > `Add`. Select `Java` and the generated `.jar` file from the `target` directory.

### Python Extensions (Legacy API)
Requires Burp Suite with Jython configured.
1. In Burp: `Extensions` > `Installed` > `Add`.
2. Select `Python` and the main `.py` file (e.g., `extensions/passive-scanner/src/PassiveScanner.py`).

## Development

- **Java**: Uses Maven and JUnit 5.
- **Python**: Uses Jython 2.7 compatible code and `unittest`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
