# Burp Suite Extensions Suite

A collection of five custom Burp Suite extensions designed for high-grade web application vulnerability assessment. This suite includes tools for passive scanning, parameter fuzzing, auth analysis, custom decoding, and reporting.

## Extensions Overview

1.  **Passive Vulnerability Scanner** (Python/Legacy API): Analyzes responses for missing/weak security headers and misconfigurations.
2.  **Automated Parameter Fuzzer** (Java/Montoya API): Smart fuzzing for injection vulnerabilities like SQLi and XSS with anomaly detection.
3.  **Auth Bypass and Session Analyzer** (Python/Legacy API): Analyzes session tokens (including JWTs), checks entropy, and simulates IDOR attacks.
4.  **Custom Decoder/Encoder** (Java/Montoya API): A flexible framework for handling non-standard data formats (XOR, Custom Base64, etc.) with auto-detection.
5.  **Report Generator and Vulnerability Tracker** (Python/Legacy API): Aggregates findings, tracks them across sessions, and exports reports in Markdown/HTML.

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
