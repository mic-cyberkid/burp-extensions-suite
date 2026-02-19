# Reset/OTP Weakness & Poisoning Analyzer

This extension focuses on identifying high-impact vulnerabilities in password reset and OTP (One-Time Password) mechanisms.

## Features

### Passive Analysis
- **Token Entropy**: Calculates Shannon entropy for reset tokens and OTPs. Flags tokens with low entropy (<3.5 bits/char).
- **Sensitive Data Exposure**: Detects if email addresses or other sensitive patterns are leaked within reset tokens.
- **OTP Brute-Force Risk**: Identifies short (<=6 digits) numeric OTPs that are susceptible to brute-forcing.
- **Host Header Poisoning**: Automatically detects if the `Host` header is reflected in responses from reset/OTP endpoints, indicating a potential for password reset poisoning.

### Semi-Active Testing
- **Poison Host Probe**: Provides a quick way to identify if the application is vulnerable to Host header poisoning by suggesting manual probes in Repeater.
- **Unified Reporting**: Automatically feeds findings into the global **Report Generator** if it is loaded.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `ITab`).
- **Dependencies**: Uses shared `entropy_utils.py` and `burp_shared.py`.

## How to Use
1. Load the extension via `extensions/reset-otp-analyzer/src/ResetOtpAnalyzer.py`.
2. Browse the application, specifically interacting with password reset and login (MFA) flows.
3. Check the **Reset/OTP** tab for findings.
4. For any flagged endpoint, use the **Poison Host Probe** to verify vulnerability in Repeater by changing the `Host` header and checking the response.
