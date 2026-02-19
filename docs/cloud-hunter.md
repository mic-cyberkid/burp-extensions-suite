# Cloud Metadata & Bucket Hunter

This extension passively scans HTTP responses for leaked cloud infrastructure details, such as metadata service IPs and cloud storage bucket names.

## Features
- **Cloud Metadata Detection**: Identifies references to AWS, GCP, and Azure metadata endpoints (e.g., `169.254.169.254`), which can indicate potential SSRF vulnerabilities.
- **Bucket Identification**: Scans for S3 buckets, Azure Blobs, and Google Cloud Storage paths.
- **Automated Alerts**: Generates Burp alerts when high-impact infrastructure leaks are detected.
- **Reporting**: Feeds findings to the global **Report Generator**.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`).
- **High-Fidelity Patterns**: Focuses on specific cloud-provider domains and IPs.

## How to Use
1. Load the extension via `extensions/cloud-hunter/src/CloudHunter.py`.
2. Browse the application.
3. Check Burp's **Alerts** tab or the extension **Tracker** for cloud-related findings.
