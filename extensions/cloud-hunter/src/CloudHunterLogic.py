import re

class CloudHunterLogic:
    def __init__(self):
        # Patterns for cloud metadata and buckets
        self.patterns = {
            "AWS Metadata": r"169\.254\.169\.254",
            "AWS S3 Bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com",
            "Azure Blob Storage": r"[a-z0-9.-]+\.blob\.core\.windows\.net",
            "Google Cloud Storage": r"storage\.googleapis\.com/[a-z0-9.-]+",
            "GCP Metadata": r"metadata\.google\.internal"
        }

    def analyze_content(self, url, content):
        findings = []
        for name, pattern in self.patterns.items():
            if re.search(pattern, content):
                severity = "Medium"
                if "169.254" in pattern or "internal" in pattern:
                    severity = "High"

                findings.append({
                    'name': 'Cloud Infrastructure Leak: ' + name,
                    'severity': severity,
                    'confidence': 'Firm',
                    'url': url,
                    'description': 'The response at {} contains a reference to cloud infrastructure ({}). This could lead to sensitive data exposure or SSRF.'.format(url, name),
                    'remediation': 'Ensure that internal infrastructure details and cloud bucket names are not exposed in client-side responses. Secure cloud buckets with proper IAM policies.'
                })
        return findings
