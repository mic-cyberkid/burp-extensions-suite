import re

class TakeoverLogic:
    def __init__(self):
        # Service fingerprints indicating potential takeover
        # Based on common knowledge (e.g., Can-I-take-over-xyz)
        self.fingerprints = {
            "GitHub Pages": {
                "pattern": r"There isn't a GitHub Pages site here",
                "severity": "High"
            },
            "Heroku": {
                "pattern": r"herokucdn\.com/error-pages/no-such-app\.html|no such app",
                "severity": "High"
            },
            "S3 Bucket": {
                "pattern": r"The specified bucket does not exist|NoSuchBucket",
                "severity": "High"
            },
            "Azure": {
                "pattern": r"The resource you are looking for has been removed, had its name changed, or is temporarily unavailable",
                "severity": "Medium"
            },
            "Fastly": {
                "pattern": r"Fastly error: unknown domain",
                "severity": "High"
            },
            "Ghost": {
                "pattern": r"The thing you were looking for is no longer here",
                "severity": "High"
            }
        }

    def analyze_response(self, url, body):
        findings = []
        if not body:
            return findings

        for service, data in self.fingerprints.items():
            if re.search(data["pattern"], body, re.IGNORECASE):
                findings.append({
                    'name': 'Potential Subdomain Takeover: ' + service,
                    'severity': data["severity"],
                    'confidence': 'Firm',
                    'url': url,
                    'description': 'The response at {} contains a signature ({}) associated with a missing or misconfigured {} service. This often indicates that the subdomain can be taken over.'.format(url, data["pattern"], service),
                    'remediation': 'Remove the DNS record (CNAME/A) pointing to the unclaimed service or claim the service.'
                })
        return findings
