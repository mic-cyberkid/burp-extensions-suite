import re

class JSMinerLogic:
    def __init__(self):
        # Regex for secrets and sensitive data
        self.secret_patterns = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"['\"]([0-9a-zA-Z/+]{40})['\"]",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "Generic Bearer Token": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            "Github Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
            "Stripe API Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}"
        }
        # Regex for endpoint discovery (relative and absolute paths)
        self.endpoint_pattern = r"['\"]((?:/|\.\./|\./)[a-zA-Z0-9_\-/]+\.[a-z]{2,5}|(?:/|\.\./|\./)[a-zA-Z0-9_\-/]+)[\"']"

    def extract_secrets(self, content):
        findings = []
        for name, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    "type": "Secret",
                    "name": name,
                    "value": match.group(0)
                })
        return findings

    def extract_endpoints(self, content):
        endpoints = set()
        matches = re.finditer(self.endpoint_pattern, content)
        for match in matches:
            endpoints.add(match.group(1))
        return list(endpoints)

    def analyze_js(self, url, content):
        findings = []
        secrets = self.extract_secrets(content)
        for s in secrets:
            findings.append({
                'name': 'Potential Secret Found in JS: ' + s['name'],
                'severity': 'High',
                'confidence': 'Firm',
                'url': url,
                'description': 'Found a potential sensitive string: {}. This was discovered in the JavaScript file at {}.'.format(s['value'], url),
                'remediation': 'Remove sensitive API keys and secrets from client-side code. Use environment variables or secure backend proxying.'
            })

        endpoints = self.extract_endpoints(content)
        if endpoints:
            findings.append({
                'name': 'Endpoints Discovered in JS',
                'severity': 'Information',
                'confidence': 'Certain',
                'url': url,
                'description': 'Found {} endpoints/paths in the JavaScript file: \n{}'.format(len(endpoints), "\n".join(list(endpoints)[:10]) + "..."),
                'remediation': 'Review discovered endpoints for hidden functionality or insecure API paths.'
            })

        return findings
