# Passive Scanner Logic for security headers

class ScannerLogic:
    def __init__(self):
        self.issues = []

    def analyze_response(self, url, status_code, headers):
        """
        Analyzes response headers for missing or weak security configurations.
        Returns a list of identified issues.
        """
        findings = []
        header_map = {k.lower(): v for k, v in headers.items()}

        # 1. Content-Security-Policy
        if 'content-security-policy' not in header_map:
            findings.append({
                'name': 'Missing Content-Security-Policy',
                'severity': 'Medium',
                'confidence': 'Certain',
                'description': 'The response does not contain a Content-Security-Policy (CSP) header, which helps prevent XSS and data injection attacks.',
                'remediation': 'Implement a strong CSP header.'
            })

        # 2. HTTP Strict-Transport-Security (HSTS)
        if 'strict-transport-security' not in header_map:
            findings.append({
                'name': 'Missing HSTS Header',
                'severity': 'Low',
                'confidence': 'Certain',
                'description': 'The Strict-Transport-Security header is missing, which may allow SSL stripping attacks.',
                'remediation': 'Add the Strict-Transport-Security header to all HTTPS responses.'
            })

        # 3. X-Frame-Options
        if 'x-frame-options' not in header_map and 'content-security-policy' not in header_map:
             findings.append({
                'name': 'Missing X-Frame-Options',
                'severity': 'Low',
                'confidence': 'Certain',
                'description': 'The X-Frame-Options header is missing, making the site vulnerable to clickjacking if CSP frame-ancestors is also missing.',
                'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN.'
            })

        # 4. X-Content-Type-Options
        if header_map.get('x-content-type-options', '').lower() != 'nosniff':
            findings.append({
                'name': 'Missing or Incorrect X-Content-Type-Options',
                'severity': 'Low',
                'confidence': 'Certain',
                'description': 'The X-Content-Type-Options header should be set to "nosniff" to prevent MIME-type sniffing.',
                'remediation': 'Add X-Content-Type-Options: nosniff.'
            })

        # 5. Permissive CORS
        cors_origin = header_map.get('access-control-allow-origin', '')
        if cors_origin == '*':
             findings.append({
                'name': 'Permissive CORS Policy',
                'severity': 'Medium',
                'confidence': 'Certain',
                'description': 'The Access-Control-Allow-Origin header is set to "*", which may allow unauthorized cross-origin access.',
                'remediation': 'Restrict Access-Control-Allow-Origin to trusted domains.'
            })

        return findings
