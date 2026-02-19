import re
import json

class APIMinerLogic:
    def __init__(self):
        self.doc_paths = [
            r"swagger\.json",
            r"swagger-ui\.html",
            r"v2/api-docs",
            r"v3/api-docs",
            r"api-docs",
            r"openapi\.json",
            r"api/swagger\.json",
            r"swagger/index\.html"
        ]

    def is_api_doc(self, url):
        url_lower = url.lower()
        return any(re.search(p, url_lower) for p in self.doc_paths)

    def extract_endpoints(self, body):
        endpoints = set()
        try:
            data = json.loads(body)
            # Swagger v2
            if "paths" in data:
                for path in data["paths"]:
                    endpoints.add(path)
            # OpenAPI v3
            if "openapi" in data and "paths" in data:
                for path in data["paths"]:
                    endpoints.add(path)
        except:
            # Fallback to regex for non-JSON or malformed Swagger
            matches = re.finditer(r"['\"](/[a-zA-Z0-9_\-/]+)[\"']", body)
            for match in matches:
                endpoints.add(match.group(1))

        return sorted(list(endpoints))

    def analyze_response(self, url, body):
        findings = []
        if self.is_api_doc(url):
            endpoints = self.extract_endpoints(body)
            findings.append({
                'name': 'API Documentation Discovered',
                'severity': 'Information',
                'confidence': 'Certain',
                'url': url,
                'description': 'Discovered API documentation at {}. Extracted {} potential endpoints.'.format(url, len(endpoints)),
                'remediation': 'Ensure API documentation is not publicly accessible in production unless intended.'
            })
        return findings
