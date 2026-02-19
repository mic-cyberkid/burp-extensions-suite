import re
import json

class GraphQLLogic:
    def __init__(self):
        self.introspection_query = "{__schema{queryType{name}}}"
        self.sensitive_fields = ["password", "secret", "token", "email", "phone", "admin", "role", "key"]

    def is_graphql_request(self, url, body):
        if "/graphql" in url.lower():
            return True
        if body and ("query" in body or "mutation" in body):
            return True
        return False

    def analyze_response(self, url, body):
        findings = []
        if not body:
            return findings

        # Check for enabled Introspection
        if "__schema" in body and "queryType" in body:
            findings.append({
                'name': 'GraphQL Introspection Enabled',
                'severity': 'Medium',
                'confidence': 'Certain',
                'url': url,
                'description': 'GraphQL introspection is enabled, allowing attackers to map the entire schema.',
                'remediation': 'Disable introspection in production environments.'
            })

        # Check for sensitive fields in response
        try:
            data = json.loads(body)
            # Recursive check for sensitive keys
            found_sensitive = self._find_sensitive_keys(data)
            if found_sensitive:
                findings.append({
                    'name': 'GraphQL Sensitive Data Exposure',
                    'severity': 'Low',
                    'confidence': 'Firm',
                    'url': url,
                    'description': 'Found potentially sensitive fields in GraphQL response: {}'.format(", ".join(found_sensitive)),
                    'remediation': 'Ensure that only necessary data is returned and sensitive fields are protected by proper authorization.'
                })
        except:
            pass

        return findings

    def _find_sensitive_keys(self, obj, found=None):
        if found is None: found = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                if any(s in k.lower() for s in self.sensitive_fields):
                    found.add(k)
                self._find_sensitive_keys(v, found)
        elif isinstance(obj, list):
            for item in obj:
                self._find_sensitive_keys(item, found)
        return found
