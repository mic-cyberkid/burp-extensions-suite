# Auth and Session Analysis Logic

import base64
import json
import math

class AuthLogic:
    def decode_jwt(self, token):
        """
        Decodes a JWT without verification.
        Returns (header, payload, signature) or None if invalid.
        """
        parts = token.split('.')
        if len(parts) != 3:
            return None

        try:
            def decode_part(part):
                # Add padding if necessary
                missing_padding = len(part) % 4
                if missing_padding:
                    part += '=' * (4 - missing_padding)
                return json.loads(base64.b64decode(part.replace('-', '+').replace('_', '/')))

            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            signature = parts[2]
            return header, payload, signature
        except Exception:
            return None

    def analyze_jwt(self, token):
        """
        Checks for common JWT vulnerabilities.
        """
        decoded = self.decode_jwt(token)
        if not decoded:
            return []

        header, payload, signature = decoded
        findings = []

        if header.get('alg', '').lower() == 'none':
            findings.append({
                'name': 'JWT alg:none Accepted',
                'severity': 'High',
                'description': 'The JWT uses "alg": "none", which means the signature is not verified.'
            })

        # Key confusion indicators (e.g., HS256 with RS256-like payload)
        # This is a bit speculative without active testing, but we can flag it.
        if header.get('alg') == 'HS256' and ('exp' not in payload or 'iat' not in payload):
             findings.append({
                'name': 'Potential JWT Key Confusion',
                'severity': 'Medium',
                'description': 'The JWT uses HS256 but lacks common claims, which might indicate a key confusion vulnerability.'
            })

        return findings

    def calculate_entropy(self, data):
        """
        Calculates Shannon entropy of a string.
        """
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def analyze_session_token(self, token):
        findings = []
        entropy = self.calculate_entropy(token)

        if entropy < 3.0 and len(token) > 8:
            findings.append({
                'name': 'Low Session Token Entropy',
                'severity': 'Medium',
                'description': 'The session token has low entropy ({:.2f}), suggesting it might be predictable.'.format(entropy)
            })

        # Check for incrementing patterns (basic check)
        if token.isdigit():
             findings.append({
                'name': 'Numeric/Sequential Session Token',
                'severity': 'Low',
                'description': 'The session token is entirely numeric, which may indicate it is sequential and predictable.'
            })

        return findings, entropy

    def mutate_id_params(self, params):
        """
        Suggests mutated parameters for IDOR testing.
        """
        id_keywords = ['id', 'user_id', 'userid', 'uid', 'accountid', 'doc_id']
        mutations = []
        for k, v in params.items():
            if k.lower() in id_keywords:
                if v.isdigit():
                    # Increment/Decrement
                    mutations.append({k: str(int(v) + 1)})
                    mutations.append({k: str(int(v) - 1)})
                else:
                    # Try common variations
                    mutations.append({k: '1'})
                    mutations.append({k: 'admin'})
        return mutations
