# Auth and Session Analysis Logic

import base64
import json
import math
import sys
import os

# Add common to path
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))
from entropy_utils import calculate_shannon_entropy

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

    def analyze_session_token(self, token):
        findings = []
        entropy = calculate_shannon_entropy(token)

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

    def compare_responses(self, resp1, resp2):
        """
        Compares two responses for the Multi-Session Matrix.
        Returns a result indicating if they are similar.
        """
        if not resp1 or not resp2:
            return "Error"

        # Simple comparison: Status code and Length
        if resp1.getStatusCode() != resp2.getStatusCode():
            return "Different (Status)"

        len1 = len(resp1.getResponse())
        len2 = len(resp2.getResponse())
        diff = abs(len1 - len2)
        if diff > (max(len1, len2) * 0.1):
            return "Different (Length)"

        return "Same"

    def analyze_token_collection(self, tokens):
        """
        Statistical analysis for Token Oracle.
        """
        if not tokens:
            return "No tokens"

        count = len(tokens)
        entropies = [calculate_shannon_entropy(t) for t in tokens]
        avg_entropy = sum(entropies) / count

        unique_count = len(set(tokens))
        predictability = "High" if unique_count < count * 0.9 else "Low"

        return {
            'count': count,
            'avg_entropy': avg_entropy,
            'unique': unique_count,
            'predictability': predictability
        }
