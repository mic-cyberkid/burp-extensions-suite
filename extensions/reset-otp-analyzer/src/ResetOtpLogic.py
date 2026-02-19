import re
import sys
import os

# Add common to path
try:
    _common_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python")
    if _common_path not in sys.path: sys.path.append(_common_path)
except NameError:
    pass

from entropy_utils import calculate_shannon_entropy

class ResetOtpLogic:
    def __init__(self):
        # Patterns for reset and OTP endpoints
        self.reset_patterns = [
            r"reset", r"forgot", r"password", r"otp", r"verify", r"code", r"token"
        ]
        self.email_regex = r"[\w\.-]+@[\w\.-]+"

    def is_interesting_endpoint(self, url):
        url_lower = url.lower()
        return any(p in url_lower for p in self.reset_patterns)

    def analyze_message(self, url, headers, body):
        findings = []

        # 1. Analyze for tokens in URL/Body
        # Basic extraction of common token-like params
        token_params = ['token', 'code', 'otp', 'reset_token', 'verification_code']
        found_tokens = []

        # Check URL
        for p in token_params:
            match = re.search(r"[?&]" + p + r"=([^&]+)", url)
            if match:
                found_tokens.append((p, match.group(1)))

        # Check Body (if JSON or form-encoded)
        if body:
            for p in token_params:
                # Basic search in body
                match = re.search(r"['\"]" + p + r"['\"]\s*:\s*['\"]([^'\"]+)['\"]", body)
                if match:
                    found_tokens.append((p, match.group(1)))
                match = re.search(p + r"=([^&]+)", body)
                if match:
                    found_tokens.append((p, match.group(1)))

        for param_name, token in found_tokens:
            # Entropy check
            entropy = calculate_shannon_entropy(token)
            if entropy < 3.5:
                findings.append({
                    'name': 'Weak Reset/OTP Token Entropy',
                    'severity': 'High',
                    'confidence': 'Certain',
                    'url': url,
                    'description': 'The token "{}" in parameter "{}" has low entropy ({:.2f}), making it potentially guessable.'.format(token, param_name, entropy),
                    'remediation': 'Use a cryptographically secure random number generator for tokens.'
                })

            # Check for email in token (often base64 encoded)
            email_match = re.search(self.email_regex, token)
            if email_match:
                 findings.append({
                    'name': 'Email Exposure in Reset Token',
                    'severity': 'Medium',
                    'confidence': 'Certain',
                    'url': url,
                    'description': 'The token contains an email address ({}), which may facilitate account enumeration or reveal user identities.'.format(email_match.group(0)),
                    'remediation': 'Avoid including sensitive data like email addresses in tokens.'
                })

            # Check for short OTP
            if token.isdigit() and len(token) <= 6:
                findings.append({
                    'name': 'Short/Numeric OTP Detected',
                    'severity': 'Medium',
                    'confidence': 'Certain',
                    'url': url,
                    'description': 'The OTP "{}" is short ({} digits), making it vulnerable to brute-force attacks if rate limiting is not strictly enforced.'.format(token, len(token)),
                    'remediation': 'Use longer tokens or implement strict rate limiting/account lockout.'
                })

        # 2. Host Header Poisoning check
        # Check if the Host header is reflected in the response (common in password reset links)
        # This requires comparing Host header with response body - usually done in the extender

        return findings

    def check_host_poisoning(self, host_value, response_body):
        if not response_body:
            return False
        # If the host value (or a substring if it's a domain) is found in the body
        # specifically inside something that looks like a link
        if host_value in response_body:
            return True
        return False
