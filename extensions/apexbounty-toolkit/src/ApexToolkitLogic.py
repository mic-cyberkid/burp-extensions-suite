# -*- coding: utf-8 -*-
"""
ApexToolkitLogic.py - Core pure-logic engines for ApexBountyToolkit.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import re
import json

def to_str(val):
    """
    Safely converts bytes/bytearrays/strings to str.
    """
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    try:
        return val.decode('utf-8', 'ignore')
    except Exception:
        try:
            return str(val)
        except Exception:
            return ""


class JunkFilter(object):
    """
    Configurable rule-based filter engine to prune junk requests (static assets,
    analytics, beacons, health checks) during automated sequence capture.
    """

    DEFAULT_EXCLUDED_EXTENSIONS = [
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.map', '.ttf', '.eot', '.otf', '.mp4', '.webm',
        '.mp3', '.pdf', '.zip', '.gz'
    ]

    DEFAULT_EXCLUDED_CONTENT_TYPES = [
        'text/css', 'application/javascript', 'application/x-javascript',
        'text/javascript', 'image/', 'font/', 'audio/', 'video/'
    ]

    DEFAULT_EXCLUDED_PATTERNS = [
        '/static/', '/assets/', '/_next/', '/cdn/', '/favicon',
        'analytics', 'beacon', 'websocket', '/health', '/metrics', '/ping'
    ]

    def __init__(self, config=None):
        self.config = {
            'enabled': True,
            'filter_extensions': True,
            'excluded_extensions': list(self.DEFAULT_EXCLUDED_EXTENSIONS),
            'filter_content_types': True,
            'excluded_content_types': list(self.DEFAULT_EXCLUDED_CONTENT_TYPES),
            'filter_patterns': True,
            'excluded_patterns': list(self.DEFAULT_EXCLUDED_PATTERNS),
            'interesting_only': False
        }
        if config and isinstance(config, dict):
            self.config.update(config)

    def is_junk(self, method, path, content_type="", url_str="", status_code=200):
        if not self.config.get('enabled', True):
            return False, "Filter disabled"

        path_lower = path.lower() if path else ""
        ct_lower = content_type.lower() if content_type else ""
        method_upper = method.upper() if method else "GET"

        # Check interesting only mode
        if self.config.get('interesting_only', False):
            is_post_put_delete = method_upper in ('POST', 'PUT', 'DELETE', 'PATCH')
            is_api = '/api/' in path_lower or 'graphql' in path_lower
            is_non_2xx = status_code and not (200 <= status_code < 300)
            if not (is_post_put_delete or is_api or is_non_2xx):
                return True, "Filtered: Not in interesting-only scope"

        # Check extensions
        if self.config.get('filter_extensions', True):
            for ext in self.config.get('excluded_extensions', []):
                if path_lower.endswith(ext) or (ext + '?') in path_lower:
                    return True, "Filtered extension: " + ext

        # Check content types
        if self.config.get('filter_content_types', True) and ct_lower:
            for ct in self.config.get('excluded_content_types', []):
                if ct in ct_lower:
                    return True, "Filtered content-type: " + ct

        # Check patterns
        if self.config.get('filter_patterns', True):
            for pat in self.config.get('excluded_patterns', []):
                if pat in path_lower or (url_str and pat in url_str.lower()):
                    return True, "Filtered pattern: " + pat

        return False, "Keep"


class TokenExtractor(object):
    """
    Extracts tokens, CSRF values, nonces, cookies, and JSON/body key-value pairs
    from HTTP response headers and body.
    """

    TOKEN_HEADER_NAMES = [
        'set-cookie', 'authorization', 'x-csrf-token', 'x-xsrf-token',
        'x-auth-token', 'x-access-token', 'bearer', 'api-key'
    ]

    TOKEN_BODY_KEYS = [
        'csrf', 'csrf_token', 'csrftoken', 'token', 'access_token',
        'auth_token', 'nonce', 'session', 'session_id', 'sessionid',
        'order_id', 'orderid', 'user_id', 'userid', 'xsrf', 'xsrf_token'
    ]

    @staticmethod
    def extract_tokens(response_str_or_bytes):
        result = {
            'cookies': {},
            'headers': {},
            'body_tokens': {}
        }

        if not response_str_or_bytes:
            return result

        resp_str = to_str(response_str_or_bytes)

        # Parse response headers and body
        parts = resp_str.split('\r\n\r\n', 1)
        if len(parts) < 2:
            parts = resp_str.split('\n\n', 1)

        headers_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ''

        # 1. Parse Headers
        header_lines = headers_part.splitlines()
        for line in header_lines[1:]:  # Skip status line
            if ':' in line:
                k, v = line.split(':', 1)
                k_strip = k.strip()
                v_strip = v.strip()
                k_lower = k_strip.lower()

                if k_lower == 'set-cookie':
                    cookie_pair = v_strip.split(';', 1)[0].strip()
                    if '=' in cookie_pair:
                        ck, cv = cookie_pair.split('=', 1)
                        result['cookies'][ck.strip()] = cv.strip()
                elif k_lower in TokenExtractor.TOKEN_HEADER_NAMES:
                    result['headers'][k_strip] = v_strip

        # 2. Parse Body (JSON or URL-encoded or Regex match)
        if body_part.strip():
            body_clean = body_part.strip()
            if body_clean.startswith('{') or body_clean.startswith('['):
                try:
                    json_data = json.loads(body_clean)
                    if isinstance(json_data, dict):
                        TokenExtractor._extract_json_tokens(json_data, result['body_tokens'])
                except Exception:
                    pass

            for token_key in TokenExtractor.TOKEN_BODY_KEYS:
                if token_key not in result['body_tokens']:
                    pattern = r'"' + re.escape(token_key) + r'"\s*:\s*["\']?([^"\'\s,\}\}\r\n]+)'
                    m = re.search(pattern, body_clean, re.IGNORECASE)
                    if m:
                        result['body_tokens'][token_key] = m.group(1)

        return result

    @staticmethod
    def _extract_json_tokens(json_dict, dest_dict):
        for k, v in json_dict.items():
            k_str = str(k)
            k_lower = k_str.lower()
            if any(key in k_lower for key in ['csrf', 'token', 'nonce', 'session', 'id', 'secret']):
                if isinstance(v, (str, int, float)) and v != "":
                    dest_dict[k_str] = str(v)
            elif isinstance(v, dict):
                TokenExtractor._extract_json_tokens(v, dest_dict)


class RequestMutator(object):
    """
    Substitutes extracted tokens/cookies into raw HTTP request headers/body/query.
    """

    @staticmethod
    def apply_state(request_str_or_bytes, state_dict):
        if not request_str_or_bytes or not state_dict:
            return request_str_or_bytes

        req_str = to_str(request_str_or_bytes)
        parts = req_str.split('\r\n\r\n', 1)
        delimiter = '\r\n\r\n'
        if len(parts) < 2:
            parts = req_str.split('\n\n', 1)
            delimiter = '\n\n'

        headers_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ''

        lines = headers_part.splitlines()
        if not lines:
            return request_str_or_bytes

        first_line = lines[0]
        header_lines = lines[1:]

        # 1. Update Cookies
        cookies_to_set = state_dict.get('cookies', {})
        if cookies_to_set:
            existing_cookies = {}
            new_header_lines = []
            for h in header_lines:
                if h.lower().startswith('cookie:'):
                    cookie_val = h.split(':', 1)[1].strip()
                    for pair in cookie_val.split(';'):
                        if '=' in pair:
                            ck, cv = pair.split('=', 1)
                            existing_cookies[ck.strip()] = cv.strip()
                else:
                    new_header_lines.append(h)

            existing_cookies.update(cookies_to_set)
            cookie_header_str = "Cookie: " + "; ".join(k + "=" + v for k, v in existing_cookies.items())
            new_header_lines.append(cookie_header_str)
            header_lines = new_header_lines

        # 2. Update Header tokens
        headers_to_set = state_dict.get('headers', {})
        if headers_to_set:
            new_header_lines = []
            keys_set = set(k.lower() for k in headers_to_set.keys())
            for h in header_lines:
                if ':' in h:
                    hk = h.split(':', 1)[0].strip().lower()
                    if hk in keys_set:
                        continue
                new_header_lines.append(h)
            for hk, hv in headers_to_set.items():
                new_header_lines.append(str(hk) + ": " + str(hv))
            header_lines = new_header_lines

        # 3. Update Body & URL Tokens
        body_tokens = state_dict.get('body_tokens', {})
        if body_tokens:
            if body_part.strip().startswith('{'):
                try:
                    json_data = json.loads(body_part.strip())
                    if isinstance(json_data, dict):
                        for bk, bv in body_tokens.items():
                            if bk in json_data:
                                json_data[bk] = bv
                        body_part = json.dumps(json_data)
                except Exception:
                    pass

            for bk, bv in body_tokens.items():
                if bk + '=' in body_part:
                    pattern = re.escape(bk) + r'=[^&\r\n]*'
                    replacement = bk + '=' + str(bv)
                    body_part = re.sub(pattern, replacement, body_part, count=1)

            if '?' in first_line:
                for bk, bv in body_tokens.items():
                    if bk + '=' in first_line:
                        pattern = re.escape(bk) + r'=[^&\s]*'
                        replacement = bk + '=' + str(bv)
                        first_line = re.sub(pattern, replacement, first_line, count=1)

        final_req = '\r\n'.join([first_line] + header_lines) + delimiter + body_part
        return final_req


class LogicBreakerEngine(object):
    """
    Engine for generating sequence permutations in multi-step workflows
    to discover business logic flaws and state-machine bypasses.
    """

    @staticmethod
    def generate_permutations(sequence):
        """
        Given a sequence of requests (list of dicts or objects with 'id' and 'name'),
        generates permutation test cases.
        """
        if not sequence:
            return []

        permutations = []
        n = len(sequence)

        # 1. Baseline sequence
        permutations.append({
            'name': 'Baseline (Full Sequence)',
            'description': 'Executes full sequence as recorded (1..N)',
            'sequence': list(sequence)
        })

        # 2. Skip single steps (Drop step i and carry forward state)
        for i in range(n):
            seq_copy = [item for idx, item in enumerate(sequence) if idx != i]
            if seq_copy:
                step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else 'Step ' + str(i + 1)
                permutations.append({
                    'name': 'Drop ' + str(step_name),
                    'description': 'Drops step ' + str(i + 1) + ' (' + str(step_name) + ') while carrying state forward',
                    'sequence': seq_copy,
                    'carry_state': True
                })

        # 3. Duplicate steps (Repeat step i)
        for i in range(n):
            seq_copy = list(sequence[:i+1]) + [sequence[i]] + list(sequence[i+1:])
            step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else 'Step ' + str(i + 1)
            permutations.append({
                'name': 'Duplicate ' + str(step_name),
                'description': 'Executes step ' + str(i + 1) + ' twice in succession',
                'sequence': seq_copy
            })

        # 4. Reverse sequence
        if n > 1:
            permutations.append({
                'name': 'Reverse Sequence',
                'description': 'Executes sequence in reverse order (N..1)',
                'sequence': list(reversed(sequence))
            })

        # 5. Swap adjacent steps
        if n > 1:
            for i in range(n - 1):
                seq_copy = list(sequence)
                seq_copy[i], seq_copy[i+1] = seq_copy[i+1], seq_copy[i]
                permutations.append({
                    'name': 'Swap Steps ' + str(i + 1) + ' & ' + str(i + 2),
                    'description': 'Swaps execution order of step ' + str(i + 1) + ' and step ' + str(i + 2),
                    'sequence': seq_copy
                })

        # 6. Direct step jump (Execute final step directly with injected state)
        if n > 1:
            permutations.append({
                'name': 'Jump to Final Step',
                'description': 'Executes only final step using baseline initial tokens',
                'sequence': [sequence[-1]],
                'use_baseline_state': True
            })

        # 7. Mass Assignment / Extra Parameter Injection
        for i in range(n):
            seq_copy = [dict(s) for s in sequence]
            # Mutate request bytes of step i with admin/privileged parameters
            step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else 'Step ' + str(i + 1)
            permutations.append({
                'name': 'Mass Assignment on ' + str(step_name),
                'description': 'Injects privileged parameters (role=admin, is_admin=true) into ' + str(step_name),
                'sequence': seq_copy,
                'inject_mass_assignment_idx': i
            })

        return permutations

    @staticmethod
    def analyze_differential_results(baseline_status, baseline_len, final_status, final_len, final_resp_body=""):
        """
        Compares permutation final step status and length against baseline.
        Returns differential notes and anomaly flag.
        """
        is_anomaly = False
        notes = []

        if str(final_status) != str(baseline_status):
            is_anomaly = True
            notes.append("Status diff: %s (baseline %s)" % (final_status, baseline_status))

        try:
            bl_len = int(baseline_len)
            fn_len = int(final_len)
            len_diff = abs(fn_len - bl_len)
            if len_diff > 50:
                notes.append("Length diff: %d bytes" % len_diff)
        except Exception:
            pass

        body_lower = to_str(final_resp_body).lower()
        success_keywords = ['success', 'approved', 'complete', 'confirmed', 'welcome', 'created', 'authorized']
        error_keywords = ['unauthorized', 'forbidden', 'denied', 'invalid', 'error', 'failed']

        found_success = [kw for kw in success_keywords if kw in body_lower]
        found_error = [kw for kw in error_keywords if kw in body_lower]

        if found_success and str(final_status).startswith('2'):
            notes.append("Success keywords: " + ", ".join(found_success))
            if is_anomaly:
                notes.append("POTENTIAL STATE BYPASS")
        elif found_error:
            notes.append("Error keywords: " + ", ".join(found_error))

        if not notes:
            notes.append("Identical to baseline")

        return is_anomaly, "; ".join(notes)


class LLMFuzzerEngine(object):
    """
    Engine for extracting request parameters, constructing LLM prompts,
    parsing generated payloads, and injecting payloads into requests.
    """

    @staticmethod
    def extract_parameters(request_str):
        """
        Extracts parameter names and current values from raw HTTP request string.
        Supports URL query string, URL-encoded body, and JSON body.
        """
        params = []
        if not request_str:
            return params

        lines = request_str.split('\r\n')
        if not lines or not lines[0]:
            lines = request_str.split('\n')

        first_line = lines[0] if lines else ''

        # 1. Extract URL parameters from request line (e.g. GET /path?param1=val1&param2=val2 HTTP/1.1)
        url_match = re.search(r'^[A-Z]+\s+([^\s]+)', first_line)
        if url_match:
            full_path = url_match.group(1)
            if '?' in full_path:
                query_str = full_path.split('?', 1)[1]
                for pair in query_str.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params.append({'name': k, 'value': v, 'type': 'URL'})
                    elif pair:
                        params.append({'name': pair, 'value': '', 'type': 'URL'})

        # Split headers and body
        parts = request_str.split('\r\n\r\n', 1)
        if len(parts) < 2:
            parts = request_str.split('\n\n', 1)

        if len(parts) == 2 and parts[1].strip():
            body = parts[1].strip()
            # 2. Try JSON body parsing
            if body.startswith('{') or body.startswith('['):
                try:
                    json_obj = json.loads(body)
                    if isinstance(json_obj, dict):
                        for k, v in json_obj.items():
                            params.append({'name': str(k), 'value': str(v), 'type': 'JSON'})
                except Exception:
                    pass

            # 3. Try URL-encoded body (param1=val1&param2=val2)
            if '=' in body and not body.startswith('{'):
                for pair in body.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        if not any(p['name'] == k and p['type'] == 'URL' for p in params):
                            params.append({'name': k, 'value': v, 'type': 'BODY'})

        return params

    @staticmethod
    def build_prompt(target_param, base_request_snippet=""):
        """
        Builds prompt for LLM API to request context-aware WAF bypass payloads.
        """
        prompt = (
            "You are an expert security researcher conducting authorized vulnerability testing.\n"
            "Generate 5 high-efficiency WAF bypass and security test payloads for parameter: '" + str(target_param) + "'.\n"
            "Request context snippet:\n" + str(base_request_snippet[:300]) + "\n\n"
            "Return ONLY a JSON array of string payloads, like:\n"
            "[\"payload1\", \"payload2\", \"payload3\", \"payload4\", \"payload5\"]"
        )
        return prompt

    @staticmethod
    def parse_llm_payloads(llm_response_text):
        """
        Parses LLM response to extract payload strings.
        """
        if not llm_response_text:
            return []

        # Try JSON array extraction first
        json_match = re.search(r'\[\s*".*?"\s*\]', llm_response_text, re.DOTALL)
        if json_match:
            try:
                payloads = json.loads(json_match.group(0))
                if isinstance(payloads, list):
                    return [str(p) for p in payloads]
            except Exception:
                pass

        # Fallback: line-by-line parsing
        lines = [line.strip() for line in llm_response_text.splitlines() if line.strip()]
        payloads = []
        for line in lines:
            # Clean up bullet points or numbers
            cleaned = re.sub(r'^\d+[\.\)]\s*', '', line)
            cleaned = re.sub(r'^[-\*\u2022]\s*', '', cleaned)
            cleaned = cleaned.strip('"\'`')
            if cleaned and not cleaned.startswith('{') and not cleaned.startswith('['):
                payloads.append(cleaned)

        return payloads[:10]

    @staticmethod
    def inject_payload(request_str, param_name, payload):
        """
        Injects a payload into the specified parameter in the raw HTTP request string.
        """
        if not request_str or not param_name:
            return request_str

        # 1. Handle JSON body injection
        parts = request_str.split('\r\n\r\n', 1)
        delimiter = '\r\n\r\n'
        if len(parts) < 2:
            parts = request_str.split('\n\n', 1)
            delimiter = '\n\n'

        if len(parts) == 2:
            headers, body = parts[0], parts[1]
            if body.strip().startswith('{'):
                try:
                    json_data = json.loads(body)
                    if isinstance(json_data, dict) and param_name in json_data:
                        json_data[param_name] = payload
                        new_body = json.dumps(json_data)
                        return headers + delimiter + new_body
                except Exception:
                    pass

            # 2. Handle POST body query string injection
            if param_name + '=' in body:
                pattern = re.escape(param_name) + r'=[^&\r\n]*'
                replacement = param_name + '=' + str(payload)
                new_body = re.sub(pattern, replacement, body, count=1)
                return headers + delimiter + new_body

        # 3. Handle URL query string injection
        lines = request_str.splitlines()
        if lines:
            first_line = lines[0]
            if param_name + '=' in first_line:
                pattern = re.escape(param_name) + r'=[^&\s]*'
                replacement = param_name + '=' + str(payload)
                new_first_line = re.sub(pattern, replacement, first_line, count=1)
                return request_str.replace(first_line, new_first_line, 1)

        return request_str


class RaceOrchestratorEngine(object):
    """
    Engine for multi-endpoint race condition analysis.
    """

    @staticmethod
    def classify_race_response(status_code, content_length, baseline_lengths=None):
        """
        Analyzes response status code and length to detect race anomalies.
        Returns anomaly flag (True/False) and description.
        """
        is_anomaly = False
        notes = []

        if status_code == 500:
            is_anomaly = True
            notes.append("Internal Server Error (500)")
        elif status_code >= 500:
            is_anomaly = True
            notes.append("Server Error (" + str(status_code) + ")")

        if baseline_lengths and content_length not in baseline_lengths:
            is_anomaly = True
            notes.append("Deviating Content Length (" + str(content_length) + ")")

        if not notes:
            notes.append("Normal (" + str(status_code) + ")")

        return is_anomaly, "; ".join(notes)


class PrivilegeMatrixEngine(object):
    """
    Engine for BOLA / IDOR dynamic auth privilege matrix analysis.
    """

    AUTH_HEADER_NAMES = [
        'authorization', 'cookie', 'x-auth-token', 'bearer',
        'api-key', 'x-api-key', 'session', 'x-access-token'
    ]

    @staticmethod
    def apply_role_headers(request_str, role_headers_raw):
        """
        Strips existing authorization and session headers from request_str,
        and injects new headers provided in role_headers_raw (newline-separated Header: Value).
        """
        if not request_str:
            return request_str

        parts = request_str.split('\r\n\r\n', 1)
        delimiter = '\r\n\r\n'
        if len(parts) < 2:
            parts = request_str.split('\n\n', 1)
            delimiter = '\n\n'

        headers_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ''

        lines = headers_part.splitlines()
        if not lines:
            return request_str

        first_line = lines[0]
        header_lines = lines[1:]

        # Filter out existing auth headers
        filtered_headers = []
        for line in header_lines:
            if ':' in line:
                key = line.split(':', 1)[0].strip().lower()
                if key in PrivilegeMatrixEngine.AUTH_HEADER_NAMES:
                    continue
            filtered_headers.append(line)

        # Parse and inject role headers
        role_headers_to_add = []
        if role_headers_raw:
            for line in role_headers_raw.splitlines():
                line = line.strip()
                if line and ':' in line:
                    role_headers_to_add.append(line)

        final_header_lines = [first_line] + filtered_headers + role_headers_to_add
        new_headers_part = '\r\n'.join(final_header_lines)

        return new_headers_part + delimiter + body_part

    @staticmethod
    def classify_status_code(status_code):
        """
        Returns status classification dict with color designation and tag.
        """
        if 200 <= status_code < 300:
            return {'status': 'SUCCESS', 'color': 'GREEN', 'code': status_code}
        elif status_code in (401, 403):
            return {'status': 'DENIED', 'color': 'RED', 'code': status_code}
        elif 300 <= status_code < 400:
            return {'status': 'REDIRECT', 'color': 'YELLOW', 'code': status_code}
        elif status_code >= 500:
            return {'status': 'ERROR', 'color': 'ORANGE', 'code': status_code}
        else:
            return {'status': 'OTHER', 'color': 'GRAY', 'code': status_code}
