# -*- coding: utf-8 -*-
"""
ApexToolkitLogic.py - Core pure-logic engines for ApexBountyToolkit.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import re
import json

class NoiseFilter(object):
    """
    Filter for stripping telemetry, static assets, and noisy endpoints
    from HTTP request sequences.
    """
    STATIC_EXTENSIONS = (
        '.js', '.css', '.woff', '.woff2', '.ttf', '.eot', '.svg',
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.map'
    )

    DEFAULT_NOISE_PATTERNS = [
        r'/api/metrics',
        r'/ping',
        r'/analytics',
        r'/telemetry',
        r'/log',
        r'/health',
        r'\.(js|css|woff2?|ttf|svg|png|jpg|jpeg|gif|ico)(\?.*)?$'
    ]

    @staticmethod
    def should_filter(url_or_path, mime_type='', custom_regex_pattern=''):
        """
        Returns True if request should be filtered out as noise/telemetry/static asset.
        """
        if not url_or_path:
            return False

        clean_url = url_or_path.split('?')[0].split('#')[0].lower()

        # Check static extensions
        for ext in NoiseFilter.STATIC_EXTENSIONS:
            if clean_url.endswith(ext):
                return True

        # Check MIME type
        if mime_type:
            mime = mime_type.lower()
            if any(m in mime for m in ['script', 'css', 'font', 'image', 'svg']):
                return True

        # Check default noise patterns
        for pattern in NoiseFilter.DEFAULT_NOISE_PATTERNS:
            try:
                if re.search(pattern, url_or_path, re.IGNORECASE):
                    return True
            except Exception:
                pass

        # Check custom user regex
        if custom_regex_pattern:
            try:
                if re.search(custom_regex_pattern, url_or_path, re.IGNORECASE):
                    return True
            except Exception:
                pass

        return False


class CorrelationEngine(object):
    """
    Engine for analyzing response body/headers of Step N and mapping dynamically
    generated tokens, UUIDs, or JSON parameters to Step N+1 request parameters.
    """

    TOKEN_KEYS = [
        'token', 'access_token', 'id_token', 'csrf', 'csrftoken', 'csrf_token',
        'xsrf_token', 'auth_token', 'session', 'session_id', 'uuid', 'id',
        'user_id', 'account_id', 'order_id', 'item_id', 'cart_id', 'transaction_id'
    ]

    UUID_REGEX = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    JWT_REGEX = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'

    @staticmethod
    def extract_tokens(response_headers_str, response_body_str):
        """
        Extracts key-value token mappings from response headers and response body.
        Returns a dictionary: {token_key: token_value}
        """
        token_map = {}
        if not response_headers_str and not response_body_str:
            return token_map

        # 1. Extract from Headers (Cookies & Custom Auth Headers)
        if response_headers_str:
            lines = response_headers_str.splitlines()
            for line in lines:
                if ':' in line:
                    header, value = line.split(':', 1)
                    header_lower = header.strip().lower()
                    val_str = value.strip()

                    if header_lower == 'set-cookie':
                        cookie_part = val_str.split(';')[0]
                        if '=' in cookie_part:
                            ck_key, ck_val = cookie_part.split('=', 1)
                            ck_key = ck_key.strip()
                            ck_val = ck_val.strip()
                            if ck_key and ck_val:
                                token_map[ck_key] = ck_val
                                token_map['Cookie:' + ck_key] = ck_val

                    elif any(k in header_lower for k in ['token', 'auth', 'csrf', 'xsrf', 'jwt']):
                        token_map[header.strip()] = val_str

        # 2. Extract from JSON Response Body
        if response_body_str and (response_body_str.strip().startswith('{') or response_body_str.strip().startswith('[')):
            try:
                json_obj = json.loads(response_body_str.strip())
                CorrelationEngine._extract_json_keys(json_obj, token_map)
            except Exception:
                pass

        # 3. Regex Fallback for UUIDs and JWTs
        if response_body_str:
            uuids = re.findall(CorrelationEngine.UUID_REGEX, response_body_str)
            if uuids and 'uuid' not in token_map:
                token_map['uuid'] = uuids[0]

            jwts = re.findall(CorrelationEngine.JWT_REGEX, response_body_str)
            if jwts and 'jwt' not in token_map:
                token_map['jwt'] = jwts[0]

        return token_map

    @staticmethod
    def _extract_json_keys(obj, token_map):
        if isinstance(obj, dict):
            for k, v in obj.items():
                key_str = str(k)
                if isinstance(v, (dict, list)):
                    CorrelationEngine._extract_json_keys(v, token_map)
                elif not isinstance(v, (dict, list)):
                    val_str = str(v)
                    k_lower = key_str.lower()
                    if k_lower in CorrelationEngine.TOKEN_KEYS or k_lower.endswith('_id') or k_lower.endswith('_token') or 'id' in k_lower or 'token' in k_lower or 'csrf' in k_lower:
                        token_map[key_str] = val_str
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    CorrelationEngine._extract_json_keys(item, token_map)

    @staticmethod
    def apply_tokens(request_str, token_map):
        """
        Updates request string (headers and body) with extracted tokens in token_map.
        """
        if not request_str or not token_map:
            return request_str

        modified_req = request_str

        for key, val in token_map.items():
            if not key or not val:
                continue

            # 1. Update Cookie header
            if key.startswith('Cookie:'):
                cookie_name = key.split(':', 1)[1]
                pattern = re.escape(cookie_name) + r'=[^;\r\n]*'
                replacement = cookie_name + '=' + str(val)
                modified_req = re.sub(pattern, replacement, modified_req)

            # 2. Update JSON Body
            elif '{' in modified_req and key in modified_req:
                pattern_str = r'("' + re.escape(key) + r'"\s*:\s*)("[^"]*"|\d+|true|false|null)'
                replacement = r'\1"' + str(val) + r'"'
                modified_req = re.sub(pattern_str, replacement, modified_req)

            # 3. Update URL Query or Form Parameters
            if key + '=' in modified_req:
                pattern = re.escape(key) + r'=[^&\s\r\n]*'
                replacement = key + '=' + str(val)
                modified_req = re.sub(pattern, replacement, modified_req)

            # 4. Update Header Lines
            if key.lower() in ['authorization', 'x-csrf-token', 'csrf-token', 'x-api-key'] or 'token' in key.lower():
                lines = modified_req.splitlines()
                new_lines = []
                for line in lines:
                    if ':' in line:
                        h_name = line.split(':', 1)[0].strip()
                        if h_name.lower() == key.lower():
                            if h_name.lower() == 'authorization' and not str(val).lower().startswith('bearer '):
                                line = h_name + ': Bearer ' + str(val)
                            else:
                                line = h_name + ': ' + str(val)
                    new_lines.append(line)
                delimiter = '\r\n' if '\r\n' in request_str else '\n'
                modified_req = delimiter.join(new_lines)

        return modified_req


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

        # 2. Skip single steps (Drop step i)
        for i in range(n):
            seq_copy = [item for idx, item in enumerate(sequence) if idx != i]
            if seq_copy:
                step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else 'Step ' + str(i + 1)
                permutations.append({
                    'name': 'Drop ' + step_name,
                    'description': 'Drops step ' + str(i + 1) + ' (' + str(step_name) + ')',
                    'sequence': seq_copy
                })

        # 3. Duplicate steps (Repeat step i)
        for i in range(n):
            seq_copy = list(sequence[:i+1]) + [sequence[i]] + list(sequence[i+1:])
            step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else 'Step ' + str(i + 1)
            permutations.append({
                'name': 'Duplicate ' + step_name,
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

        # 6. Direct step jump (Execute final step directly)
        if n > 1:
            permutations.append({
                'name': 'Jump to Final Step',
                'description': 'Executes only the final step without previous setup steps',
                'sequence': [sequence[-1]]
            })

        return permutations


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
