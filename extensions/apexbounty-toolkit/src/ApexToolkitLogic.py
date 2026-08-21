# -*- coding: utf-8 -*-
"""
ApexToolkitLogic.py - Core pure-logic engines and utilities for ApexBountyToolkit.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import re
import json
import sys

# ------------------------------------------------------------------------------
# Central Logging Utility & Persistence Helpers
# ------------------------------------------------------------------------------

def log_info(callbacks, message):
    """
    Logs informational messages to Burp's extension output stream or standard stdout.
    """
    msg = "[ApexToolkit] " + str(message)
    if callbacks:
        try:
            callbacks.printOutput(msg)
            return
        except Exception:
            pass
    print(msg)


def log_error(callbacks, message, exception=None):
    """
    Logs error messages and exceptions to Burp's extension error stream or standard stderr.
    """
    err_msg = "[ApexToolkit ERROR] " + str(message)
    if exception is not None:
        err_msg += " | Exception: " + str(exception)
    if callbacks:
        try:
            callbacks.printError(err_msg)
            return
        except Exception:
            pass
    sys.stderr.write(err_msg + "\n")


def save_setting(callbacks, key, value):
    """
    Persists configuration settings using Burp Suite extension settings API.
    """
    if callbacks and key:
        try:
            callbacks.saveExtensionSetting(key, str(value) if value is not None else "")
        except Exception as ex:
            log_error(callbacks, "Failed to save extension setting: " + str(key), ex)


def load_setting(callbacks, key, default_value=""):
    """
    Loads persisted configuration setting from Burp Suite extension settings API.
    """
    if callbacks and key:
        try:
            val = callbacks.loadExtensionSetting(key)
            if val is not None and len(val) > 0:
                return str(val)
        except Exception as ex:
            log_error(callbacks, "Failed to load extension setting: " + str(key), ex)
    return default_value


# ------------------------------------------------------------------------------
# Logic Breaker Engine
# ------------------------------------------------------------------------------

class LogicBreakerEngine(object):
    """
    Engine for generating sequence permutations, token extraction/substitution,
    and JSON sequence import/export for multi-step workflow logic testing.
    """

    STATIC_EXTENSIONS = (
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
        '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map'
    )

    @staticmethod
    def is_static_asset(path):
        """
        Checks if a URL path belongs to a static asset that should be pruned during flow recording.
        """
        if not path:
            return False
        clean_path = path.split('?')[0].lower()
        return any(clean_path.endswith(ext) for ext in LogicBreakerEngine.STATIC_EXTENSIONS)

    @staticmethod
    def generate_permutations(sequence):
        """
        Given a sequence of requests (list of dicts with 'id' and 'name'),
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

    @staticmethod
    def export_sequence_to_json(sequence):
        """
        Serializes sequence steps list to JSON string for saving/sharing.
        """
        exportable = []
        for step in sequence:
            exportable.append({
                'method': step.get('method', 'GET'),
                'host': step.get('host', ''),
                'port': step.get('port', 80),
                'use_https': step.get('use_https', False),
                'path': step.get('path', '/'),
                'name': step.get('name', ''),
                'request_str': step.get('request_str', ''),
                'include': step.get('include', True)
            })
        return json.dumps(exportable, indent=2)

    @staticmethod
    def import_sequence_from_json(json_str):
        """
        Parses JSON sequence string back into list of step dictionaries.
        """
        if not json_str:
            return []
        try:
            data = json.loads(json_str)
            if isinstance(data, list):
                result = []
                for item in data:
                    if isinstance(item, dict):
                        result.append({
                            'method': item.get('method', 'GET'),
                            'host': item.get('host', ''),
                            'port': int(item.get('port', 80)),
                            'use_https': bool(item.get('use_https', False)),
                            'path': item.get('path', '/'),
                            'name': item.get('name', ''),
                            'request_str': item.get('request_str', ''),
                            'include': bool(item.get('include', True))
                        })
                return result
        except Exception:
            pass
        return []

    @staticmethod
    def extract_dynamic_tokens(response_str):
        """
        Extracts dynamic tokens (e.g., CSRF tokens, session IDs, bearer tokens, state params)
        from HTTP response headers or body.
        """
        tokens = {}
        if not response_str:
            return tokens

        # 1. Check JSON body tokens
        parts = response_str.split('\r\n\r\n', 1)
        if len(parts) < 2:
            parts = response_str.split('\n\n', 1)

        body = parts[1] if len(parts) > 1 else ''
        if body.strip().startswith('{'):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, (str, int, float)) and any(t in k.lower() for t in ['token', 'csrf', 'state', 'session', 'auth']):
                            tokens[k] = str(v)
            except Exception:
                pass

        # 2. Regex search for token parameters in response body or headers
        patterns = [
            (r'name=["\'](?:csrf[-_]?token|_csrf|authenticity_token)["\']\s+value=["\']([^"\']+)["\']', 'csrf_token'),
            (r'["\'](?:csrf[-_]?token|access[-_]?token|auth[-_]?token|token)["\']\s*:\s*["\']([^"\']+)["\']', 'token'),
            (r'Set-Cookie:\s*([^=;\s]+)=([^;\r\n]+)', 'cookie')
        ]

        for pattern, default_key in patterns:
            matches = re.findall(pattern, response_str, re.IGNORECASE)
            for m in matches:
                if isinstance(m, tuple):
                    if len(m) == 2:
                        tokens[m[0]] = m[1]
                else:
                    tokens[default_key] = m

        return tokens

    @staticmethod
    def substitute_tokens(request_str, token_map):
        """
        Substitutes dynamic token values into raw HTTP request string.
        """
        if not request_str or not token_map:
            return request_str

        modified = request_str
        for token_name, token_val in token_map.items():
            if not token_name or not token_val:
                continue

            # Replace token in headers or query parameters (e.g. csrf_token=XXX)
            pattern = re.escape(token_name) + r'=[^&\s\r\n]*'
            replacement = token_name + '=' + str(token_val)
            modified = re.sub(pattern, replacement, modified)

            # Replace token in JSON body
            parts = modified.split('\r\n\r\n', 1)
            delimiter = '\r\n\r\n'
            if len(parts) < 2:
                parts = modified.split('\n\n', 1)
                delimiter = '\n\n'

            if len(parts) == 2:
                headers, body = parts[0], parts[1]
                if body.strip().startswith('{'):
                    try:
                        jdata = json.loads(body)
                        if isinstance(jdata, dict) and token_name in jdata:
                            jdata[token_name] = token_val
                            modified = headers + delimiter + json.dumps(jdata)
                    except Exception:
                        pass

        return modified


# ------------------------------------------------------------------------------
# LLM Fuzzer Engine
# ------------------------------------------------------------------------------

class LLMFuzzerEngine(object):
    """
    Engine for parameter extraction, prompt building, LLM parsing, and payload injection.
    """

    @staticmethod
    def extract_parameters(request_str):
        """
        Extracts parameter names and current values from raw HTTP request string.
        Supports URL query string, URL-encoded body, multipart form-data, and nested JSON.
        """
        params = []
        if not request_str:
            return params

        lines = request_str.split('\r\n')
        if not lines or not lines[0]:
            lines = request_str.split('\n')

        first_line = lines[0] if lines else ''

        # 1. Extract URL parameters from request line
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

            # 2. Try JSON body parsing (including recursive nested structures)
            if body.startswith('{') or body.startswith('['):
                try:
                    json_obj = json.loads(body)
                    def traverse(obj, prefix=""):
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                key_path = (prefix + "." + str(k)) if prefix else str(k)
                                if isinstance(v, (dict, list)):
                                    traverse(v, key_path)
                                else:
                                    params.append({'name': key_path, 'value': str(v), 'type': 'JSON'})
                        elif isinstance(obj, list):
                            for idx, item in enumerate(obj):
                                key_path = prefix + "[" + str(idx) + "]"
                                if isinstance(item, (dict, list)):
                                    traverse(item, key_path)
                                else:
                                    params.append({'name': key_path, 'value': str(item), 'type': 'JSON'})

                    traverse(json_obj)
                except Exception:
                    pass

            # 3. Multipart / Form-Data body parsing
            if 'Content-Type: multipart/form-data' in request_str or 'name="' in body:
                matches = re.findall(r'name=["\']([^"\']+)["\'](?:\r\n|\n)?(?:\r\n|\n)?([^\r\n-]+)?', body)
                for m in matches:
                    p_name = m[0]
                    p_val = m[1].strip() if len(m) > 1 and m[1] else ''
                    if p_name and not any(p['name'] == p_name for p in params):
                        params.append({'name': p_name, 'value': p_val, 'type': 'MULTIPART'})

            # 4. Try URL-encoded body
            if '=' in body and not body.startswith('{') and not body.startswith('['):
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
            cleaned = re.sub(r'^\d+[\.\)]\s*', '', line)
            cleaned = re.sub(r'^[-\*\u2022]\s*', '', cleaned)
            cleaned = cleaned.strip('"\'`')
            if cleaned and not cleaned.startswith('{') and not cleaned.startswith('['):
                payloads.append(cleaned)

        return payloads[:10]

    @staticmethod
    def inject_payload(request_str, param_name, payload):
        """
        Injects a payload into the specified parameter in raw HTTP request string.
        """
        if not request_str or not param_name:
            return request_str

        parts = request_str.split('\r\n\r\n', 1)
        delimiter = '\r\n\r\n'
        if len(parts) < 2:
            parts = request_str.split('\n\n', 1)
            delimiter = '\n\n'

        if len(parts) == 2:
            headers, body = parts[0], parts[1]

            # 1. Handle JSON body injection
            if body.strip().startswith('{'):
                try:
                    json_data = json.loads(body)
                    # Simple or nested parameter key
                    if param_name in json_data:
                        json_data[param_name] = payload
                        return headers + delimiter + json.dumps(json_data)
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


# ------------------------------------------------------------------------------
# Race Orchestrator Engine
# ------------------------------------------------------------------------------

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

    @staticmethod
    def export_race_results_csv(race_results):
        """
        Exports race attack results list to CSV string format.
        """
        csv_lines = ["Target,Thread ID,Status,Content Length,Anomaly Flag,Note"]
        for item in race_results:
            target = item[0] if len(item) > 0 else ""
            tid = item[1] if len(item) > 1 else ""
            status = item[2] if len(item) > 2 else ""
            length = item[3] if len(item) > 3 else ""
            flag = item[4] if len(item) > 4 else ""
            note = item[5] if len(item) > 5 else ""

            # Sanitize CSV fields
            row = [
                '"' + str(target).replace('"', '""') + '"',
                '"' + str(tid).replace('"', '""') + '"',
                '"' + str(status).replace('"', '""') + '"',
                '"' + str(length).replace('"', '""') + '"',
                '"' + str(flag).replace('"', '""') + '"',
                '"' + str(note).replace('"', '""') + '"'
            ]
            csv_lines.append(",".join(row))

        return "\n".join(csv_lines)


# ------------------------------------------------------------------------------
# Privilege Matrix Engine
# ------------------------------------------------------------------------------

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
                if line and ':' in line and not line.startswith('#'):
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
