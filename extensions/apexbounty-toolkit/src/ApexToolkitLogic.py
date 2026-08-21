# -*- coding: utf-8 -*-
"""
ApexToolkitLogic.py - Core pure-logic engines for ApexBountyToolkit.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import re
import json

try:
    import urllib
    url_quote = urllib.quote
except AttributeError:
    import urllib.parse
    url_quote = urllib.parse.quote


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

    SENSITIVE_HEADERS = [
        'authorization', 'cookie', 'x-api-key', 'api-key',
        'x-auth-token', 'session', 'token', 'x-access-token', 'bearer'
    ]

    @staticmethod
    def redact_sensitive_headers(snippet):
        """
        Redacts authorization tokens, cookies, and secret headers from request context snippet.
        """
        if not snippet:
            return snippet
        lines = snippet.splitlines()
        redacted_lines = []
        for line in lines:
            if ':' in line:
                key = line.split(':', 1)[0].strip().lower()
                if key in LLMFuzzerEngine.SENSITIVE_HEADERS:
                    redacted_lines.append(line.split(':', 1)[0] + ": [REDACTED]")
                    continue
            redacted_lines.append(line)
        delimiter = '\r\n' if '\r\n' in snippet else '\n'
        return delimiter.join(redacted_lines)

    @staticmethod
    def update_content_length(headers_str, new_body):
        """
        Recalculates and updates or inserts Content-Length header in headers string.
        """
        lines = headers_str.splitlines()
        if not lines:
            return headers_str

        try:
            new_len = len(new_body.encode('utf-8'))
        except Exception:
            new_len = len(new_body)

        new_lines = []
        has_cl = False
        for line in lines:
            if ':' in line:
                key = line.split(':', 1)[0].strip().lower()
                if key == 'content-length':
                    new_lines.append(line.split(':', 1)[0] + ': ' + str(new_len))
                    has_cl = True
                    continue
            new_lines.append(line)

        if not has_cl and new_body:
            new_lines.append('Content-Length: ' + str(new_len))

        delimiter = '\r\n' if '\r\n' in headers_str else '\n'
        return delimiter.join(new_lines)

    @staticmethod
    def extract_parameters(request_str):
        """
        Extracts parameter names and current values from raw HTTP request string.
        Supports URL query string, URL-encoded body, and JSON body (objects/arrays).
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
                            val_str = "null" if v is None else str(v)
                            params.append({'name': str(k), 'value': val_str, 'type': 'JSON'})
                    elif isinstance(json_obj, list):
                        for item in json_obj:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    val_str = "null" if v is None else str(v)
                                    if not any(p['name'] == str(k) and p['type'] == 'JSON' for p in params):
                                        params.append({'name': str(k), 'value': val_str, 'type': 'JSON'})
                except Exception:
                    pass

            # 3. Try URL-encoded body (param1=val1&param2=val2)
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
        Automatically redacts sensitive auth tokens and cookies before sending.
        """
        safe_snippet = LLMFuzzerEngine.redact_sensitive_headers(base_request_snippet)
        prompt = (
            "You are an expert security researcher conducting authorized vulnerability testing.\n"
            "Generate 5 high-efficiency WAF bypass and security test payloads for parameter: '" + str(target_param) + "'.\n"
            "Request context snippet:\n" + str(safe_snippet[:300]) + "\n\n"
            "Return ONLY a JSON array of string payloads, like:\n"
            "[\"payload1\", \"payload2\", \"payload3\", \"payload4\", \"payload5\"]"
        )
        return prompt

    @staticmethod
    def parse_llm_payloads(llm_response_text):
        """
        Parses LLM response to extract payload strings. Handles markdown code fences and direct JSON.
        """
        if not llm_response_text:
            return []

        text = llm_response_text.strip()
        # Strip markdown code fences if present
        if text.startswith('```'):
            lines = text.splitlines()
            if len(lines) >= 2:
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                text = '\n'.join(lines).strip()

        # Try direct json.loads
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [str(p) for p in data]
        except Exception:
            pass

        # Try JSON array regex extraction
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
        Injects a payload into the specified parameter in the raw HTTP request string.
        Ensures exact parameter name matching, percent encoding for URL/body params,
        and recalculates Content-Length header.
        """
        if not request_str or not param_name:
            return request_str

        parts = request_str.split('\r\n\r\n', 1)
        delimiter = '\r\n\r\n'
        if len(parts) < 2:
            parts = request_str.split('\n\n', 1)
            delimiter = '\n\n'

        headers = parts[0]
        body = parts[1] if len(parts) > 1 else ''

        # 1. Handle JSON body injection
        if body and body.strip().startswith('{'):
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict) and param_name in json_data:
                    json_data[param_name] = payload
                    new_body = json.dumps(json_data)
                    new_headers = LLMFuzzerEngine.update_content_length(headers, new_body)
                    return new_headers + delimiter + new_body
            except Exception:
                pass

        # 2. Handle POST body query string injection (URL-encoded body)
        if body and '=' in body and not body.strip().startswith('{') and not body.strip().startswith('['):
            tokens = body.split('&')
            matched = False
            for idx, token in enumerate(tokens):
                if '=' in token:
                    k, v = token.split('=', 1)
                else:
                    k, v = token, ''
                if k == param_name:
                    tokens[idx] = k + '=' + url_quote(str(payload), safe='')
                    matched = True
            if matched:
                new_body = '&'.join(tokens)
                new_headers = LLMFuzzerEngine.update_content_length(headers, new_body)
                return new_headers + delimiter + new_body

        # 3. Handle URL query string injection in request line
        lines = headers.splitlines()
        if lines:
            first_line = lines[0]
            parts_fl = first_line.split(' ', 2)
            if len(parts_fl) >= 2 and '?' in parts_fl[1]:
                method = parts_fl[0]
                url_path, query_str = parts_fl[1].split('?', 1)
                proto = parts_fl[2] if len(parts_fl) > 2 else ''

                tokens = query_str.split('&')
                matched = False
                for idx, token in enumerate(tokens):
                    if '=' in token:
                        k, v = token.split('=', 1)
                    else:
                        k, v = token, ''
                    if k == param_name:
                        tokens[idx] = k + '=' + url_quote(str(payload), safe='')
                        matched = True
                if matched:
                    new_query = '&'.join(tokens)
                    new_url_path = url_path + '?' + new_query
                    new_first_line = method + ' ' + new_url_path + (' ' + proto if proto else '')
                    lines[0] = new_first_line
                    new_headers = ('\r\n' if '\r\n' in headers else '\n').join(lines)
                    return new_headers + delimiter + body

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
