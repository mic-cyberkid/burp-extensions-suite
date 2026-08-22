# -*- coding: utf-8 -*-
"""
ApexToolkitLogic.py - Core pure-logic engines for ApexBountyToolkit.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import re
import json

try:
    import urllib.parse as urllib_parse
except ImportError:
    import urllib as urllib_parse

try:
    from java.net import URL
except ImportError:
    URL = None


def _update_content_length(headers, new_body_len):
    """
    Updates or inserts Content-Length header in raw HTTP headers string.
    """
    lines = headers.splitlines()
    cl_found = False
    for i, line in enumerate(lines):
        if line.lower().startswith('content-length:'):
            lines[i] = "Content-Length: " + str(new_body_len)
            cl_found = True
            break
    if not cl_found and lines:
        lines.append("Content-Length: " + str(new_body_len))

    delimiter = '\r\n' if '\r\n' in headers else '\n'
    return delimiter.join(lines)


class ScopeEngine(object):
    """
    Engine for checking target scope enforcement across Burp extensions.
    """

    @staticmethod
    def is_in_scope(callbacks, target):
        """
        Checks if a given target (java.net.URL, IHttpService, host string, or URL string)
        is within Burp's configured target scope.
        Returns True if in scope or if scope checking is not available/callbacks is None.
        """
        if callbacks is None:
            return True

        if target is None or target == "":
            return True

        if not hasattr(callbacks, 'isInScope'):
            return True

        try:
            # Case 1: Target is a java.net.URL object
            if URL is not None and isinstance(target, URL):
                return bool(callbacks.isInScope(target))

            # Case 2: Target is an IHttpService object
            if hasattr(target, 'getHost'):
                host = target.getHost()
                protocol = target.getProtocol() if hasattr(target, 'getProtocol') else 'https'
                port = target.getPort() if hasattr(target, 'getPort') else (443 if protocol == 'https' else 80)
                target_str = protocol + "://" + host + ":" + str(port)
            else:
                target_str = str(target).strip()

            if not target_str:
                return True

            if not (target_str.startswith('http://') or target_str.startswith('https://')):
                target_str = 'https://' + target_str

            if URL is not None:
                try:
                    java_url = URL(target_str)
                    return bool(callbacks.isInScope(java_url))
                except Exception:
                    pass

            # Fallback for CLI Python 3 tests or string mock callbacks
            return bool(callbacks.isInScope(target_str))

        except Exception:
            return True


class LogicBreakerEngine(object):
    """
    Engine for generating sequence permutations in multi-step workflows
    to discover business logic flaws and state-machine bypasses.
    """

    @staticmethod
    def generate_permutations(sequence):
        """
        Given a sequence of requests (list of dicts or objects with 'id' and 'name'),
        generates permutation test cases. Filtered to only include active/included steps.
        """
        if not sequence:
            return []

        active_sequence = [item for item in sequence if item.get('included', True)]
        if not active_sequence:
            return []

        permutations = []
        n = len(active_sequence)

        # 1. Baseline sequence
        permutations.append({
            'name': 'Baseline (Full Sequence)',
            'description': 'Executes full active sequence as recorded (1..N)',
            'sequence': list(active_sequence)
        })

        # 2. Skip single steps (Drop step i)
        for i in range(n):
            seq_copy = [item for idx, item in enumerate(active_sequence) if idx != i]
            if seq_copy:
                step_name = active_sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(active_sequence[i], dict) else 'Step ' + str(i + 1)
                permutations.append({
                    'name': 'Drop ' + step_name,
                    'description': 'Drops step ' + str(i + 1) + ' (' + str(step_name) + ')',
                    'sequence': seq_copy
                })

        # 3. Duplicate steps (Repeat step i)
        for i in range(n):
            seq_copy = list(active_sequence[:i+1]) + [active_sequence[i]] + list(active_sequence[i+1:])
            step_name = active_sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(active_sequence[i], dict) else 'Step ' + str(i + 1)
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
                'sequence': list(reversed(active_sequence))
            })

        # 5. Swap adjacent steps
        if n > 1:
            for i in range(n - 1):
                seq_copy = list(active_sequence)
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
                'sequence': [active_sequence[-1]]
            })

        return permutations


class LLMFuzzerEngine(object):
    """
    Engine for extracting request parameters, constructing LLM prompts,
    parsing generated payloads, and injecting payloads into requests.
    """

    SENSITIVE_HEADERS = [
        'authorization', 'cookie', 'x-api-key', 'api-key',
        'x-auth-token', 'bearer', 'session', 'x-access-token'
    ]

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
            # 2. Try JSON body parsing
            if body.startswith('{') or body.startswith('['):
                try:
                    json_obj = json.loads(body)
                    if isinstance(json_obj, dict):
                        def _recurse_json(d, prefix=''):
                            for k, v in d.items():
                                param_key = (prefix + '.' + str(k)) if prefix else str(k)
                                if isinstance(v, dict):
                                    _recurse_json(v, param_key)
                                elif isinstance(v, list):
                                    params.append({'name': param_key, 'value': json.dumps(v), 'type': 'JSON'})
                                else:
                                    val_str = 'null' if v is None else ('true' if v is True else ('false' if v is False else str(v)))
                                    params.append({'name': param_key, 'value': val_str, 'type': 'JSON'})
                        _recurse_json(json_obj)
                    elif isinstance(json_obj, list):
                        for idx, item in enumerate(json_obj):
                            params.append({'name': '[' + str(idx) + ']', 'value': json.dumps(item), 'type': 'JSON'})
                except Exception:
                    pass

            # 3. Try URL-encoded body
            if '=' in body and not body.startswith('{') and not body.startswith('['):
                for pair in body.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        if not any(p['name'] == k and p['type'] == 'URL' for p in params):
                            params.append({'name': k, 'value': v, 'type': 'BODY'})

        return params

    @staticmethod
    def redact_sensitive_headers(request_snippet):
        """
        Strips/redacts sensitive authentication headers from request snippets before passing to LLM.
        """
        if not request_snippet:
            return request_snippet
        lines = request_snippet.splitlines()
        redacted_lines = []
        for line in lines:
            if ':' in line:
                header_name = line.split(':', 1)[0].strip().lower()
                if header_name in LLMFuzzerEngine.SENSITIVE_HEADERS:
                    redacted_lines.append(line.split(':', 1)[0] + ": [REDACTED]")
                    continue
            redacted_lines.append(line)
        delimiter = '\r\n' if '\r\n' in request_snippet else '\n'
        return delimiter.join(redacted_lines)

    @staticmethod
    def build_prompt(target_param, base_request_snippet=""):
        """
        Builds prompt for LLM API to request context-aware WAF bypass payloads.
        Redacts authorization and sensitive headers from snippet.
        """
        safe_snippet = LLMFuzzerEngine.redact_sensitive_headers(base_request_snippet[:400])
        prompt = (
            "You are an expert security researcher conducting authorized vulnerability testing.\n"
            "Generate 5 high-efficiency WAF bypass and security test payloads for parameter: '" + str(target_param) + "'.\n"
            "Request context snippet:\n" + safe_snippet + "\n\n"
            "Return ONLY a JSON array of string payloads, like:\n"
            "[\"payload1\", \"payload2\", \"payload3\", \"payload4\", \"payload5\"]"
        )
        return prompt

    @staticmethod
    def parse_llm_payloads(llm_response_text):
        """
        Parses LLM response to extract payload strings cleanly.
        Supports structured JSON, code-fenced JSON, and line fallback parsing.
        """
        if not llm_response_text:
            return []

        text = llm_response_text.strip()
        # Remove markdown code fences if present
        if text.startswith('```'):
            lines = text.splitlines()
            if len(lines) >= 2 and lines[-1].strip().startswith('```'):
                text = '\n'.join(lines[1:-1]).strip()
            elif len(lines) >= 1:
                text = '\n'.join(lines[1:]).strip()
            if text.lower().startswith('json'):
                text = text[4:].strip()

        # 1. Try direct JSON parse
        try:
            payloads = json.loads(text)
            if isinstance(payloads, list):
                return [str(p) for p in payloads]
            elif isinstance(payloads, dict) and 'payloads' in payloads:
                return [str(p) for p in payloads['payloads']]
        except Exception:
            pass

        # 2. Try JSON array extraction via regex
        json_match = re.search(r'\[\s*".*?"\s*\]', text, re.DOTALL)
        if json_match:
            try:
                payloads = json.loads(json_match.group(0))
                if isinstance(payloads, list):
                    return [str(p) for p in payloads]
            except Exception:
                pass

        # 3. Fallback: line-by-line parsing
        lines = [line.strip() for line in text.splitlines() if line.strip()]
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
        Uses exact parameter key matching and percent-encoding for URL parameters.
        Supports dot-notation for nested JSON parameters (e.g. meta.role).
        """
        if not request_str or not param_name:
            return request_str

        encoded_payload = urllib_parse.quote(str(payload), safe='')

        parts = request_str.split('\r\n\r\n', 1)
        delimiter = '\r\n\r\n'
        if len(parts) < 2:
            parts = request_str.split('\n\n', 1)
            delimiter = '\n\n'

        headers = parts[0]
        body = parts[1] if len(parts) > 1 else ''

        # 1. Handle JSON body injection
        if body and (body.strip().startswith('{') or body.strip().startswith('[')):
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    if '.' in param_name:
                        keys = param_name.split('.')
                        curr = json_data
                        for k in keys[:-1]:
                            if isinstance(curr, dict) and k in curr:
                                curr = curr[k]
                            else:
                                curr = None
                                break
                        if isinstance(curr, dict) and keys[-1] in curr:
                            curr[keys[-1]] = payload
                            new_body = json.dumps(json_data)
                            new_headers = _update_content_length(headers, len(new_body))
                            return new_headers + delimiter + new_body
                    elif param_name in json_data:
                        json_data[param_name] = payload
                        new_body = json.dumps(json_data)
                        new_headers = _update_content_length(headers, len(new_body))
                        return new_headers + delimiter + new_body
            except Exception:
                pass

        # 2. Handle POST body query string injection
        if body and '=' in body:
            tokens = body.split('&')
            matched = False
            for idx, token in enumerate(tokens):
                key = token.split('=', 1)[0] if '=' in token else token
                if key == param_name:
                    tokens[idx] = param_name + '=' + encoded_payload
                    matched = True
            if matched:
                new_body = '&'.join(tokens)
                new_headers = _update_content_length(headers, len(new_body))
                return new_headers + delimiter + new_body

        # 3. Handle URL query string injection
        lines = request_str.splitlines()
        if lines:
            first_line = lines[0]
            url_match = re.search(r'^([A-Z]+\s+)([^\s]+)(\s+HTTP/\d\.\d)', first_line)
            if url_match:
                prefix, full_path, suffix = url_match.group(1), url_match.group(2), url_match.group(3)
                if '?' in full_path:
                    path_part, query_part = full_path.split('?', 1)
                    q_tokens = query_part.split('&')
                    q_matched = False
                    for idx, q_tok in enumerate(q_tokens):
                        q_key = q_tok.split('=', 1)[0] if '=' in q_tok else q_tok
                        if q_key == param_name:
                            q_tokens[idx] = param_name + '=' + encoded_payload
                            q_matched = True
                    if q_matched:
                        new_query = '&'.join(q_tokens)
                        new_first_line = prefix + path_part + '?' + new_query + suffix
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

        if baseline_lengths is not None and len(baseline_lengths) > 0 and content_length not in baseline_lengths:
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


class CorrelationEngine(object):
    """
    Engine for extracting dynamic tokens (CSRF tokens, auth tokens, session IDs)
    from response headers and bodies, and propagating them across request steps.
    """

    TOKEN_KEYS = [
        'csrf', 'csrf_token', 'xsrf', 'xsrf_token', '_csrf', 'token',
        'access_token', 'auth_token', 'bearer', 'session_id', 'nonce'
    ]

    @staticmethod
    def extract_tokens(response_str):
        """
        Extracts candidate tokens from raw HTTP response string.
        Returns dict of {token_name: token_value}.
        """
        tokens = {}
        if not response_str:
            return tokens

        parts = response_str.split('\r\n\r\n', 1)
        if len(parts) < 2:
            parts = response_str.split('\n\n', 1)

        headers = parts[0]
        body = parts[1] if len(parts) > 1 else ''

        # 1. Parse Set-Cookie headers
        for line in headers.splitlines():
            if line.lower().startswith('set-cookie:'):
                cookie_str = line.split(':', 1)[1].strip()
                cookie_pair = cookie_str.split(';', 1)[0]
                if '=' in cookie_pair:
                    k, v = cookie_pair.split('=', 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    if v_clean:
                        tokens['cookie:' + k_clean] = v_clean
                        if any(tk in k_clean.lower() for tk in CorrelationEngine.TOKEN_KEYS):
                            tokens[k_clean] = v_clean

        # 2. Parse JSON response body
        if body and (body.strip().startswith('{') or body.strip().startswith('[')):
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    for k, v in json_data.items():
                        if isinstance(v, (str, int, float)) and v:
                            k_lower = str(k).lower()
                            if any(tk in k_lower for tk in CorrelationEngine.TOKEN_KEYS):
                                tokens[str(k)] = str(v)
            except Exception:
                pass

        # 3. Regex match HTML form input elements for CSRF tokens
        matches = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']+)["\']', body, re.IGNORECASE)
        for name, val in matches:
            if any(tk in name.lower() for tk in CorrelationEngine.TOKEN_KEYS):
                tokens[name] = val

        return tokens

    @staticmethod
    def apply_token_updates(request_str, token_map):
        """
        Replaces token values in request_str using values from token_map.
        """
        if not request_str or not token_map:
            return request_str

        updated_req = request_str

        for key, new_val in token_map.items():
            if not new_val:
                continue

            lines = updated_req.splitlines()
            new_lines = []
            modified = False
            for line in lines:
                if ':' in line:
                    h_name, h_val = line.split(':', 1)
                    h_clean = h_name.strip().lower().replace('_', '-').replace('x-', '')
                    k_clean = key.lower().replace('_', '-').replace('x-', '')
                    if h_clean == k_clean or h_name.strip().lower() == key.lower():
                        new_lines.append(h_name + ": " + str(new_val))
                        modified = True
                        continue
                    elif h_name.strip().lower() == 'authorization' and any(k in key.lower() for k in ['bearer', 'token', 'access']):
                        new_lines.append(h_name + ": Bearer " + str(new_val))
                        modified = True
                        continue
                new_lines.append(line)

            if modified:
                delimiter = '\r\n' if '\r\n' in updated_req else '\n'
                updated_req = delimiter.join(new_lines)

            # Update parameter values in request
            updated_req = LLMFuzzerEngine.inject_payload(updated_req, key, new_val)

        return updated_req
