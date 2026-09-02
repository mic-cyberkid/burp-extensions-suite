# -*- coding: utf-8 -*-
"""
ApexToolkitLogic.py - Core pure-logic engines for ApexBountyToolkit.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import re
import json
import time
import uuid


class MarkdownRenderer(object):
    """
    Pure Python Markdown-to-HTML converter designed for Java Swing JEditorPane rendering.
    Supports headings, bold/italic, bullet/numbered lists, code blocks, blockquotes, and paragraphs.
    """

    @staticmethod
    def render_to_html(markdown_text):
        if not markdown_text:
            return "<html><body style='font-family:sans-serif; color:#333333;'><i>No notes available for this target.</i></body></html>"

        lines = markdown_text.splitlines()
        html_lines = ["<html><body style='font-family:sans-serif; font-size:12pt; color:#222222; margin:10px;'>"]

        in_code_block = False
        in_ul = False
        in_ol = False

        for line in lines:
            line_str = line.rstrip()

            # Code Block Toggle
            if line_str.startswith("```"):
                if in_code_block:
                    html_lines.append("</pre></code>")
                    in_code_block = False
                else:
                    if in_ul:
                        html_lines.append("</ul>")
                        in_ul = False
                    if in_ol:
                        html_lines.append("</ol>")
                        in_ol = False
                    html_lines.append("<pre style='background-color:#f4f4f4; border:1px solid #cccccc; padding:8px;'><code>")
                    in_code_block = True
                continue

            if in_code_block:
                escaped = line_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                html_lines.append(escaped)
                continue

            # Close lists if blank line encountered
            if not line_str.strip():
                if in_ul:
                    html_lines.append("</ul>")
                    in_ul = False
                if in_ol:
                    html_lines.append("</ol>")
                    in_ol = False
                html_lines.append("<br/>")
                continue

            # Escape raw HTML tags for standard text lines to prevent hidden text (e.g. <user_id>)
            formatted = line_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

            # Inline formatting helper (Bold, Italic, Code)
            formatted = re.sub(r'\*\*\*(.*?)\*\*\*', r'<b><i>\1</i></b>', formatted)
            formatted = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', formatted)
            formatted = re.sub(r'\*(.*?)\*', r'<i>\1</i>', formatted)
            formatted = re.sub(r'`(.*?)`', r'<code style="background-color:#f0f0f0;">\1</code>', formatted)

            # Headings
            if line_str.startswith("# "):
                if in_ul:
                    html_lines.append("</ul>"); in_ul = False
                if in_ol:
                    html_lines.append("</ol>"); in_ol = False
                html_lines.append("<h1 style='color:#114477; border-bottom:1px solid #dddddd;'>" + formatted[2:] + "</h1>")
                continue
            elif line_str.startswith("## "):
                if in_ul:
                    html_lines.append("</ul>"); in_ul = False
                if in_ol:
                    html_lines.append("</ol>"); in_ol = False
                html_lines.append("<h2 style='color:#225588;'>" + formatted[3:] + "</h2>")
                continue
            elif line_str.startswith("### "):
                if in_ul:
                    html_lines.append("</ul>"); in_ul = False
                if in_ol:
                    html_lines.append("</ol>"); in_ol = False
                html_lines.append("<h3 style='color:#336699;'>" + formatted[4:] + "</h3>")
                continue

            # Bullet List
            bullet_match = re.match(r'^\s*[\-\*]\s+(.*)', line_str)
            if bullet_match:
                if not in_ul:
                    if in_ol:
                        html_lines.append("</ol>"); in_ol = False
                    html_lines.append("<ul>")
                    in_ul = True
                content = formatted.lstrip().lstrip("-*").strip()
                html_lines.append("<li>" + content + "</li>")
                continue

            # Numbered List
            num_match = re.match(r'^\s*\d+[\.\)]\s+(.*)', line_str)
            if num_match:
                if not in_ol:
                    if in_ul:
                        html_lines.append("</ul>"); in_ul = False
                    html_lines.append("<ol>")
                    in_ol = True
                content = re.sub(r'^\s*\d+[\.\)]\s*', '', formatted)
                html_lines.append("<li>" + content + "</li>")
                continue

            # Blockquote
            if line_str.startswith("> "):
                if in_ul:
                    html_lines.append("</ul>"); in_ul = False
                if in_ol:
                    html_lines.append("</ol>"); in_ol = False
                html_lines.append("<blockquote style='background:#f9f9f9; border-left:4px solid #cccccc; margin:4px; padding:4px 8px;'>" + formatted[2:] + "</blockquote>")
                continue

            # Default Paragraph
            if in_ul:
                html_lines.append("</ul>"); in_ul = False
            if in_ol:
                html_lines.append("</ol>"); in_ol = False

            html_lines.append("<p style='margin:4px 0;'>" + formatted + "</p>")

        if in_ul:
            html_lines.append("</ul>")
        if in_ol:
            html_lines.append("</ol>")
        if in_code_block:
            html_lines.append("</pre></code>")

        html_lines.append("</body></html>")
        return "\n".join(html_lines)


class TargetNotesManager(object):
    """
    Manages per-target domain Markdown notes and metadata persistence.
    """

    def __init__(self):
        self.notes_db = {}  # domain -> {'markdown': str, 'updated_at': float}

    def save_notes(self, domain, markdown_text):
        domain_clean = (domain or "global").lower().strip()
        self.notes_db[domain_clean] = {
            'markdown': markdown_text or "",
            'updated_at': time.time()
        }
        return domain_clean

    def get_notes(self, domain):
        domain_clean = (domain or "global").lower().strip()
        if domain_clean in self.notes_db:
            return self.notes_db[domain_clean]['markdown']
        return ""

    def get_rendered_notes(self, domain):
        raw_md = self.get_notes(domain)
        if not raw_md:
            raw_md = "# Target Notes: " + str(domain) + "\n\n*No notes recorded yet for this domain.*"
        return MarkdownRenderer.render_to_html(raw_md)

    def list_domains(self):
        return sorted(list(self.notes_db.keys()))


class NoiseScorer(object):
    """
    Multi-signal noise classifier that assigns numeric noise scores (0.0 to 1.0)
    to captured requests based on URL extension, HTTP method, JSON content,
    MIME type, and state-changing keywords.
    """

    STATIC_EXTENSIONS = (
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4', '.mp3'
    )

    TELEMETRY_PATTERNS = (
        '/analytics', '/telemetry', '/tracking', '/log', '/metrics',
        'google-analytics', 'mixpanel', 'segment', 'sentry', 'bugsnag'
    )

    STATE_KEYWORDS = (
        'token', 'auth', 'login', 'signup', 'invite', 'accept', 'confirm',
        'approve', 'checkout', 'pay', 'reset', 'password', 'user', 'create',
        'update', 'delete', 'order', 'submit', 'cart', 'admin', 'role'
    )

    @staticmethod
    def score(method, path, headers=None, body=None, status_code=200, mime_type=""):
        """
        Calculates noise score between 0.0 (highly relevant API/state-changing action)
        and 1.0 (pure static noise / asset).
        """
        score = 0.5  # Neutral baseline
        path_lower = (path or "").lower()
        method_upper = (method or "GET").upper()
        headers_str = str(headers or "").lower()
        body_str = str(body or "").lower()

        # 1. Static asset extensions
        if any(path_lower.endswith(ext) or (ext + "?") in path_lower for ext in NoiseScorer.STATIC_EXTENSIONS):
            score += 0.40

        # 2. Telemetry and logging endpoints
        if any(pattern in path_lower for pattern in NoiseScorer.TELEMETRY_PATTERNS):
            score += 0.45

        # 3. MIME type checks
        mime_lower = (mime_type or "").lower()
        if "image/" in mime_lower or "text/css" in mime_lower or "javascript" in mime_lower:
            score += 0.45

        # 4. State-changing HTTP methods
        if method_upper in ('POST', 'PUT', 'PATCH', 'DELETE'):
            score -= 0.35

        # 5. JSON API headers / body
        if 'application/json' in headers_str or 'application/json' in mime_lower:
            score -= 0.30

        if body_str and (body_str.startswith('{') or body_str.startswith('[')):
            score -= 0.25

        # 6. State-changing / Security relevant keywords
        if any(kw in path_lower or kw in body_str for kw in NoiseScorer.STATE_KEYWORDS):
            score -= 0.25

        # Clamp score within [0.0, 1.0]
        final_score = max(0.0, min(1.0, round(score, 2)))
        return final_score

    @staticmethod
    def classify(score):
        """
        Translates numeric score into semantic label.
        """
        if score < 0.40:
            return "RELEVANT"
        elif score < 0.70:
            return "AMBIGUOUS"
        else:
            return "LIKELY_NOISE"


class FlowStep(object):
    """
    Data model representing a single step within a business logic flow session.
    Preserves raw requests/responses along with parsed metadata and pruning tombstones.
    """

    def __init__(self, step_id, sequence_index, method, host, path,
                 query_params=None, headers=None, body=None,
                 http_service=None, request_bytes=None, response_bytes=None,
                 status_code=0, response_headers=None, response_body=None,
                 source="proxy", noise_score=0.5, classification="AMBIGUOUS"):
        self.step_id = step_id
        self.sequence_index = sequence_index
        self.source = source
        self.method = (method or "GET").upper()
        self.host = host or ""
        self.path = path or "/"
        self.query_params = query_params or {}
        self.headers = headers or {}
        self.body = body or ""

        self.http_service = http_service
        self.request_bytes = request_bytes
        self.response_bytes = response_bytes

        self.status_code = status_code
        self.response_headers = response_headers or {}
        self.response_body = response_body or ""

        self.noise_score = noise_score
        self.classification = classification
        self.is_pruned = False
        self.is_essential = False
        self.dependencies = []

    def to_dict(self):
        return {
            'step_id': self.step_id,
            'sequence_index': self.sequence_index,
            'source': self.source,
            'method': self.method,
            'host': self.host,
            'path': self.path,
            'status_code': self.status_code,
            'noise_score': self.noise_score,
            'classification': self.classification,
            'is_pruned': self.is_pruned,
            'is_essential': self.is_essential,
            'name': self.method + " " + self.path,
            'dependencies_count': len(self.dependencies)
        }


class FlowSession(object):
    """
    Session container for recording, filtering, pruning, and establishing baseline
    flows for Logic Breaker testing.
    """

    # Lifecycle States: IDLE -> ARMED -> CAPTURING -> PAUSED -> FINALIZING -> BASELINE_READY
    STATES = ('IDLE', 'ARMED', 'CAPTURING', 'PAUSED', 'FINALIZING', 'BASELINE_READY')

    def __init__(self, name="Flow Session", scope_hosts=None, flow_id=None):
        self.flow_id = flow_id or str(uuid.uuid4())[:8]
        self.name = name
        self.status = 'IDLE'
        self.anchor_request = None
        self.steps = []
        self.scope_hosts = set(scope_hosts) if scope_hosts else set()
        self.created_at = time.time()
        self.updated_at = time.time()

    def add_step(self, step):
        step.sequence_index = len(self.steps) + 1
        self.steps.append(step)
        self.updated_at = time.time()
        return step

    def prune_step(self, step_id):
        for s in self.steps:
            if s.step_id == step_id:
                s.is_pruned = True
                self.updated_at = time.time()
                return True
        return False

    def restore_step(self, step_id):
        for s in self.steps:
            if s.step_id == step_id:
                s.is_pruned = False
                self.updated_at = time.time()
                return True
        return False

    def reorder_step(self, from_idx, to_idx):
        if 0 <= from_idx < len(self.steps) and 0 <= to_idx < len(self.steps):
            step = self.steps.pop(from_idx)
            self.steps.insert(to_idx, step)
            for idx, s in enumerate(self.steps):
                s.sequence_index = idx + 1
            self.updated_at = time.time()
            return True
        return False

    def get_active_steps(self, include_pruned=False):
        if include_pruned:
            return list(self.steps)
        return [s for s in self.steps if not s.is_pruned]

    def get_summary(self):
        total = len(self.steps)
        pruned = sum(1 for s in self.steps if s.is_pruned)
        active = [s for s in self.steps if not s.is_pruned]
        relevant = sum(1 for s in active if s.classification == "RELEVANT")
        noise = sum(1 for s in active if s.classification == "LIKELY_NOISE")
        ambiguous = sum(1 for s in active if s.classification == "AMBIGUOUS")
        duration = round(time.time() - self.created_at, 1)

        return {
            'flow_id': self.flow_id,
            'name': self.name,
            'status': self.status,
            'total_steps': total,
            'active_steps': len(active),
            'pruned_steps': pruned,
            'relevant_count': relevant,
            'noise_count': noise,
            'ambiguous_count': ambiguous,
            'scope_hosts': list(self.scope_hosts),
            'duration_seconds': duration
        }


class FlowCorrelator(object):
    """
    Extracts dynamic tokens, object IDs, and referrer/cookie dependencies
    between steps in a flow session.
    """

    TOKEN_KEYS = ('token', 'csrf', 'nonce', 'state', 'code', 'session', 'id', 'user_id', 'invite_id')

    @staticmethod
    def correlate_steps(steps):
        """
        Analyzes sequence steps to identify data dependencies across requests/responses.
        Returns a list of dependency dicts.
        """
        dependencies = []
        if not steps:
            return dependencies

        for i, target_step in enumerate(steps):
            target_str = (target_step.path + " " + str(target_step.body) + " " + str(target_step.headers)).lower()

            for j in range(i):
                source_step = steps[j]
                source_resp = str(source_step.response_body or "") + " " + str(source_step.response_headers or "")

                # 1. Search for JSON key/value propagation
                if source_step.response_body:
                    try:
                        resp_json = json.loads(source_step.response_body)
                        if isinstance(resp_json, dict):
                            for key, val in resp_json.items():
                                val_str = str(val).strip()
                                if len(val_str) >= 4 and val_str.lower() in target_str:
                                    dep = {
                                        'from_step_id': source_step.step_id,
                                        'to_step_id': target_step.step_id,
                                        'key': str(key),
                                        'value': val_str,
                                        'confidence': 0.90
                                    }
                                    dependencies.append(dep)
                                    target_step.dependencies.append(dep)
                    except Exception:
                        pass

                # 2. Search for explicit token keywords in path or body
                for key in FlowCorrelator.TOKEN_KEYS:
                    pattern = r'["\']?' + re.escape(key) + r'["\']?\s*[:=]\s*["\']?([^"\'&\s]+)'
                    matches = re.findall(pattern, source_resp, re.IGNORECASE)
                    for match in matches:
                        match_val = str(match).strip()
                        if len(match_val) >= 4 and match_val.lower() in target_str:
                            dep = {
                                'from_step_id': source_step.step_id,
                                'to_step_id': target_step.step_id,
                                'key': key,
                                'value': match_val,
                                'confidence': 0.95
                            }
                            dependencies.append(dep)
                            target_step.dependencies.append(dep)

        return dependencies


class FlowCaptureManager(object):
    """
    Manager controlling the live capture lifecycle and routing incoming HTTP
    traffic into active FlowSessions.
    """

    def __init__(self):
        self.active_session = None

    def start_capture(self, anchor_request=None, name="Flow Session", scope_hosts=None):
        self.active_session = FlowSession(name=name, scope_hosts=scope_hosts)
        self.active_session.status = 'CAPTURING'
        if anchor_request:
            self.active_session.anchor_request = anchor_request
        return self.active_session

    def pause_capture(self):
        if self.active_session and self.active_session.status == 'CAPTURING':
            self.active_session.status = 'PAUSED'
            return True
        return False

    def resume_capture(self):
        if self.active_session and self.active_session.status == 'PAUSED':
            self.active_session.status = 'CAPTURING'
            return True
        return False

    def stop_capture(self):
        if self.active_session:
            self.active_session.status = 'BASELINE_READY'
            # Perform flow correlation when baseline is finalized
            FlowCorrelator.correlate_steps(self.active_session.get_active_steps())
            return self.active_session
        return None

    def ingest_candidate(self, method, host, path, query_params=None, headers=None, body=None,
                         http_service=None, request_bytes=None, response_bytes=None,
                         status_code=200, response_headers=None, response_body=None,
                         source="proxy", mime_type=""):
        if not self.active_session or self.active_session.status != 'CAPTURING':
            return None

        # Scope enforcement if scope hosts are defined
        if self.active_session.scope_hosts and host not in self.active_session.scope_hosts:
            return None

        # Calculate noise score and classification
        score = NoiseScorer.score(method, path, headers=headers, body=body, status_code=status_code, mime_type=mime_type)
        classification = NoiseScorer.classify(score)

        step_id = "step-" + str(len(self.active_session.steps) + 1)
        step = FlowStep(
            step_id=step_id,
            sequence_index=len(self.active_session.steps) + 1,
            method=method,
            host=host,
            path=path,
            query_params=query_params,
            headers=headers,
            body=body,
            http_service=http_service,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            status_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            source=source,
            noise_score=score,
            classification=classification
        )

        return self.active_session.add_step(step)


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
                step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else getattr(sequence[i], 'name', 'Step ' + str(i + 1))
                permutations.append({
                    'name': 'Drop ' + str(step_name),
                    'description': 'Drops step ' + str(i + 1) + ' (' + str(step_name) + ')',
                    'sequence': seq_copy
                })

        # 3. Duplicate steps (Repeat step i)
        for i in range(n):
            seq_copy = list(sequence[:i+1]) + [sequence[i]] + list(sequence[i+1:])
            step_name = sequence[i].get('name', 'Step ' + str(i + 1)) if isinstance(sequence[i], dict) else getattr(sequence[i], 'name', 'Step ' + str(i + 1))
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
