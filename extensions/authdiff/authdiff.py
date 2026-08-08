import os
import sys
import yaml
import json
import time
import re
import difflib
import threading
from concurrent.futures import ThreadPoolExecutor
import requests

# mitmproxy imports
try:
    import mitmproxy.http
    from mitmproxy import ctx
except ImportError:
    # Allow running/importing without mitmproxy
    pass


class AuthDiff:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self.scope_domains = []
        self.ignore_extensions = []
        self.contexts = {}
        self.results = []

        # Mutex lock to synchronize access to self.results and report generation
        self.lock = threading.Lock()

        # Thread pool for asynchronous replays
        self.executor = ThreadPoolExecutor(max_workers=10)

        # Try loading config immediately in case of standalone running
        if os.path.exists(config_path):
            self.load_config(config_path)

    def load(self, loader):
        loader.add_option(
            name="config_path",
            typespec=str,
            default="config.yaml",
            help="Path to the AuthDiff YAML configuration file",
        )
        loader.add_option(
            name="output_json",
            typespec=str,
            default="authdiff_results.json",
            help="Path to output machine-readable JSON results",
        )
        loader.add_option(
            name="output_html",
            typespec=str,
            default="authdiff_report.html",
            help="Path to output human-readable HTML report",
        )

    def configure(self, updated):
        if "config_path" in updated:
            config_path = ctx.options.config_path
            self.config_path = config_path
            self.load_config(config_path)

    def load_config(self, path):
        try:
            with open(path, 'r') as f:
                self.config = yaml.safe_load(f) or {}

            # Extract key config fields
            config_section = self.config.get("config", {})
            self.scope_domains = config_section.get("scope_domains", [])
            self.ignore_extensions = config_section.get("ignore_extensions", [])

            # Extract context objects
            self.contexts = {}
            for k, v in self.config.items():
                if k.startswith("context_"):
                    clean_key = k
                    if "low_priv" in k:
                        clean_key = "low_priv"
                    elif "cross_tenant" in k:
                        clean_key = "cross_tenant"
                    elif "base" in k:
                        clean_key = "base"
                    self.contexts[clean_key] = v

            print(f"[AuthDiff] Config loaded from {path}")
            print(f"  Scopes: {self.scope_domains}")
            print(f"  Ignore extensions: {self.ignore_extensions}")
            print(f"  Contexts: {list(self.contexts.keys())}")
        except Exception as e:
            print(f"[AuthDiff] Error loading config: {e}")

    def normalize_text(self, text):
        if not text:
            return ""
        # Replace UUIDs
        uuid_re = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
        text = uuid_re.sub("[UUID_MASK]", text)

        # Replace ISO timestamps or general date/times
        date_re = re.compile(r'\b\d{4}[-/]\d{2}[-/]\d{2}(?:T|\s+)\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')
        text = date_re.sub("[DATETIME_MASK]", text)

        # Replace long hex strings (likely md5/sha1/sha256/tokens)
        hex_re = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
        text = hex_re.sub("[HEX_MASK]", text)

        # Replace standalone numbers to ignore ID/numeric differences
        num_re = re.compile(r'\b\d+\b')
        text = num_re.sub("[NUM_MASK]", text)

        return text

    def extract_json_structure(self, data, path=""):
        paths = set()
        if isinstance(data, dict):
            for k, v in data.items():
                current_path = f"{path}.{k}" if path else k
                paths.add(current_path)
                paths.update(self.extract_json_structure(v, current_path))
        elif isinstance(data, list):
            for item in data:
                paths.update(self.extract_json_structure(item, path))
        return paths

    def parse_json_structure(self, text):
        try:
            data = json.loads(text)
            paths = self.extract_json_structure(data)
            return True, paths
        except Exception:
            return False, set()

    def calculate_similarity(self, res_a, res_b):
        status_a = res_a.get("status_code")
        status_b = res_b.get("status_code")
        body_a = res_a.get("body", "")
        body_b = res_b.get("body", "")

        # 1. Status Code Delta
        status_match = (status_a == status_b)

        # 2. Content-Length Tolerance check (default 5%)
        len_a = len(body_a)
        len_b = len(body_b)
        max_len = max(len_a, len_b, 1)
        len_diff_pct = abs(len_a - len_b) / max_len
        length_ok = len_diff_pct <= 0.05

        # 3. Response Body Distance on normalized text
        norm_a = self.normalize_text(body_a)
        norm_b = self.normalize_text(body_b)

        if norm_a == norm_b:
            body_sim = 1.0
        else:
            body_sim = difflib.SequenceMatcher(None, norm_a, norm_b).ratio()

        # 4. JSON Structural Hash comparison
        is_json_a, struct_a = self.parse_json_structure(body_a)
        is_json_b, struct_b = self.parse_json_structure(body_b)

        if is_json_a and is_json_b:
            if not struct_a and not struct_b:
                struct_sim = 1.0
            else:
                union_set = struct_a | struct_b
                if union_set:
                    struct_sim = len(struct_a & struct_b) / len(union_set)
                else:
                    struct_sim = 1.0
        else:
            struct_sim = body_sim if (body_a or body_b) else 1.0

        composite_score = (body_sim + struct_sim) / 2.0

        return {
            "status_match": status_match,
            "status_a": status_a,
            "status_b": status_b,
            "body_sim": body_sim,
            "struct_sim": struct_sim,
            "len_diff_pct": len_diff_pct,
            "length_ok": length_ok,
            "composite_score": composite_score,
            "is_json": (is_json_a and is_json_b)
        }

    def classify_severity(self, orig_res, replayed_res, score_details):
        status_a = orig_res.get("status_code")
        status_b = replayed_res.get("status_code")
        composite_score = score_details.get("composite_score", 0.0)

        is_success_a = status_a in [200, 201, 204]
        is_success_b = status_b in [200, 201, 204]

        if is_success_a:
            if status_b in [401, 403]:
                return "INFO / ENFORCED"
            elif is_success_b:
                if composite_score > 0.85:
                    return "CRITICAL"
                elif composite_score < 0.50:
                    return "UNCERTAIN"
                else:
                    return "WARNING"
            else:
                return "INFO / ENFORCED"
        else:
            if status_a == status_b and composite_score > 0.85:
                return "UNCERTAIN"
            else:
                return "INFO / ENFORCED"

    def process_and_replay(self, flow):
        orig_req = {
            "method": flow.request.method,
            "url": flow.request.url,
            "headers": dict(flow.request.headers),
            "body": flow.request.content.decode("utf-8", errors="ignore")
        }

        orig_res = {
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": flow.response.content.decode("utf-8", errors="ignore")
        }

        for context_name, context_config in self.contexts.items():
            if context_name == "base":
                continue
            self.executor.submit(self.replay_request_task, orig_req, orig_res, context_name, context_config)

    def replay_request_task(self, orig_req, orig_res, context_name, context_config):
        try:
            headers = dict(orig_req["headers"])
            headers["X-AuthDiff-Replayed"] = "1"
            headers["X-AuthDiff-Context"] = context_name

            cfg_headers = context_config.get("headers", {})
            for k, v in cfg_headers.items():
                for orig_k in list(headers.keys()):
                    if orig_k.lower() == k.lower():
                        del headers[orig_k]
                headers[k] = v

            cfg_cookies = context_config.get("cookies", {})
            cookie_str = ""
            for orig_k in list(headers.keys()):
                if orig_k.lower() == "cookie":
                    cookie_str = headers[orig_k]
                    del headers[orig_k]

            cookie_dict = {}
            if cookie_str:
                for part in cookie_str.split(";"):
                    if "=" in part:
                        ck, cv = part.strip().split("=", 1)
                        cookie_dict[ck] = cv
            for ck, cv in cfg_cookies.items():
                cookie_dict[ck] = cv

            if cookie_dict:
                headers["Cookie"] = "; ".join(f"{ck}={cv}" for ck, cv in cookie_dict.items())

            method = orig_req["method"]
            url = orig_req["url"]
            body = orig_req["body"]

            start_time = time.time()
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=body.encode("utf-8") if body else None,
                allow_redirects=False,
                timeout=10
            )
            elapsed = time.time() - start_time

            replayed_res = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text
            }

            score_details = self.calculate_similarity(orig_res, replayed_res)
            severity = self.classify_severity(orig_res, replayed_res, score_details)

            finding = {
                "id": f"FINDING-{len(self.results) + 1:03d}",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "endpoint": url,
                "path": url.split("?")[0],
                "method": method,
                "context": context_name,
                "severity": severity,
                "similarity_score": round(score_details["composite_score"], 4),
                "score_details": score_details,
                "original_request": orig_req,
                "original_response": orig_res,
                "replayed_request": {
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": body
                },
                "replayed_response": replayed_res
            }

            self.results.append(finding)
            print(f"[AuthDiff] Intercepted {method} {url} -> Replayed for {context_name}: Status={resp.status_code}, Severity={severity}, Sim={finding['similarity_score']}")

            self.save_results()

        except Exception as e:
            print(f"[AuthDiff] Error replaying request: {e}")

    def generate_diff_html(self, text_a, text_b):
        if not text_a and not text_b:
            return "<span class='text-slate-500' style='font-style: italic; font-family: monospace;'>No response bodies to diff</span>"

        # If texts are identical, don't generate empty unified diff
        if text_a == text_b:
            return "<span class='text-slate-400' style='font-style: italic; font-family: monospace; color: #22c55e;'>No differences detected between response bodies.</span>"

        lines_a = (text_a or "").splitlines()
        lines_b = (text_b or "").splitlines()
        diff = list(difflib.unified_diff(lines_a, lines_b, fromfile='Original', tofile='Replayed', lineterm=''))

        # Check if the unified diff contains meaningful changes
        has_changes = any(line.startswith('+') or line.startswith('-') for line in diff if not line.startswith('+++') and not line.startswith('---'))
        if not has_changes:
            return "<span class='text-slate-400' style='font-style: italic; font-family: monospace; color: #22c55e;'>No differences detected between response bodies.</span>"

        html_lines = []
        for line in diff:
            # Escape HTML characters safely
            escaped = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            if escaped.startswith('+') and not escaped.startswith('+++'):
                html_lines.append(f'<span class="diff-add" style="color: #4ade80; background-color: rgba(74, 222, 128, 0.15); display: block; font-family: monospace; white-space: pre-wrap; padding: 1px 4px;">{escaped}</span>')
            elif escaped.startswith('-') and not escaped.startswith('---'):
                html_lines.append(f'<span class="diff-del" style="color: #f87171; background-color: rgba(248, 113, 113, 0.15); display: block; font-family: monospace; white-space: pre-wrap; padding: 1px 4px;">{escaped}</span>')
            elif escaped.startswith('@@'):
                html_lines.append(f'<span class="diff-meta" style="color: #60a5fa; display: block; font-family: monospace; white-space: pre-wrap; padding: 1px 4px;">{escaped}</span>')
            else:
                html_lines.append(f'<span class="diff-ctx" style="color: #94a3b8; display: block; font-family: monospace; white-space: pre-wrap; padding: 1px 4px;">{escaped}</span>')
        return "\n".join(html_lines)

    def generate_html_report(self):
        total = len(self.results)
        critical = sum(1 for r in self.results if r["severity"] == "CRITICAL")
        warning = sum(1 for r in self.results if r["severity"] == "WARNING")
        enforced = sum(1 for r in self.results if "ENFORCED" in r["severity"])
        uncertain = sum(1 for r in self.results if r["severity"] == "UNCERTAIN")

        # HTML table rows
        rows_html = []
        for f in self.results:
            fid = f["id"]
            method = f["method"]
            endpoint = f["endpoint"]
            context = f["context"]
            severity = f["severity"]
            score = f["similarity_score"]
            status_orig = f["original_response"]["status_code"]
            status_repl = f["replayed_response"]["status_code"]

            # Severity badge styling
            if severity == "CRITICAL":
                sev_badge = '<span style="background-color: #ef4444; color: #ffffff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem;">CRITICAL</span>'
            elif severity == "WARNING":
                sev_badge = '<span style="background-color: #f97316; color: #ffffff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem;">WARNING</span>'
            elif "ENFORCED" in severity:
                sev_badge = '<span style="background-color: #22c55e; color: #ffffff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem;">ENFORCED</span>'
            else:
                sev_badge = '<span style="background-color: #3b82f6; color: #ffffff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem;">UNCERTAIN</span>'

            # Headers and bodies representation
            orig_headers_str = "\n".join(f"{k}: {v}" for k, v in f["original_request"]["headers"].items())
            repl_headers_str = "\n".join(f"{k}: {v}" for k, v in f["replayed_request"]["headers"].items())
            orig_resp_headers_str = "\n".join(f"{k}: {v}" for k, v in f["original_response"]["headers"].items())
            repl_resp_headers_str = "\n".join(f"{k}: {v}" for k, v in f["replayed_response"]["headers"].items())

            body_diff = self.generate_diff_html(f["original_response"]["body"], f["replayed_response"]["body"])

            row = f"""
            <tr class="table-row cursor-pointer hover:bg-slate-700/50 transition-colors" onclick="toggleDetails('{fid}')" data-severity="{severity}" data-method="{method}">
                <td style="padding: 12px; border-bottom: 1px solid #334155;">{fid}</td>
                <td style="padding: 12px; border-bottom: 1px solid #334155;"><span style="font-weight: bold; color: #e2e8f0;">{method}</span></td>
                <td style="padding: 12px; border-bottom: 1px solid #334155; font-family: monospace; color: #cbd5e1; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{endpoint}">{endpoint}</td>
                <td style="padding: 12px; border-bottom: 1px solid #334155; color: #cbd5e1;">{context}</td>
                <td style="padding: 12px; border-bottom: 1px solid #334155; font-family: monospace; color: #cbd5e1;">{status_orig} / {status_repl}</td>
                <td style="padding: 12px; border-bottom: 1px solid #334155; font-family: monospace; font-weight: bold; color: {'#ef4444' if score > 0.85 else '#cbd5e1'};">{score}</td>
                <td style="padding: 12px; border-bottom: 1px solid #334155;">{sev_badge}</td>
            </tr>
            <tr id="details-{fid}" class="details-row bg-slate-900/60" style="display: none;">
                <td colspan="7" style="padding: 20px; border-bottom: 1px solid #334155; background-color: #0b0f19;">
                    <div class="grid grid-cols-2 gap-6" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">

                        <!-- Left Panel: Original (User A) -->
                        <div class="panel border border-slate-700/60 p-4 rounded bg-slate-800/40" style="border: 1px solid #334155; padding: 15px; border-radius: 6px; background: rgba(30, 41, 59, 0.4);">
                            <h3 style="color: #60a5fa; font-weight: bold; margin-bottom: 10px; font-size: 1rem; border-bottom: 1px solid #334155; padding-bottom: 5px;">Original Session (User A - High Privilege)</h3>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 10px;">Request Headers</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #94a3b8; max-height: 200px;">{orig_headers_str}</pre>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 10px;">Request Body</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #cbd5e1; max-height: 200px;">{f["original_request"]["body"] or "[Empty Body]"}</pre>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 15px;">Response Headers</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #94a3b8; max-height: 200px;">{orig_resp_headers_str}</pre>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 10px;">Response Body</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #cbd5e1; max-height: 250px;">{f["original_response"]["body"] or "[Empty Response]"}</pre>
                        </div>

                        <!-- Right Panel: Replayed (User B/C) -->
                        <div class="panel border border-slate-700/60 p-4 rounded bg-slate-800/40" style="border: 1px solid #334155; padding: 15px; border-radius: 6px; background: rgba(30, 41, 59, 0.4);">
                            <h3 style="color: #f43f5e; font-weight: bold; margin-bottom: 10px; font-size: 1rem; border-bottom: 1px solid #334155; padding-bottom: 5px;">Replayed Session ({context})</h3>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 10px;">Request Headers</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #94a3b8; max-height: 200px;">{repl_headers_str}</pre>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 10px;">Request Body</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #cbd5e1; max-height: 200px;">{f["replayed_request"]["body"] or "[Empty Body]"}</pre>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 15px;">Response Headers</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #94a3b8; max-height: 200px;">{repl_resp_headers_str}</pre>

                            <h4 style="color: #94a3b8; font-size: 0.85rem; font-weight: bold; margin-top: 10px;">Response Body</h4>
                            <pre style="background-color: #020617; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #cbd5e1; max-height: 250px;">{f["replayed_response"]["body"] or "[Empty Response]"}</pre>
                        </div>
                    </div>

                    <!-- Line Diff Block -->
                    <div class="diff-block border border-slate-700/60 p-4 rounded bg-slate-800/40 mt-4" style="border: 1px solid #334155; padding: 15px; border-radius: 6px; background: rgba(30, 41, 59, 0.4); margin-top: 20px;">
                        <h3 style="color: #38bdf8; font-weight: bold; margin-bottom: 10px; font-size: 1rem; border-bottom: 1px solid #334155; padding-bottom: 5px;">Response Line Diff (difflib.unified_diff)</h3>
                        <div style="background-color: #020617; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; max-height: 400px; border: 1px solid #1e293b;">
                            {body_diff}
                        </div>
                    </div>
                </td>
            </tr>
            """
            rows_html.append(row)

        all_rows = "\n".join(rows_html)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthDiff - Access Control & IDOR Testing Report</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #e2e8f0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 0;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #1e293b;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .title-area h1 {{
            margin: 0;
            font-size: 2.2rem;
            color: #f43f5e;
            letter-spacing: -0.05em;
        }}
        .title-area p {{
            margin: 5px 0 0 0;
            color: #94a3b8;
            font-size: 1rem;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .metric-card.critical {{
            border-left: 5px solid #ef4444;
        }}
        .metric-card.warning {{
            border-left: 5px solid #f97316;
        }}
        .metric-card.enforced {{
            border-left: 5px solid #22c55e;
        }}
        .metric-card.uncertain {{
            border-left: 5px solid #3b82f6;
        }}
        .metric-label {{
            font-size: 0.85rem;
            color: #94a3b8;
            text-transform: uppercase;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .metric-value {{
            font-size: 1.8rem;
            font-weight: bold;
        }}
        .filter-section {{
            background-color: #111827;
            border: 1px solid #1f2937;
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 25px;
            display: flex;
            gap: 15px;
            align-items: center;
        }}
        .filter-label {{
            font-weight: bold;
            color: #94a3b8;
            font-size: 0.9rem;
        }}
        .filter-btn {{
            background-color: #1f2937;
            border: 1px solid #374151;
            color: #cbd5e1;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: bold;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background-color: #f43f5e;
            color: #ffffff;
            border-color: #f43f5e;
        }}
        .search-input {{
            background-color: #1f2937;
            border: 1px solid #374151;
            color: #cbd5e1;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.85rem;
            flex-grow: 1;
        }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #111827;
            border: 1px solid #1f2937;
            border-radius: 6px;
            overflow: hidden;
        }}
        .findings-table th {{
            background-color: #1f2937;
            color: #94a3b8;
            text-align: left;
            padding: 12px;
            font-weight: bold;
            font-size: 0.85rem;
            text-transform: uppercase;
            border-bottom: 2px solid #374151;
        }}
        .hidden {{
            display: none !important;
        }}
    </style>
    <script>
        let activeSeverity = "ALL";
        let activeMethod = "ALL";

        function filterTable() {{
            const searchVal = document.getElementById("searchBox").value.toLowerCase();
            const rows = document.querySelectorAll(".table-row");

            rows.forEach(row => {{
                const id = row.querySelector("td:nth-child(1)").textContent.toLowerCase();
                const method = row.querySelector("td:nth-child(2)").textContent.toLowerCase();
                const path = row.querySelector("td:nth-child(3)").textContent.toLowerCase();
                const severity = row.getAttribute("data-severity");
                const rowMethod = row.getAttribute("data-method");

                const matchesSearch = id.includes(searchVal) || method.includes(searchVal) || path.includes(searchVal);
                const matchesSeverity = (activeSeverity === "ALL" || severity === activeSeverity);
                const matchesMethod = (activeMethod === "ALL" || rowMethod === activeMethod);

                const detailsRow = document.getElementById("details-" + row.querySelector("td:nth-child(1)").textContent.trim());

                if (matchesSearch && matchesSeverity && matchesMethod) {{
                    row.classList.remove("hidden");
                }} else {{
                    row.classList.add("hidden");
                    if (detailsRow) {{
                        detailsRow.style.display = "none";
                    }}
                }}
            }});
        }}

        function setSeverityFilter(sev, btn) {{
            activeSeverity = sev;
            document.querySelectorAll(".sev-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            filterTable();
        }}

        function toggleDetails(id) {{
            const detailsRow = document.getElementById("details-" + id);
            if (detailsRow.style.display === "none" || detailsRow.style.display === "") {{
                detailsRow.style.display = "table-row";
            }} else {{
                detailsRow.style.display = "none";
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title-area">
                <h1>AuthDiff</h1>
                <p>Autonomous Access Control (BAC/IDOR) Testing Engine Report</p>
            </div>
            <div class="time-stamp" style="color: #64748b; font-size: 0.9rem;">
                Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>

        <!-- executive dashboard -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Analyzed</div>
                <div class="metric-value">{total}</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical Findings</div>
                <div class="metric-value" style="color: #ef4444;">{critical}</div>
            </div>
            <div class="metric-card warning">
                <div class="metric-label">Warning (Suspicious)</div>
                <div class="metric-value" style="color: #f97316;">{warning}</div>
            </div>
            <div class="metric-card enforced">
                <div class="metric-label">Enforced (Secure)</div>
                <div class="metric-value" style="color: #22c55e;">{enforced}</div>
            </div>
            <div class="metric-card uncertain">
                <div class="metric-label">Uncertain</div>
                <div class="metric-value" style="color: #3b82f6;">{uncertain}</div>
            </div>
        </div>

        <!-- filtering section -->
        <div class="filter-section">
            <span class="filter-label">Severity:</span>
            <button class="filter-btn active sev-btn" onclick="setSeverityFilter('ALL', this)">All</button>
            <button class="filter-btn sev-btn" onclick="setSeverityFilter('CRITICAL', this)">Critical</button>
            <button class="filter-btn sev-btn" onclick="setSeverityFilter('WARNING', this)">Warning</button>
            <button class="filter-btn sev-btn" onclick="setSeverityFilter('INFO / ENFORCED', this)">Enforced</button>
            <button class="filter-btn sev-btn" onclick="setSeverityFilter('UNCERTAIN', this)">Uncertain</button>

            <input type="text" id="searchBox" class="search-input" placeholder="Search by ID, Method, or Path..." oninput="filterTable()">
        </div>

        <!-- findings table -->
        <table class="findings-table">
            <thead>
                <tr>
                    <th style="padding: 12px; width: 10%;">ID</th>
                    <th style="padding: 12px; width: 10%;">Method</th>
                    <th style="padding: 12px; width: 40%;">Endpoint / Path</th>
                    <th style="padding: 12px; width: 15%;">Context Tested</th>
                    <th style="padding: 12px; width: 10%;">Status Code (A/B)</th>
                    <th style="padding: 12px; width: 10%;">Sim Score</th>
                    <th style="padding: 12px; width: 10%;">Severity</th>
                </tr>
            </thead>
            <tbody>
                {all_rows if all_rows else '<tr><td colspan="7" style="padding: 20px; text-align: center; color: #64748b;">No intercepted requests replayed yet. Ensure requests match target scopes and trigger in the proxy.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        return html_template

    def save_results(self):
        with self.lock:
            output_json = "authdiff_results.json"
            output_html = "authdiff_report.html"
            try:
                if "ctx" in globals() and ctx and ctx.options:
                    output_json = ctx.options.output_json
                    output_html = ctx.options.output_html
            except Exception:
                pass

            try:
                data = {
                    "scan_metadata": {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "target_scope": self.scope_domains,
                        "total_requests": len(self.results)
                    },
                    "vulnerabilities": self.results
                }
                with open(output_json, "w") as f:
                    json.dump(data, f, indent=2)
                print(f"[AuthDiff] Wrote machine-readable findings to {output_json}")
            except Exception as e:
                print(f"[AuthDiff] Error saving JSON findings: {e}")

            try:
                html_content = self.generate_html_report()
                with open(output_html, "w") as f:
                    f.write(html_content)
                print(f"[AuthDiff] Wrote interactive HTML report to {output_html}")
            except Exception as e:
                print(f"[AuthDiff] Error saving HTML report: {e}")

    def response(self, flow):
        if "X-AuthDiff-Replayed" in flow.request.headers:
            return

        host = flow.request.host
        in_scope = False
        for domain in self.scope_domains:
            if domain in host or host == domain:
                in_scope = True
                break
        if not in_scope:
            return

        path = flow.request.path.split("?")[0]
        for ext in self.ignore_extensions:
            if path.endswith(ext):
                return

        self.process_and_replay(flow)

    def done(self):
        self.save_results()


# Register addon for mitmproxy
addons = [
    AuthDiff()
]
