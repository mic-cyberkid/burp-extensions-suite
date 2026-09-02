# -*- coding: utf-8 -*-
"""
FieldbookLogic.py - Core data model, thread-safe store, atomic persistence,
debounced saving, search/filtering, Markdown parsing, and export generation for Fieldbook.
"""

import os
import json
import time
import uuid
import re
import threading

ENTRY_TYPES = ["NOTE", "OBSERVATION", "HYPOTHESIS", "TEST_RESULT", "EVIDENCE"]

ENTRY_TYPE_COLORS = {
    "NOTE": "#2196F3",         # Blue
    "OBSERVATION": "#9C27B0",  # Purple
    "HYPOTHESIS": "#FF9800",   # Orange
    "TEST_RESULT": "#4CAF50",  # Green
    "EVIDENCE": "#E91E63"      # Pink/Red
}

class FieldbookEntry(object):
    """
    Data model representing a single research note in Fieldbook.
    """
    def __init__(self, entry_id=None, entry_type="NOTE", content="", target="", tags=None,
                 created_at=None, updated_at=None, linked_requests=None):
        self.id = entry_id or "fb_" + str(uuid.uuid4())[:8] + "_" + str(int(time.time()))
        self.type = entry_type if entry_type in ENTRY_TYPES else "NOTE"
        self.content = content or ""
        self.target = target or ""
        self.tags = list(tags) if tags else []
        now = time.time()
        self.created_at = created_at if created_at is not None else now
        self.updated_at = updated_at if updated_at is not None else now
        self.linked_requests = list(linked_requests) if linked_requests else []

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "content": self.content,
            "target": self.target,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "linked_requests": self.linked_requests
        }

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Invalid entry data format")
        return cls(
            entry_id=data.get("id"),
            entry_type=data.get("type", "NOTE"),
            content=data.get("content", ""),
            target=data.get("target", ""),
            tags=data.get("tags", []),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            linked_requests=data.get("linked_requests", [])
        )


class FieldbookStore(object):
    """
    Thread-safe store for managing Fieldbook entries with debounced atomic persistence.
    """
    def __init__(self, filepath=None, debounce_interval=1.0):
        if filepath is None:
            home = os.path.expanduser("~")
            fb_dir = os.path.join(home, ".fieldbook")
            if not os.path.exists(fb_dir):
                try:
                    os.makedirs(fb_dir)
                except Exception:
                    pass
            filepath = os.path.join(fb_dir, "notebook.json")

        self.filepath = filepath
        self.debounce_interval = debounce_interval
        self.lock = threading.Lock()
        self.entries = {}  # id -> FieldbookEntry
        self._save_timer = None
        self._corrupt_backup_path = None

        self.load()

    def set_filepath(self, filepath):
        with self.lock:
            self.filepath = filepath
            dir_path = os.path.dirname(filepath)
            if dir_path and not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path)
                except Exception:
                    pass

    def load(self):
        """
        Loads entries from the JSON persistence file.
        Missing file -> starts empty.
        Corrupt/unreadable file -> renames bad file to .bak and starts empty.
        """
        with self.lock:
            self.entries = {}
            if not os.path.exists(self.filepath):
                return

            try:
                with open(self.filepath, "r") as f:
                    raw = f.read()

                if not raw.strip():
                    return

                data = json.loads(raw)
                if isinstance(data, list):
                    for item in data:
                        try:
                            entry = FieldbookEntry.from_dict(item)
                            self.entries[entry.id] = entry
                        except Exception:
                            pass
                elif isinstance(data, dict) and "entries" in data:
                    for item in data.get("entries", []):
                        try:
                            entry = FieldbookEntry.from_dict(item)
                            self.entries[entry.id] = entry
                        except Exception:
                            pass
                else:
                    raise ValueError("JSON content does not contain an entry list")
            except Exception as e:
                # File is corrupt or unreadable: backup bad file as .bak
                bak_path = self.filepath + ".bak"
                try:
                    if os.path.exists(bak_path):
                        os.remove(bak_path)
                    os.rename(self.filepath, bak_path)
                    self._corrupt_backup_path = bak_path
                except Exception:
                    pass
                self.entries = {}

    def save_immediate(self):
        """
        Saves all entries immediately using an atomic write (write to .tmp then replace).
        """
        with self.lock:
            if self._save_timer:
                try:
                    self._save_timer.cancel()
                except Exception:
                    pass
                self._save_timer = None

            dir_path = os.path.dirname(self.filepath)
            if dir_path and not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path)
                except Exception:
                    pass

            tmp_path = self.filepath + ".tmp"
            data_list = [entry.to_dict() for entry in sorted(self.entries.values(), key=lambda x: x.created_at)]
            payload = json.dumps(data_list, indent=2, ensure_ascii=False)

            with open(tmp_path, "w") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())

            if hasattr(os, "replace"):
                os.replace(tmp_path, self.filepath)
            else:
                if os.path.exists(self.filepath):
                    os.remove(self.filepath)
                os.rename(tmp_path, self.filepath)

    def schedule_save(self):
        """
        Schedules a debounced auto-save.
        """
        with self.lock:
            if self._save_timer:
                try:
                    self._save_timer.cancel()
                except Exception:
                    pass
            self._save_timer = threading.Timer(self.debounce_interval, self._on_debounce_timer)
            self._save_timer.daemon = True
            self._save_timer.start()

    def _on_debounce_timer(self):
        try:
            self.save_immediate()
        except Exception:
            pass

    def add_entry(self, entry, immediate=False):
        with self.lock:
            entry.updated_at = time.time()
            self.entries[entry.id] = entry

        if immediate:
            self.save_immediate()
        else:
            self.schedule_save()
        return entry

    def update_entry(self, entry_id, content=None, entry_type=None, target=None, tags=None, linked_requests=None, immediate=False):
        with self.lock:
            if entry_id not in self.entries:
                return None
            entry = self.entries[entry_id]
            if content is not None:
                entry.content = content
            if entry_type is not None and entry_type in ENTRY_TYPES:
                entry.type = entry_type
            if target is not None:
                entry.target = target
            if tags is not None:
                entry.tags = list(tags)
            if linked_requests is not None:
                entry.linked_requests = list(linked_requests)
            entry.updated_at = time.time()

        if immediate:
            self.save_immediate()
        else:
            self.schedule_save()
        return entry

    def delete_entry(self, entry_id, immediate=False):
        with self.lock:
            if entry_id in self.entries:
                del self.entries[entry_id]

        if immediate:
            self.save_immediate()
        else:
            self.schedule_save()

    def get_entry(self, entry_id):
        with self.lock:
            return self.entries.get(entry_id)

    def get_all_entries(self):
        with self.lock:
            return sorted(self.entries.values(), key=lambda x: x.updated_at, reverse=True)

    def get_targets(self):
        with self.lock:
            targets = set()
            for entry in self.entries.values():
                if entry.target.strip():
                    targets.add(entry.target.strip())
            return sorted(list(targets))

    def get_tags(self):
        with self.lock:
            tags = set()
            for entry in self.entries.values():
                for tag in entry.tags:
                    if tag.strip():
                        tags.add(tag.strip())
            return sorted(list(tags))

    def search_entries(self, query="", entry_type="ALL", target="ALL", tag="ALL"):
        with self.lock:
            results = []
            q = query.lower().strip() if query else ""
            filter_type = entry_type.upper().strip() if entry_type else "ALL"
            filter_target = target.strip() if target else "ALL"
            filter_tag = tag.strip() if tag else "ALL"

            for entry in self.entries.values():
                # Entry type check
                if filter_type != "ALL" and entry.type != filter_type:
                    continue

                # Target check
                if filter_target != "ALL":
                    if filter_target.lower() not in entry.target.lower():
                        continue

                # Tag check
                if filter_tag != "ALL":
                    if not any(filter_tag.lower() == t.lower() for t in entry.tags):
                        continue

                # Text query search across content, target, tags, and type
                if q:
                    content_match = q in entry.content.lower()
                    target_match = q in entry.target.lower()
                    tags_match = any(q in t.lower() for t in entry.tags)
                    type_match = q in entry.type.lower()
                    if not (content_match or target_match or tags_match or type_match):
                        continue

                results.append(entry)

            return sorted(results, key=lambda x: x.updated_at, reverse=True)


class MarkdownParser(object):
    """
    Simple Markdown-to-HTML parser supporting headers, bold, italic, lists,
    inline code, code blocks, links, and #req:N reference syntax.
    """
    @staticmethod
    def to_html(markdown_text):
        if not markdown_text:
            return "<html><body></body></html>"

        lines = markdown_text.splitlines()
        html_lines = []
        in_code_block = False
        in_list = False

        for line in lines:
            # Code blocks
            if line.strip().startswith("```"):
                if in_code_block:
                    html_lines.append("</code></pre>")
                    in_code_block = False
                else:
                    if in_list:
                        html_lines.append("</ul>")
                        in_list = False
                    html_lines.append("<pre><code>")
                    in_code_block = True
                continue

            if in_code_block:
                escaped = MarkdownParser._escape_html(line)
                html_lines.append(escaped + "\n")
                continue

            # List items
            stripped = line.strip()
            if stripped.startswith("- ") or stripped.startswith("* "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                item_content = stripped[2:]
                html_lines.append("<li>" + MarkdownParser._parse_inline(item_content) + "</li>")
                continue
            else:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False

            # Empty lines
            if not stripped:
                html_lines.append("<br/>")
                continue

            # Headers
            if stripped.startswith("### "):
                html_lines.append("<h3>" + MarkdownParser._parse_inline(stripped[4:]) + "</h3>")
            elif stripped.startswith("## "):
                html_lines.append("<h2>" + MarkdownParser._parse_inline(stripped[3:]) + "</h2>")
            elif stripped.startswith("# "):
                html_lines.append("<h1>" + MarkdownParser._parse_inline(stripped[2:]) + "</h1>")
            else:
                html_lines.append("<p>" + MarkdownParser._parse_inline(stripped) + "</p>")

        if in_code_block:
            html_lines.append("</code></pre>")
        if in_list:
            html_lines.append("</ul>")

        body = "".join(html_lines)
        style = (
            "<style>"
            "body { font-family: sans-serif; font-size: 13px; line-height: 1.4; margin: 8px; color: #222; }"
            "h1 { font-size: 18px; margin: 8px 0 4px 0; color: #111; }"
            "h2 { font-size: 16px; margin: 6px 0 4px 0; color: #222; }"
            "h3 { font-size: 14px; margin: 4px 0 2px 0; color: #333; }"
            "code { background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-family: monospace; font-size: 12px; }"
            "pre { background-color: #f8f8f8; padding: 8px; border: 1px solid #ddd; border-radius: 4px; overflow-x: auto; }"
            "a { color: #0066cc; text-decoration: none; font-weight: bold; }"
            "a:hover { text-decoration: underline; }"
            "ul { margin: 4px 0 4px 20px; padding: 0; }"
            "p { margin: 4px 0; }"
            "</style>"
        )
        return "<html><head>" + style + "</head><body>" + body + "</body></html>"

    @staticmethod
    def _escape_html(text):
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @staticmethod
    def _parse_inline(text):
        escaped = MarkdownParser._escape_html(text)

        # Inline code: `code`
        escaped = re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped)

        # Bold: **text**
        escaped = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', escaped)

        # Italic: *text*
        escaped = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', escaped)

        # Markdown links: [label](url)
        escaped = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', escaped)

        # #req:N reference links (e.g. #req:1 -> <a href="req:1">#req:1</a>)
        escaped = re.sub(r'#req:(\d+)', r'<a href="req:\1">#req:\1</a>', escaped)

        return escaped


class FieldbookExporter(object):
    """
    Generates Markdown or JSON exports from a list of FieldbookEntries.
    """
    @staticmethod
    def export_markdown(entries):
        """
        Exports entries grouped by Target, chronological within each target group,
        with linked requests rendered as blockquotes.
        """
        # Group entries by Target
        targets = {}
        for entry in entries:
            target_key = entry.target.strip() if entry.target and entry.target.strip() else "Unassigned Target"
            if target_key not in targets:
                targets[target_key] = []
            targets[target_key].append(entry)

        output_lines = ["# Fieldbook Research Report", ""]

        for target_name in sorted(targets.keys()):
            output_lines.append("## Target: " + target_name)
            output_lines.append("")

            # Chronological order within target
            sorted_entries = sorted(targets[target_name], key=lambda x: x.created_at)

            for entry in sorted_entries:
                created_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.created_at))
                output_lines.append("### [" + entry.type + "] " + created_str)

                if entry.tags:
                    output_lines.append("**Tags:** " + ", ".join(entry.tags))
                    output_lines.append("")

                if entry.content:
                    output_lines.append(entry.content)
                    output_lines.append("")

                if entry.linked_requests:
                    output_lines.append("**Linked Requests:**")
                    for req in entry.linked_requests:
                        req_id = req.get("id", "?")
                        method = req.get("method", "HTTP")
                        host = req.get("host", "")
                        path = req.get("path", "")
                        url = req.get("url", method + " " + host + path)
                        output_lines.append("> **#req:" + str(req_id) + ":** `" + method + " " + host + path + "` (" + url + ")")
                    output_lines.append("")

                output_lines.append("---")
                output_lines.append("")

        return "\n".join(output_lines)

    @staticmethod
    def export_json(entries):
        """
        Exports entries as formatted JSON.
        """
        data = [entry.to_dict() for entry in entries]
        return json.dumps(data, indent=2, ensure_ascii=False)
