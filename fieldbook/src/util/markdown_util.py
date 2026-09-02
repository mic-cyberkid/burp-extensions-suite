"""
Lightweight Markdown to HTML converter for Fieldbook JEditorPane rendering.
Includes #req:N deep linking token parsing.
"""

import re

try:
    import html
    def escape_html(text):
        if not text:
            return ""
        return html.escape(text)
except ImportError:
    import cgi
    def escape_html(text):
        if not text:
            return ""
        return cgi.escape(text, quote=True)

def markdown_to_html(md_text, linked_requests=None):
    """
    Converts lightweight Markdown text into an HTML string suitable for JEditorPane.
    Supported elements:
    - Headings (# , ## , ### )
    - Bold (**text** or __text__)
    - Italic (*text* or _text_)
    - Inline code (`code`) and Code blocks (```code```)
    - Links ([text](url))
    - Unordered lists (- item or * item)
    - Deep linking tokens (#req:N or #req:1, #req:2)
    """
    if not md_text:
        return "<html><body></body></html>"

    lines = md_text.splitlines()
    in_code_block = False
    html_lines = []
    in_list = False

    for line in lines:
        # Check code block toggle
        if line.strip().startswith("```"):
            if in_code_block:
                in_code_block = False
                html_lines.append("</pre></div>")
            else:
                in_code_block = True
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append("<div style='background-color:#f3f4f6; padding:8px; border-radius:4px;'><pre style='font-family:monospace; margin:0;'>")
            continue

        if in_code_block:
            html_lines.append(escape_html(line))
            continue

        # Check lists
        stripped = line.strip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                in_list = True
                html_lines.append("<ul style='margin-top:4px; margin-bottom:4px; padding-left:20px;'>")
            item_text = stripped[2:]
            formatted_item = _format_inline(escape_html(item_text))
            html_lines.append("<li>" + formatted_item + "</li>")
            continue
        else:
            if in_list:
                html_lines.append("</ul>")
                in_list = False

        if not line.strip():
            html_lines.append("<br/>")
            continue

        # Check Headings
        if line.startswith("# "):
            h_text = _format_inline(escape_html(line[2:]))
            html_lines.append("<h1 style='font-size:18px; margin-top:8px; margin-bottom:4px; color:#1e293b;'>" + h_text + "</h1>")
            continue
        elif line.startswith("## "):
            h_text = _format_inline(escape_html(line[3:]))
            html_lines.append("<h2 style='font-size:16px; margin-top:6px; margin-bottom:4px; color:#334155;'>" + h_text + "</h2>")
            continue
        elif line.startswith("### "):
            h_text = _format_inline(escape_html(line[4:]))
            html_lines.append("<h3 style='font-size:14px; margin-top:4px; margin-bottom:2px; color:#475569;'>" + h_text + "</h3>")
            continue

        # Regular paragraph
        formatted_line = _format_inline(escape_html(line))
        html_lines.append("<p style='margin-top:2px; margin-bottom:4px; line-height:1.4;'>" + formatted_line + "</p>")

    if in_list:
        html_lines.append("</ul>")
    if in_code_block:
        html_lines.append("</pre></div>")

    content = "\n".join(html_lines)

    body_html = """<html>
<head>
<style>
body { font-family: sans-serif; font-size: 13px; color: #1e293b; margin: 8px; }
a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }
code { background-color: #f1f5f9; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
.req-link { background-color: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-decoration: none; border: 1px solid #bae6fd; }
.note-link { background-color: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-decoration: none; border: 1px solid #fde68a; }
</style>
</head>
<body>
""" + content + """
</body>
</html>"""

    return body_html

def _format_inline(escaped_text):
    """Formats inline bold, italic, code, links, and #req:N / #note:ID tokens."""
    # Inline code
    escaped_text = re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped_text)

    # Bold
    escaped_text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', escaped_text)
    escaped_text = re.sub(r'__([^_]+)__', r'<b>\1</b>', escaped_text)

    # Italic
    escaped_text = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', escaped_text)
    escaped_text = re.sub(r'_([^_]+)_', r'<i>\1</i>', escaped_text)

    # Links [text](url)
    escaped_text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', escaped_text)

    # #req:N token (e.g., #req:1 or #req:2)
    escaped_text = re.sub(
        r'#req:([0-9]+)',
        r'<a class="req-link" href="req:\1">#req:\1</a>',
        escaped_text
    )

    # #note:UUID token (e.g., #note:12345)
    escaped_text = re.sub(
        r'#note:([a-zA-Z0-9\-]+)',
        r'<a class="note-link" href="note:\1">#note:\1</a>',
        escaped_text
    )

    return escaped_text
