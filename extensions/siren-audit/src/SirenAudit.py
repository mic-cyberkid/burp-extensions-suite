# -*- coding: utf-8 -*-
"""
Siren Security Audit Assistant - Burp Suite Extension (Python / Jython)

Captures HTTP request/response pairs from Burp Suite (Proxy, Repeater, Logger,
Target/Site map) under operator-labeled roles (e.g. Unauthenticated, User A /
Tenant A, User B / Tenant B, or any custom label) and dispatches the bundle to
the Jules REST API (https://jules.google/docs/api/reference/) for analysis,
using the AGENTS.md file in this repo as the agent's operating rules.

Requirements: Burp Suite with a Jython 2.7 standalone JAR configured under
Extender > Options > Python Environment, and a Jules API key
(https://jules.google.com -> Settings -> API keys).

What this extension does NOT do:
  - It never sends anything to Jules until you click Dispatch (Preview Bundle
    and Copy Prompt let you inspect the exact payload first).
  - It never replays a captured request itself; it only forwards what Burp
    already captured. Any live re-testing is left to Jules to *propose*,
    per AGENTS.md's operator-approval gating, and to you to actually run.
  - It does not submit anything to a bug bounty program on your behalf.

Key behaviors worth knowing about:
  - Both the request AND the response of each captured item are sent (not
    just the request) -- differential auth analysis needs to see what data
    actually came back under each role.
  - Authorization/Cookie/Set-Cookie/API-key-shaped headers and common
    password/token/secret-shaped body fields are redacted by default before
    anything leaves Burp. This is a best-effort heuristic, not a guarantee --
    review what you're sending, especially for unusual auth schemes.
  - All network calls to the Jules API run on a background thread; the Burp
    UI is never blocked waiting on them.
  - Connection settings (source, branch, task type, automation preferences)
    persist across Burp restarts via Burp's extension settings. The API key
    is only persisted if you explicitly check "Remember".

Multiple sessions: this extension tracks any number of Jules sessions at
once, not just one. "Dispatch as New Session" always starts a fresh one;
"Send as Follow-up to Selected Session" targets whichever row is selected
in the Jules Sessions table. Each tracked session keeps its own status, PR
list, and activity log; a single Auto-refresh toggle polls every tracked
session that isn't finished yet. The tracked list (session IDs, titles,
task types -- not their content) persists across Burp restarts the same
way the connection settings do.

--------------------------------------------------------------------------
UI NOTE: this file's presentation layer (UITheme / RoundedButton /
ZebraTableCellRenderer / the _build_*_panel and small _style_*/_label/_btn/
_field_row helpers on BurpExtender) was restyled for visual hierarchy and
Burp dark/light-mode support. None of it changes what the extension does --
every redaction rule, API call, event handler and piece of persisted state
below is unchanged. See the accompanying summary for details.
--------------------------------------------------------------------------
"""

import json
import re
import socket
import time
import threading
import urllib
import urllib2

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener

from java.awt import (BorderLayout, FlowLayout, Dimension, Color, Font,
                       Toolkit, Desktop, Cursor, RenderingHints, BasicStroke)
from java.awt.datatransfer import StringSelection
from java.awt.event import ItemEvent, MouseAdapter
from java.net import URI
from java.io import File
from java.lang import Object

from javax.swing import (
    JPanel, JLabel, JTextField, JPasswordField, JButton, JMenuItem, JCheckBox,
    JComboBox, JTextArea, JTextPane, JScrollPane, BorderFactory, BoxLayout, Box,
    SwingUtilities, JOptionPane, JTable, JSplitPane, JSpinner, SpinnerNumberModel,
    DefaultComboBoxModel, JPopupMenu, JFileChooser, JList, DefaultListModel,
    ListSelectionModel, UIManager
)
from javax.swing import Timer as SwingTimer
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.text import SimpleAttributeSet, StyleConstants


# ---------------------------------------------------------------------------
# Module-level constants (audit/business logic -- unchanged by the redesign)
# ---------------------------------------------------------------------------

# Kept identical to the SENSITIVE_HEADERS set in app-mapping-crawl/crawl.py so
# redaction behaves consistently across every tool in this repo.
SENSITIVE_HEADERS = set(["authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"])

# Best-effort redaction of secret-shaped fields inside JSON/form bodies.
# Deliberately conservative (word-boundaried key list) to avoid mangling
# bodies beyond recognition; this is a safety net, not a guarantee.
BODY_SECRET_KEY_RE = re.compile(
    r'(?i)("?\b(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|'
    r'access[_-]?token|refresh[_-]?token|session[_-]?id|jwt|bearer)\b"?\s*[:=]\s*)'
    r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^&\s,}]+)'
)

# application/x-www-form-urlencoded deliberately does NOT match here -- it is
# text, and it is exactly the kind of body (login forms, reset forms) this
# tool most needs to inspect.
BINARY_CONTENT_TYPE_PREFIXES = ("image/", "audio/", "video/", "font/")
BINARY_CONTENT_TYPES_EXACT = set([
    "application/octet-stream", "application/pdf", "application/zip",
    "application/gzip", "application/x-gzip", "application/x-tar",
    "application/x-rar-compressed", "application/x-7z-compressed",
    "application/wasm", "application/x-shockwave-flash",
])
BINARY_CONTENT_TYPE_VND_RE = re.compile(r'(?i)^application/vnd\.')

# Semantic color role for each Jules session state (rendered by the theme --
# see SessionStateCellRenderer). Same categories as before; only the
# representation changed from hardcoded RGB to a theme-resolved role so the
# palette can adapt to Burp's current Look and Feel.
STATE_COLOR_ROLE = {
    "QUEUED": "neutral",
    "PLANNING": "info",
    "AWAITING_PLAN_APPROVAL": "warning",
    "AWAITING_USER_FEEDBACK": "warning",
    "IN_PROGRESS": "info",
    "PAUSED": "neutral",
    "COMPLETED": "success",
    "FAILED": "danger",
}

# Maps each Task Type option to (skill_name_or_None, framing_text). Keep the
# skill names in sync with the folder names in the repo root.
TASK_FRAMING = {
    "Differential Authorization Review (IDOR / BOLA)": (
        "burp-bundle-differential-audit",
        "Use the `burp-bundle-differential-audit` skill as the primary methodology for this bundle."
    ),
    "Email Ownership Bypass Review": (
        "email-ownership-bypass-audit",
        "Frame this analysis using the `email-ownership-bypass-audit` skill's ownership-binding "
        "oracle. The bundle below is evidence already captured by the operator in Burp Suite -- "
        "it is not a live trigger of the flow. If a live re-test of a specific step looks "
        "warranted, propose the exact request per that skill's gating and wait for the operator "
        "rather than sending it yourself."
    ),
    "Web Cache Poisoning Review": (
        "web-cache-poisoning-audit",
        "Frame this analysis using the `web-cache-poisoning-audit` skill's cache-poisoning oracle: "
        "a shared cache, an unkeyed input influencing the response, and that response being served "
        "back on the same cache-busted path. If confirming the oracle needs another live probe not "
        "already in this bundle, propose it per that skill's gating rules rather than sending it."
    ),
    "App Surface / Role Mapping Review": (
        "app-mapping-crawl",
        "Frame this analysis using the `app-mapping-crawl` skill's role-diff logic: treat the roles "
        "in this bundle like separate crawl passes, and look for (method, endpoint) pairs reached "
        "under a higher-privileged role that a lower-privileged role's captured requests never "
        "reached. GET-shaped candidates are reasonable to flag for a quick manual replay check; "
        "mutating candidates need explicit operator sign-off before any replay, per that skill's "
        "guardrails."
    ),
    "Custom / Freeform": (
        None,
        "No specific built-in skill is being pinned for this bundle. Analyze it using the general "
        "audit methodology and gating rules in AGENTS.md (hypothesize, propose, wait for approval, "
        "execute, validate), guided primarily by the operator's hypothesis below."
    ),
}


# ---------------------------------------------------------------------------
# Theme system
#
# Burp extensions built on the legacy IBurpExtender API don't get a direct
# "give me Burp's current theme" callback the way Montoya extensions do. The
# practical workaround -- used here -- is to ask Swing's own UIManager for
# the background color Burp's Look and Feel has already installed for plain
# panels, and derive everything else from that single real value. That means
# section/row backgrounds always match whatever Burp is actually running
# (dark or light, whatever the exact shade) instead of guessing at it, while
# the semantic accent/success/warning/danger colors come from two curated,
# contrast-checked palettes selected by measured luminance.
#
# The theme is resolved once, when the tab is first built. Burp doesn't hot-
# swap a running extension's UI if you flip its own theme afterwards, so
# this matches the tab's usual lifecycle; reload the extension after a Burp
# theme change to re-detect.
# ---------------------------------------------------------------------------

def _relative_luminance(color):
    return 0.299 * color.getRed() + 0.587 * color.getGreen() + 0.114 * color.getBlue()


def _shade(color, delta):
    """Nudges an RGB color toward lighter (positive delta) or darker
    (negative), clamped to a valid channel range. Used to derive section/row/
    hover/press backgrounds directly from a real base color rather than a
    second set of hardcoded constants that could drift out of sync with it."""
    r = max(0, min(255, color.getRed() + delta))
    g = max(0, min(255, color.getGreen() + delta))
    b = max(0, min(255, color.getBlue() + delta))
    return Color(r, g, b)


class UITheme(object):
    """Resolves a small set of semantic colors/fonts once at UI build time,
    based on whether Burp is currently running a dark or light Look and
    Feel. Every panel/component below reads from here rather than
    hardcoding RGB triples, so the whole console shifts consistently."""

    LABEL_FONT = Font("SansSerif", Font.PLAIN, 12)
    LABEL_BOLD_FONT = Font("SansSerif", Font.BOLD, 12)
    HINT_FONT = Font("SansSerif", Font.ITALIC, 11)
    TITLE_FONT = Font("SansSerif", Font.BOLD, 20)
    MONO_FONT = Font("Monospaced", Font.PLAIN, 12)
    MONO_FONT_SMALL = Font("Monospaced", Font.PLAIN, 11)

    def __init__(self):
        base_bg = None
        try:
            base_bg = UIManager.getColor("Panel.background")
        except Exception:
            base_bg = None
        if base_bg is None:
            base_bg = Color(240, 240, 240)

        self.dark = _relative_luminance(base_bg) < 128
        self.base_bg = base_bg

        # Backgrounds derived from Burp's real detected background so cards
        # and striped rows always read as "a deliberate step away from the
        # surrounding chrome" rather than clashing with whatever theme Burp
        # actually has active.
        self.section_bg = _shade(base_bg, 9 if self.dark else -7)
        self.row_alt_bg = _shade(base_bg, 16 if self.dark else -13)
        self.input_bg = _shade(base_bg, -8 if self.dark else 3)
        self.header_bg = _shade(base_bg, 18 if self.dark else -16)

        if self.dark:
            self.text_primary = Color(226, 228, 231)
            self.text_secondary = Color(168, 172, 178)
            self.text_muted = Color(128, 132, 138)
            self.divider = Color(80, 83, 88)
            self.input_border = Color(90, 94, 100)
            self.accent = Color(90, 156, 224)
            self.accent_hover = Color(112, 173, 234)
            self.accent_press = Color(70, 130, 194)
            self.accent_fg = Color(20, 22, 24)
            self.success = Color(96, 191, 130)
            self.warning = Color(232, 168, 76)
            self.danger = Color(232, 110, 100)
            self.neutral = Color(150, 154, 160)
            self.chip_fg = Color(24, 26, 28)
        else:
            self.text_primary = Color(31, 33, 36)
            self.text_secondary = Color(90, 95, 102)
            self.text_muted = Color(138, 142, 148)
            self.divider = Color(210, 213, 218)
            self.input_border = Color(196, 200, 206)
            self.accent = Color(28, 98, 176)
            self.accent_hover = Color(46, 116, 194)
            self.accent_press = Color(18, 80, 150)
            self.accent_fg = Color(255, 255, 255)
            self.success = Color(38, 128, 74)
            self.warning = Color(178, 116, 12)
            self.danger = Color(184, 56, 46)
            self.neutral = Color(110, 114, 120)
            self.chip_fg = Color(255, 255, 255)

    def role_color(self, role):
        return {
            "success": self.success,
            "warning": self.warning,
            "danger": self.danger,
            "info": self.accent,
            "neutral": self.neutral,
        }.get(role, self.text_secondary)

    def http_status_role(self, status_text):
        try:
            code = int(status_text)
        except Exception:
            return "neutral"
        if 200 <= code < 300:
            return "success"
        if 300 <= code < 400:
            return "info"
        if 400 <= code < 500:
            return "warning"
        if code >= 500:
            return "danger"
        return "neutral"


class _RoundedButtonHover(MouseAdapter):
    """Drives a RoundedButton's hover/press repaint. Kept as a separate
    listener (rather than overriding mouse methods on the button itself) so
    RoundedButton's own method surface stays a plain JButton surface."""

    def __init__(self, button):
        self.button = button

    def mouseEntered(self, event):
        self.button.hovering = True
        self.button.repaint()

    def mouseExited(self, event):
        self.button.hovering = False
        self.button.pressed = False
        self.button.repaint()

    def mousePressed(self, event):
        self.button.pressed = True
        self.button.repaint()

    def mouseReleased(self, event):
        self.button.pressed = False
        self.button.repaint()


class RoundedButton(JButton):
    """A flat, rounded-corner JButton with real hover / press / focus /
    disabled states. Same JButton surface as a plain button (construct with
    text, then addActionListener/setEnabled/setToolTipText as usual) -- only
    the painting differs -- so it drops in at every existing call site
    without changing how any handler is wired up."""

    ARC = 8

    def __init__(self, text, theme, kind="secondary"):
        JButton.__init__(self, text)
        self.hovering = False
        self.pressed = False
        self._theme = theme
        self._kind = kind
        self._resolve_colors(theme, kind)
        self.setContentAreaFilled(False)
        self.setFocusPainted(False)
        self.setBorderPainted(False)
        self.setRolloverEnabled(False)
        self.setOpaque(False)
        self.setForeground(self._fg)
        self.setFont(Font("SansSerif", Font.BOLD, 12))
        self.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14))
        self.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        self.addMouseListener(_RoundedButtonHover(self))

    def _resolve_colors(self, theme, kind):
        if kind == "primary":
            base = theme.accent
            hover = theme.accent_hover
            press = theme.accent_press
            fg = theme.accent_fg
        elif kind == "success":
            base = theme.success
            hover = _shade(base, 16 if theme.dark else -14)
            press = _shade(base, -18 if theme.dark else -26)
            fg = theme.chip_fg
        elif kind == "danger":
            base = theme.danger
            hover = _shade(base, 16 if theme.dark else -14)
            press = _shade(base, -18 if theme.dark else -26)
            fg = theme.chip_fg
        else:  # secondary / ghost -- the default for utility actions
            base = theme.section_bg
            hover = _shade(base, 16 if theme.dark else -10)
            press = _shade(base, -14 if theme.dark else -22)
            fg = theme.text_primary
        self._base, self._hover_c, self._press_c, self._fg = base, hover, press, fg

    def paintComponent(self, g):
        g2 = g.create()
        try:
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            if not self.isEnabled():
                fill = self._theme.divider
            elif self.pressed:
                fill = self._press_c
            elif self.hovering:
                fill = self._hover_c
            else:
                fill = self._base
            g2.setColor(fill)
            g2.fillRoundRect(0, 0, self.getWidth(), self.getHeight(), self.ARC, self.ARC)
            if self._kind == "secondary":
                g2.setColor(self._theme.input_border)
                g2.drawRoundRect(0, 0, self.getWidth() - 1, self.getHeight() - 1, self.ARC, self.ARC)
            if self.isEnabled() and self.isFocusOwner():
                g2.setColor(self._theme.accent)
                g2.setStroke(BasicStroke(1.6))
                g2.drawRoundRect(1, 1, self.getWidth() - 3, self.getHeight() - 3, self.ARC, self.ARC)
        finally:
            g2.dispose()
        # paintComponent is a *protected* JComponent method -- Jython's usual
        # "JavaClass.method(self, args)" unbound-super trick only resolves
        # methods visible via Java's public reflection, so it can't see this
        # one (that trick DOES work for the public getTableCellRendererComponent
        # calls elsewhere in this file). Jython's actual mechanism for calling
        # an overridden Java method's original implementation -- public or
        # not -- is the auto-generated self.super__<name>(...) binding.
        try:
            self.super__paintComponent(g)
        except AttributeError:
            self._paint_label_fallback(g)

    def _paint_label_fallback(self, g):
        """Only used if self.super__paintComponent isn't available for some
        Jython-version-specific reason -- draws the button's own text so it
        stays readable instead of rendering blank."""
        g2 = g.create()
        try:
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.setFont(self.getFont())
            g2.setColor(self._fg if self.isEnabled() else self._theme.text_muted)
            fm = g2.getFontMetrics()
            text = self.getText() or ""
            tw = fm.stringWidth(text)
            x = (self.getWidth() - tw) / 2
            y = (self.getHeight() + fm.getAscent() - fm.getDescent()) / 2
            g2.drawString(text, x, y)
        finally:
            g2.dispose()

    def setEnabled(self, enabled):
        try:
            self.super__setEnabled(enabled)
        except AttributeError:
            JButton.setEnabled(self, enabled)
        self.setForeground(self._fg if enabled else self._theme.text_muted)
        self.repaint()


class WrappingTextPane(JTextPane):
    """JTextPane doesn't track its viewport's width the way
    JTextArea(lineWrap=True) does; without this override long log lines grow
    a horizontal scrollbar instead of wrapping. Used for the activity log so
    it can render per-line status colors (see BurpExtender._log)."""

    def getScrollableTracksViewportWidth(self):
        return True


# ---------------------------------------------------------------------------
# Small helper classes (audit/business logic -- unchanged by the redesign)
# ---------------------------------------------------------------------------

class JulesApiError(Exception):
    """Raised for any Jules REST API failure, with the real API error message
    (parsed from the {"error": {...}} body per the API's documented error
    format) rather than a generic urllib2 HTTP error string."""

    def __init__(self, message, status_code=None, api_status=None):
        Exception.__init__(self, message)
        self.status_code = status_code
        self.api_status = api_status


class ContextEntry(object):
    """One captured HTTP transaction plus its operator-assigned role/notes."""

    def __init__(self, role, req_resp, notes=""):
        self.role = role
        self.req_resp = req_resp
        self.notes = notes
        self.captured_at = time.time()


class ContextTableModel(AbstractTableModel):
    """Backs the Captured Contexts table. Method/URL/Status are derived live
    from the underlying Burp IHttpRequestResponse rather than cached, so the
    table always reflects the real captured data."""

    COLUMN_NAMES = ["#", "Role", "Method", "URL", "Status", "Notes"]

    def __init__(self, extender):
        self.extender = extender
        self.entries = []

    def getRowCount(self):
        return len(self.entries)

    def getColumnCount(self):
        return len(self.COLUMN_NAMES)

    def getColumnName(self, col):
        return self.COLUMN_NAMES[col]

    def isCellEditable(self, row, col):
        return col == 1 or col == 5

    def getValueAt(self, row, col):
        if row < 0 or row >= len(self.entries):
            return ""
        entry = self.entries[row]
        if col == 0:
            return row + 1
        elif col == 1:
            return entry.role
        elif col == 2:
            return self.extender._safe_method(entry.req_resp)
        elif col == 3:
            return self.extender._safe_url(entry.req_resp)
        elif col == 4:
            return self.extender._safe_status(entry.req_resp)
        elif col == 5:
            return entry.notes
        return ""

    def setValueAt(self, value, row, col):
        if row < 0 or row >= len(self.entries):
            return
        entry = self.entries[row]
        if col == 1:
            entry.role = str(value) if value is not None else ""
        elif col == 5:
            entry.notes = str(value) if value is not None else ""
        self.fireTableCellUpdated(row, col)

    def add_entry(self, entry):
        self.entries.append(entry)
        idx = len(self.entries) - 1
        self.fireTableRowsInserted(idx, idx)

    def remove_rows(self, indices):
        for i in sorted(set(indices), reverse=True):
            if 0 <= i < len(self.entries):
                del self.entries[i]
        self.fireTableDataChanged()

    def clear(self):
        self.entries = []
        self.fireTableDataChanged()


class ZebraTableCellRenderer(DefaultTableCellRenderer):
    """Shared base renderer: alternates row background for scanability and
    applies the theme's default text color/padding to every cell. The
    status/state renderers below extend this so specially-colored columns
    get the same striping and spacing as the rest of the row instead of
    standing apart from it."""

    def __init__(self, theme):
        DefaultTableCellRenderer.__init__(self)
        self._theme = theme

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col
        )
        if isSelected:
            comp.setForeground(self._theme.accent_fg)
        else:
            comp.setBackground(self._theme.row_alt_bg if row % 2 == 1 else self._theme.base_bg)
            comp.setForeground(self._theme.text_primary)
        comp.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8))
        return comp


class StatusCellRenderer(ZebraTableCellRenderer):
    """Color-codes the Status column by HTTP status class, the way Burp's own
    tables do, so an operator can scan a busy bundle at a glance."""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = ZebraTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col
        )
        text = str(value) if value is not None else ""
        if not isSelected:
            role = self._theme.http_status_role(text)
            comp.setForeground(self._theme.role_color(role))
        try:
            comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        except Exception:
            pass
        return comp


class _ContextTableMouseListener(MouseAdapter):
    """Right-click context menu + double-click-to-edit-notes for the table."""

    def __init__(self, extender):
        self.extender = extender

    def mousePressed(self, e):
        self._maybe_popup(e)

    def mouseReleased(self, e):
        self._maybe_popup(e)

    def mouseClicked(self, e):
        if e.getClickCount() == 2:
            table = self.extender._context_table
            row = table.rowAtPoint(e.getPoint())
            if row >= 0:
                self.extender._edit_notes_dialog(row)

    def _maybe_popup(self, e):
        if e.isPopupTrigger():
            table = self.extender._context_table
            row = table.rowAtPoint(e.getPoint())
            if row >= 0 and not table.isRowSelected(row):
                table.setRowSelectionInterval(row, row)
            self.extender._show_context_table_popup(e.getComponent(), e.getX(), e.getY())


class SessionEntry(object):
    """One Jules session this extension is tracking. Holds its own status,
    PR list, and activity log so any number of sessions can be monitored
    independently side by side."""

    def __init__(self, session_id, title="", task_type=""):
        self.session_id = session_id
        self.title = title or ""
        self.task_type = task_type or ""
        self.state = "UNKNOWN"
        self.web_url = None
        self.seen_pr_urls = set()
        self.seen_activity_ids = set()
        self.activity_lines = []
        self.last_refreshed = None


class SessionTableModel(AbstractTableModel):
    """Backs the Jules Sessions table. One row per tracked session."""

    COLUMN_NAMES = ["#", "Session ID", "Title", "State", "Updated"]

    def __init__(self):
        self.entries = []

    def getRowCount(self):
        return len(self.entries)

    def getColumnCount(self):
        return len(self.COLUMN_NAMES)

    def getColumnName(self, col):
        return self.COLUMN_NAMES[col]

    def isCellEditable(self, row, col):
        return False

    def getValueAt(self, row, col):
        if row < 0 or row >= len(self.entries):
            return ""
        entry = self.entries[row]
        if col == 0:
            return row + 1
        elif col == 1:
            return entry.session_id
        elif col == 2:
            return entry.title
        elif col == 3:
            return entry.state
        elif col == 4:
            if entry.last_refreshed:
                return time.strftime("%H:%M:%S", time.localtime(entry.last_refreshed))
            return "never"
        return ""

    def find_by_id(self, session_id):
        for e in self.entries:
            if e.session_id == session_id:
                return e
        return None

    def index_of(self, entry):
        try:
            return self.entries.index(entry)
        except ValueError:
            return -1

    def add_entry(self, entry):
        self.entries.append(entry)
        idx = len(self.entries) - 1
        self.fireTableRowsInserted(idx, idx)
        return idx

    def remove_rows(self, indices):
        for i in sorted(set(indices), reverse=True):
            if 0 <= i < len(self.entries):
                del self.entries[i]
        self.fireTableDataChanged()

    def fire_row_updated(self, row):
        self.fireTableRowsUpdated(row, row)


class SessionStateCellRenderer(ZebraTableCellRenderer):
    """Color-codes the State column using the same semantic roles (info/
    warning/success/danger/neutral) as the rest of the UI, so the sessions
    table reads at a glance across many rows."""

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = ZebraTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col
        )
        text = str(value) if value is not None else ""
        if not isSelected:
            role = STATE_COLOR_ROLE.get(text, "neutral")
            comp.setForeground(self._theme.role_color(role))
        try:
            comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        except Exception:
            pass
        return comp


class _SessionsTableMouseListener(MouseAdapter):
    """Right-click context menu + double-click-to-view-log for the sessions
    table, mirroring _ContextTableMouseListener's pattern."""

    def __init__(self, extender):
        self.extender = extender

    def mousePressed(self, e):
        self._maybe_popup(e)

    def mouseReleased(self, e):
        self._maybe_popup(e)

    def mouseClicked(self, e):
        if e.getClickCount() == 2:
            table = self.extender._sessions_table
            row = table.rowAtPoint(e.getPoint())
            if row >= 0:
                self.extender._do_view_activity_log(None)

    def _maybe_popup(self, e):
        if e.isPopupTrigger():
            table = self.extender._sessions_table
            row = table.rowAtPoint(e.getPoint())
            if row >= 0 and not table.isRowSelected(row):
                table.setRowSelectionInterval(row, row)
            self.extender._show_sessions_table_popup(e.getComponent(), e.getX(), e.getY())


# ---------------------------------------------------------------------------
# Main extension
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    JULES_BASE_URL = "https://jules.googleapis.com/v1alpha"
    SETTINGS_PREFIX = "siren."

    TASK_TYPES = [
        "Differential Authorization Review (IDOR / BOLA)",
        "Email Ownership Bypass Review",
        "Web Cache Poisoning Review",
        "App Surface / Role Mapping Review",
        "Custom / Freeform",
    ]

    AUTOMATION_MODE_LABELS = [
        "No automation (recommended for audits)",
        "Auto-create PR when changes are ready",
    ]
    AUTOMATION_MODE_MAP = {
        "No automation (recommended for audits)": None,
        "Auto-create PR when changes are ready": "AUTO_CREATE_PR",
    }

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Siren Security Audit Assistant")

        self._sources_by_name = {}
        self._last_bundle_json = None
        self._last_prompt = None
        self._poll_timer = None

        self._init_ui()
        self._load_all_settings()
        self._load_tracked_sessions()

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        try:
            callbacks.registerExtensionStateListener(self)
        except Exception:
            pass

        self._log("Siren Security Audit Assistant loaded. Jules base URL: %s" % self.JULES_BASE_URL)
        if self._get_api_key() and self._session_table_model.getRowCount() > 0:
            self._log("Restored %d tracked session(s) from last time -- refreshing..."
                      % self._session_table_model.getRowCount())
            self._refresh_all_sessions_core()

    def getTabCaption(self):
        return "Siren Audit"

    def getUiComponent(self):
        return self._main_panel

    def extensionUnloaded(self):
        try:
            self._persist_all_settings()
        except Exception:
            pass
        try:
            self._persist_tracked_sessions()
        except Exception:
            pass
        try:
            if self._poll_timer is not None:
                self._poll_timer.stop()
        except Exception:
            pass

    # -----------------------------------------------------------------
    # Small styled-component factories
    #
    # Every widget the UI builders below construct goes through one of
    # these, so font/color/spacing choices live in one place instead of
    # being repeated (and drifting) at each call site. None of these change
    # what a widget IS -- a self._btn(...) is still a real JButton with a
    # normal addActionListener/setEnabled/setToolTipText surface.
    # -----------------------------------------------------------------

    def _style_section(self, panel, title):
        panel.setOpaque(True)
        panel.setBackground(self._theme.section_bg)
        outer = BorderFactory.createLineBorder(self._theme.divider, 1, True)
        tb = BorderFactory.createTitledBorder(outer, title)
        tb.setTitleFont(self._theme.LABEL_BOLD_FONT)
        tb.setTitleColor(self._theme.text_secondary)
        panel.setBorder(BorderFactory.createCompoundBorder(tb, BorderFactory.createEmptyBorder(8, 12, 12, 12)))
        return panel

    def _label(self, text, secondary=False, bold=False, muted=False):
        lbl = JLabel(text)
        lbl.setFont(self._theme.LABEL_BOLD_FONT if bold else self._theme.LABEL_FONT)
        if muted:
            lbl.setForeground(self._theme.text_muted)
        elif secondary:
            lbl.setForeground(self._theme.text_secondary)
        else:
            lbl.setForeground(self._theme.text_primary)
        return lbl

    def _field_row(self, label_text, control, hint=None):
        """A label stacked above its control, with an optional muted hint
        line underneath. Used for every settings field so labels don't
        fight their inputs for width the way a forced two-column grid does
        once a label runs long (e.g. the repository-source field below)."""
        row = JPanel(BorderLayout(0, 3))
        row.setOpaque(False)
        row.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0))
        lbl = self._label(label_text, secondary=True)
        row.add(lbl, BorderLayout.NORTH)
        row.add(control, BorderLayout.CENTER)
        if hint:
            hint_lbl = JLabel(hint)
            hint_lbl.setFont(self._theme.HINT_FONT)
            hint_lbl.setForeground(self._theme.text_muted)
            hint_lbl.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0))
            row.add(hint_lbl, BorderLayout.SOUTH)
        return row

    def _btn(self, text, handler, kind="secondary", enabled=True, tooltip=None):
        b = RoundedButton(text, self._theme, kind)
        if handler is not None:
            b.addActionListener(handler)
        if not enabled:
            b.setEnabled(False)
        if tooltip:
            b.setToolTipText(tooltip)
        return b

    def _checkbox(self, text, selected=False, tooltip=None):
        cb = JCheckBox(text, selected)
        cb.setFont(self._theme.LABEL_FONT)
        cb.setForeground(self._theme.text_primary)
        cb.setOpaque(False)
        if tooltip:
            cb.setToolTipText(tooltip)
        return cb

    def _combo(self, editable=False):
        combo = JComboBox()
        combo.setEditable(editable)
        combo.setFont(self._theme.LABEL_FONT)
        combo.setBackground(self._theme.input_bg)
        combo.setForeground(self._theme.text_primary)
        return combo

    def _text_field(self, text="", columns=None):
        tf = JTextField(text, columns) if columns is not None else JTextField(text)
        self._style_text_component(tf, mono=True)
        return tf

    def _password_field(self):
        pf = JPasswordField()
        self._style_text_component(pf, mono=True)
        return pf

    def _style_text_component(self, comp, mono=True):
        comp.setFont(self._theme.MONO_FONT_SMALL if mono else self._theme.LABEL_FONT)
        comp.setBackground(self._theme.input_bg)
        comp.setForeground(self._theme.text_primary)
        comp.setCaretColor(self._theme.text_primary)
        comp.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(self._theme.input_border, 1, True),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)))

    def _text_area(self, rows, cols, mono=True):
        ta = JTextArea(rows, cols)
        ta.setLineWrap(True)
        ta.setWrapStyleWord(True)
        ta.setFont(self._theme.MONO_FONT if mono else self._theme.LABEL_FONT)
        ta.setBackground(self._theme.input_bg)
        ta.setForeground(self._theme.text_primary)
        ta.setCaretColor(self._theme.text_primary)
        ta.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        return ta

    def _scroll_of(self, component, pref_size=None):
        scroll = JScrollPane(component)
        scroll.setBorder(BorderFactory.createLineBorder(self._theme.divider, 1))
        try:
            scroll.getViewport().setBackground(component.getBackground())
        except Exception:
            pass
        if pref_size:
            scroll.setPreferredSize(pref_size)
        return scroll

    def _labeled_pane(self, title, component):
        wrap = JPanel(BorderLayout(0, 4))
        wrap.setOpaque(False)
        lbl = self._label(title, bold=True, secondary=True)
        wrap.add(lbl, BorderLayout.NORTH)
        wrap.add(self._scroll_of(component), BorderLayout.CENTER)
        return wrap

    def _style_spinner(self, spinner):
        spinner.setFont(self._theme.LABEL_FONT)
        try:
            editor = spinner.getEditor()
            tf = editor.getTextField()
            tf.setBackground(self._theme.input_bg)
            tf.setForeground(self._theme.text_primary)
            tf.setFont(self._theme.LABEL_FONT)
        except Exception:
            pass

    def _style_table(self, table):
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        table.setRowHeight(26)
        table.setFillsViewportHeight(True)
        table.setShowGrid(False)
        table.setIntercellSpacing(Dimension(0, 0))
        table.setFont(self._theme.LABEL_FONT)
        table.setBackground(self._theme.base_bg)
        table.setSelectionBackground(self._theme.accent)
        table.setSelectionForeground(self._theme.accent_fg)
        table.setDefaultRenderer(Object, ZebraTableCellRenderer(self._theme))
        header = table.getTableHeader()
        header.setFont(self._theme.LABEL_BOLD_FONT)
        header.setBackground(self._theme.header_bg)
        header.setForeground(self._theme.text_secondary)
        header.setReorderingAllowed(False)
        header.setPreferredSize(Dimension(header.getPreferredSize().width, 28))

    # -----------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------

    def _init_ui(self):
        self._theme = UITheme()

        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setOpaque(True)
        content.setBackground(self._theme.base_bg)
        content.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14))

        content.add(self._build_header())
        content.add(Box.createVerticalStrut(12))

        panels = [
            self._build_config_panel(),
            self._build_context_panel(),
            self._build_task_panel(),
            self._build_dispatch_panel(),
            self._build_sessions_panel(),
            self._build_log_panel(),
        ]
        for panel in panels:
            panel.setAlignmentX(0.0)
            panel.setMaximumSize(Dimension(32767, panel.getPreferredSize().height))
            content.add(panel)
            content.add(Box.createVerticalStrut(12))

        scroll = JScrollPane(content)
        scroll.getVerticalScrollBar().setUnitIncrement(16)
        scroll.setBorder(BorderFactory.createEmptyBorder())
        scroll.setOpaque(True)
        scroll.getViewport().setBackground(self._theme.base_bg)
        self._main_panel = scroll

    def _build_header(self):
        header = JPanel(BorderLayout())
        header.setOpaque(False)
        header.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, self._theme.divider),
            BorderFactory.createEmptyBorder(0, 0, 12, 0)))

        title_box = JPanel()
        title_box.setLayout(BoxLayout(title_box, BoxLayout.Y_AXIS))
        title_box.setOpaque(False)

        title = JLabel("Siren")
        title.setFont(self._theme.TITLE_FONT)
        title.setForeground(self._theme.accent)
        title_box.add(title)

        subtitle = self._label("Differential audit console for the Jules REST API", secondary=True)
        subtitle.setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0))
        title_box.add(subtitle)

        header.add(title_box, BorderLayout.WEST)
        return header

    def _build_config_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        self._style_section(panel, "Jules REST API Connection")

        key_row = JPanel(BorderLayout(8, 0))
        key_row.setOpaque(False)
        self._api_key_field = self._password_field()
        key_row.add(self._api_key_field, BorderLayout.CENTER)
        self._remember_key_checkbox = self._checkbox(
            "Remember", tooltip=(
                "Stores the API key in this Burp project's extension settings so you don't have to "
                "re-enter it. Leave unchecked to keep it in memory for this session only."))
        key_row.add(self._remember_key_checkbox, BorderLayout.EAST)
        panel.add(self._field_row("API key  (sent as x-goog-api-key)", key_row))
        panel.add(Box.createVerticalStrut(6))

        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        btn_row.setOpaque(False)
        btn_row.add(self._btn("Test Connection", self._do_test_connection, "secondary"))
        btn_row.add(self._btn("Fetch Sources", self._do_fetch_sources, "secondary"))
        panel.add(btn_row)
        panel.add(Box.createVerticalStrut(10))

        self._source_combo = self._combo(editable=True)
        self._source_combo.addItem("")
        self._source_combo.addItemListener(self._on_source_selection_changed)
        panel.add(self._field_row("Repository source", self._source_combo,
                                   hint="Leave blank for a repoless session."))

        self._source_info_label = JLabel(" ")
        self._source_info_label.setFont(self._theme.HINT_FONT)
        self._source_info_label.setForeground(self._theme.text_muted)
        self._source_info_label.setBorder(BorderFactory.createEmptyBorder(2, 2, 8, 0))
        panel.add(self._source_info_label)

        self._branch_combo = self._combo(editable=True)
        self._branch_combo.addItem("main")
        panel.add(self._field_row("Starting branch", self._branch_combo))
        panel.add(Box.createVerticalStrut(6))

        self._title_field = self._text_field("Siren Differential Audit")
        panel.add(self._field_row("Session title", self._title_field,
                                   hint="Used when dispatching new sessions."))

        return panel

    def _build_context_panel(self):
        panel = JPanel(BorderLayout(8, 8))
        self._style_section(panel, "Captured Contexts")

        caption = self._label("Right-click a request or response anywhere in Burp -> Siren -> Add as...",
                               muted=True)
        caption.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 0))
        panel.add(caption, BorderLayout.NORTH)

        self._table_model = ContextTableModel(self)
        self._context_table = JTable(self._table_model)
        self._style_table(self._context_table)
        col_model = self._context_table.getColumnModel()
        col_model.getColumn(0).setPreferredWidth(30)
        col_model.getColumn(1).setPreferredWidth(140)
        col_model.getColumn(2).setPreferredWidth(70)
        col_model.getColumn(3).setPreferredWidth(380)
        col_model.getColumn(4).setPreferredWidth(70)
        col_model.getColumn(4).setCellRenderer(StatusCellRenderer(self._theme))
        col_model.getColumn(5).setPreferredWidth(220)
        self._context_table.addMouseListener(_ContextTableMouseListener(self))
        self._context_table.getSelectionModel().addListSelectionListener(self._on_context_selection_changed)

        table_scroll = self._scroll_of(self._context_table, Dimension(900, 220))
        panel.add(table_scroll, BorderLayout.CENTER)

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        toolbar.setOpaque(False)
        self._context_status_label = self._label("0 contexts captured", secondary=True)
        toolbar.add(self._context_status_label)
        toolbar.add(self._btn("View", lambda e: self._view_selected_entry(), "secondary"))
        toolbar.add(self._btn("Edit Notes", lambda e: self._edit_selected_notes(), "secondary"))
        toolbar.add(self._btn("Duplicate", lambda e: self._do_duplicate_selected(), "secondary"))
        toolbar.add(self._btn("Remove Selected", lambda e: self._do_remove_selected_rows(), "secondary"))
        toolbar.add(self._btn("Clear All", self._do_clear_all_contexts, "secondary"))
        panel.add(toolbar, BorderLayout.SOUTH)

        return panel

    def _build_task_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        self._style_section(panel, "Task Framing")

        self._task_type_combo = self._combo(editable=False)
        for t in self.TASK_TYPES:
            self._task_type_combo.addItem(t)
        panel.add(self._field_row("Task type", self._task_type_combo,
                                   hint="Selects which built-in skill Jules is pointed at."))
        panel.add(Box.createVerticalStrut(8))

        panel.add(self._label("Operator hypothesis / focus for this bundle (optional but recommended)",
                               secondary=True))
        panel.add(Box.createVerticalStrut(3))

        self._hypothesis_area = self._text_area(3, 60, mono=False)
        self._hypothesis_area.setToolTipText(
            "e.g. \"GET /api/orders/{id} does not verify the order belongs to the caller's "
            "tenant.\" A specific, falsifiable claim (AGENTS.md Phase 6) gives Jules a sharper "
            "target than the raw traffic alone."
        )
        panel.add(self._scroll_of(self._hypothesis_area))
        panel.add(Box.createVerticalStrut(10))

        self._scope_checkbox = self._checkbox(
            "<html>I've confirmed this target is in the program's current published scope and "
            "that automated/scripted testing is permitted (AGENTS.md Audit Gate 0).</html>")
        panel.add(self._scope_checkbox)

        return panel

    def _build_dispatch_panel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        self._style_section(panel, "Dispatch Settings")

        self._automation_combo = self._combo(editable=False)
        for label in self.AUTOMATION_MODE_LABELS:
            self._automation_combo.addItem(label)
        panel.add(self._field_row("Automation mode  (new sessions only)", self._automation_combo))
        panel.add(Box.createVerticalStrut(4))

        self._plan_approval_checkbox = self._checkbox(
            "Require plan approval before Jules acts (new sessions only)", selected=True,
            tooltip=(
                "Recommended. Jules pauses and waits for you to approve its plan before acting, "
                "mirroring AGENTS.md's operator-decides model. The API itself defaults this off; "
                "Siren defaults it on. Only applies when creating a new session -- a follow-up "
                "message to an existing session doesn't take this parameter."))
        panel.add(self._plan_approval_checkbox)
        panel.add(Box.createVerticalStrut(10))

        spinner_row = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        spinner_row.setOpaque(False)
        self._max_body_spinner = JSpinner(SpinnerNumberModel(4000, 200, 50000, 100))
        self._style_spinner(self._max_body_spinner)
        spinner_row.add(self._max_body_spinner)
        panel.add(self._field_row("Max characters captured per request/response body", spinner_row))
        panel.add(Box.createVerticalStrut(4))

        self._redact_checkbox = self._checkbox(
            "Redact sensitive headers/fields before sending (best-effort)", selected=True,
            tooltip=(
                "Masks Authorization/Cookie/Set-Cookie/API-key-shaped headers and common password/"
                "token/secret-shaped body fields before anything leaves Burp. Bodies can still "
                "contain other sensitive business data -- review before you turn this off."))
        panel.add(self._redact_checkbox)
        panel.add(Box.createVerticalStrut(10))

        panel.add(self._label(
            "Dispatch and Send-as-Follow-up use the selected rows in Captured Contexts, or all "
            "rows if none are selected.", muted=True))
        panel.add(Box.createVerticalStrut(8))

        action_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        action_row.setOpaque(False)
        self._dispatch_btn = self._btn("Dispatch as New Session", self._dispatch_to_jules, "primary")
        action_row.add(self._dispatch_btn)
        self._followup_btn = self._btn(
            "Send as Follow-up to Selected Session", self._do_send_followup, "secondary", enabled=False,
            tooltip=(
                "Select a session in the Jules Sessions table below first, then use this to send "
                "the current bundle to it as a follow-up message."))
        action_row.add(self._followup_btn)
        panel.add(action_row)
        panel.add(Box.createVerticalStrut(4))

        utility_row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        utility_row.setOpaque(False)
        utility_row.add(self._btn("Preview Bundle", self._do_preview_bundle, "secondary"))
        utility_row.add(self._btn("Copy Prompt", self._do_copy_prompt, "secondary"))
        utility_row.add(self._btn("Export Bundle...", self._do_export_bundle, "secondary"))
        panel.add(utility_row)

        return panel

    def _build_sessions_panel(self):
        panel = JPanel(BorderLayout(8, 8))
        self._style_section(panel, "Jules Sessions")

        caption = self._label("Tracks any number of sessions at once -- select a row to act on it.",
                               muted=True)
        caption.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 0))
        panel.add(caption, BorderLayout.NORTH)

        self._session_table_model = SessionTableModel()
        self._sessions_table = JTable(self._session_table_model)
        self._style_table(self._sessions_table)
        col_model = self._sessions_table.getColumnModel()
        col_model.getColumn(0).setPreferredWidth(30)
        col_model.getColumn(1).setPreferredWidth(110)
        col_model.getColumn(2).setPreferredWidth(260)
        col_model.getColumn(3).setPreferredWidth(190)
        col_model.getColumn(3).setCellRenderer(SessionStateCellRenderer(self._theme))
        col_model.getColumn(4).setPreferredWidth(90)
        self._sessions_table.addMouseListener(_SessionsTableMouseListener(self))
        self._sessions_table.getSelectionModel().addListSelectionListener(self._on_session_selection_changed)

        table_scroll = self._scroll_of(self._sessions_table, Dimension(900, 180))
        panel.add(table_scroll, BorderLayout.CENTER)

        south = JPanel()
        south.setLayout(BoxLayout(south, BoxLayout.Y_AXIS))
        south.setOpaque(False)
        south.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0))

        attach_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        attach_row.setOpaque(False)
        attach_row.add(self._label("Attach by ID:"))
        self._attach_id_field = self._text_field(columns=14)
        attach_row.add(self._attach_id_field)
        attach_row.add(self._btn("Attach", self._do_attach_by_id, "secondary"))
        attach_row.add(self._btn("Attach Existing...", self._do_attach_existing, "secondary"))
        south.add(attach_row)

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        toolbar.setOpaque(False)
        self._approve_plan_btn = self._btn("Approve Plan", self._do_approve_plan, "success", enabled=False)
        toolbar.add(self._approve_plan_btn)
        self._refresh_selected_btn = self._btn("Refresh Selected", self._do_refresh_selected_sessions,
                                                "secondary", enabled=False)
        toolbar.add(self._refresh_selected_btn)
        toolbar.add(self._btn("Refresh All", self._do_refresh_all_sessions, "secondary"))
        self._view_activity_btn = self._btn("View Activity Log", self._do_view_activity_log,
                                             "secondary", enabled=False)
        toolbar.add(self._view_activity_btn)
        self._open_browser_btn = self._btn("Open in Browser", self._do_open_selected_in_browser,
                                            "secondary", enabled=False)
        toolbar.add(self._open_browser_btn)
        self._remove_session_btn = self._btn("Remove from List", self._do_remove_selected_sessions,
                                              "secondary", enabled=False)
        toolbar.add(self._remove_session_btn)
        south.add(toolbar)

        bottom_row = JPanel(BorderLayout())
        bottom_row.setOpaque(False)
        self._auto_refresh_checkbox = self._checkbox("Auto-refresh all every 10s")
        self._auto_refresh_checkbox.addItemListener(self._on_auto_refresh_toggled)
        bottom_row.add(self._auto_refresh_checkbox, BorderLayout.WEST)
        self._sessions_summary_label = self._label("No sessions tracked yet.", bold=True)
        bottom_row.add(self._sessions_summary_label, BorderLayout.EAST)
        south.add(bottom_row)

        panel.add(south, BorderLayout.SOUTH)
        return panel

    def _build_log_panel(self):
        panel = JPanel(BorderLayout(4, 4))
        self._style_section(panel, "Execution / Activity Log")

        self._log_area = WrappingTextPane()
        self._log_area.setEditable(False)
        self._log_area.setFont(self._theme.MONO_FONT_SMALL)
        self._log_area.setBackground(self._theme.input_bg)
        self._log_area.setForeground(self._theme.text_primary)
        self._log_area.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))
        scroll = self._scroll_of(self._log_area, Dimension(900, 220))
        panel.add(scroll, BorderLayout.CENTER)

        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_row.setOpaque(False)
        btn_row.add(self._btn("Clear Log", lambda e: self._log_area.setText(""), "secondary"))
        panel.add(btn_row, BorderLayout.SOUTH)
        return panel

    # -----------------------------------------------------------------
    # Settings persistence
    # -----------------------------------------------------------------

    def _save_setting(self, key, value):
        try:
            self._callbacks.saveExtensionSetting(self.SETTINGS_PREFIX + key, value)
        except Exception:
            pass

    def _load_setting(self, key, default=""):
        try:
            v = self._callbacks.loadExtensionSetting(self.SETTINGS_PREFIX + key)
            return v if v is not None else default
        except Exception:
            return default

    def _load_all_settings(self):
        source = self._load_setting("source", "")
        if source:
            self._source_combo.addItem(source)
            self._source_combo.setSelectedItem(source)

        branch = self._load_setting("branch", "")
        if branch:
            self._branch_combo.addItem(branch)
            self._branch_combo.setSelectedItem(branch)

        title = self._load_setting("title", "")
        if title:
            self._title_field.setText(title)

        task_type = self._load_setting("task_type", "")
        if task_type in self.TASK_TYPES:
            self._task_type_combo.setSelectedItem(task_type)

        automation = self._load_setting("automation_mode", "")
        if automation in self.AUTOMATION_MODE_LABELS:
            self._automation_combo.setSelectedItem(automation)

        self._plan_approval_checkbox.setSelected(self._load_setting("require_plan_approval", "1") == "1")
        self._redact_checkbox.setSelected(self._load_setting("redact", "1") == "1")

        try:
            max_chars = int(self._load_setting("max_body_chars", "4000"))
            self._max_body_spinner.setValue(max_chars)
        except Exception:
            pass

        remember = self._load_setting("remember_key", "0") == "1"
        self._remember_key_checkbox.setSelected(remember)
        if remember:
            stored_key = self._load_setting("api_key", "")
            if stored_key:
                self._api_key_field.setText(stored_key)

    def _persist_all_settings(self):
        self._save_setting("source", self._get_source_text())
        self._save_setting("branch", self._get_branch_text())
        self._save_setting("title", self._title_field.getText())
        self._save_setting("task_type", str(self._task_type_combo.getSelectedItem()))
        self._save_setting("automation_mode", str(self._automation_combo.getSelectedItem()))
        self._save_setting("require_plan_approval", "1" if self._plan_approval_checkbox.isSelected() else "0")
        self._save_setting("redact", "1" if self._redact_checkbox.isSelected() else "0")
        self._save_setting("max_body_chars", str(self._max_body_spinner.getValue()))
        remember = self._remember_key_checkbox.isSelected()
        self._save_setting("remember_key", "1" if remember else "0")
        if remember:
            self._save_setting("api_key", self._get_api_key())
        else:
            self._save_setting("api_key", "")

    def _persist_tracked_sessions(self):
        try:
            data = [
                {"session_id": e.session_id, "title": e.title, "task_type": e.task_type}
                for e in self._session_table_model.entries
            ]
            self._save_setting("tracked_sessions", json.dumps(data))
        except Exception:
            pass

    def _load_tracked_sessions(self):
        raw = self._load_setting("tracked_sessions", "")
        if not raw:
            return
        try:
            data = json.loads(raw)
        except Exception:
            return
        for item in data:
            sid = item.get("session_id", "")
            if not sid or self._session_table_model.find_by_id(sid) is not None:
                continue
            entry = SessionEntry(sid, item.get("title", ""), item.get("task_type", ""))
            self._session_table_model.add_entry(entry)
        self._update_sessions_summary_label()

    # -----------------------------------------------------------------
    # Context menu / capture
    # -----------------------------------------------------------------

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if not responses or len(responses) == 0:
            return None

        menu_items = []
        for role_label in ("Unauthenticated", "User A / Tenant A", "User B / Tenant B"):
            item = JMenuItem("Siren -> Add as %s" % role_label)
            item.addActionListener(self._make_add_handler(responses, role_label))
            menu_items.append(item)

        custom_item = JMenuItem("Siren -> Add with custom role...")
        custom_item.addActionListener(self._make_add_custom_handler(responses))
        menu_items.append(custom_item)

        return menu_items

    def _make_add_handler(self, responses, role_label):
        def handler(event):
            self._add_captured(responses, role_label)
        return handler

    def _make_add_custom_handler(self, responses):
        def handler(event):
            label = JOptionPane.showInputDialog(
                self._main_panel, "Role / identity label for this capture:", "Custom role",
                JOptionPane.PLAIN_MESSAGE
            )
            if label:
                self._add_captured(responses, label.strip())
        return handler

    def _add_captured(self, responses, role_label):
        count = 0
        for r in responses:
            try:
                self._callbacks.saveBuffersToTempFiles(r)
            except Exception:
                pass
            self._table_model.add_entry(ContextEntry(role_label, r, ""))
            count += 1
        self._update_context_status_label()
        if count == 1:
            self._log("Captured 1 request as '%s'." % role_label)
        else:
            self._log("Captured %d requests as '%s'." % (count, role_label))

    # -----------------------------------------------------------------
    # Table helpers
    # -----------------------------------------------------------------

    def _safe_method(self, req_resp):
        try:
            info = self._helpers.analyzeRequest(req_resp)
            return info.getMethod()
        except Exception:
            return "?"

    def _safe_url(self, req_resp):
        try:
            info = self._helpers.analyzeRequest(req_resp)
            return str(info.getUrl())
        except Exception:
            return "?"

    def _safe_status(self, req_resp):
        try:
            raw_resp = req_resp.getResponse()
            if raw_resp is None or len(raw_resp) == 0:
                return "No response"
            info = self._helpers.analyzeResponse(raw_resp)
            return str(info.getStatusCode())
        except Exception:
            return "?"

    def _get_selected_rows(self):
        return list(self._context_table.getSelectedRows())

    def _do_remove_selected_rows(self):
        rows = self._get_selected_rows()
        if not rows:
            JOptionPane.showMessageDialog(self._main_panel, "Select one or more rows first.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        self._table_model.remove_rows(rows)
        self._update_context_status_label()

    def _do_clear_all_contexts(self, event):
        if self._table_model.getRowCount() == 0:
            return
        confirm = JOptionPane.showConfirmDialog(
            self._main_panel, "Remove all %d captured context(s)?" % self._table_model.getRowCount(),
            "Clear all", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self._table_model.clear()
            self._update_context_status_label()
            self._log("Cleared all captured contexts.")

    def _do_duplicate_selected(self):
        rows = self._get_selected_rows()
        if not rows:
            JOptionPane.showMessageDialog(self._main_panel, "Select one or more rows first.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        for r in rows:
            entry = self._table_model.entries[r]
            self._table_model.add_entry(ContextEntry(entry.role, entry.req_resp, entry.notes))
        self._update_context_status_label()

    def _edit_selected_notes(self):
        rows = self._get_selected_rows()
        if len(rows) != 1:
            JOptionPane.showMessageDialog(self._main_panel, "Select exactly one row to edit its notes.",
                                           "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        self._edit_notes_dialog(rows[0])

    def _edit_notes_dialog(self, row):
        if row < 0 or row >= len(self._table_model.entries):
            return
        entry = self._table_model.entries[row]
        ta = self._text_area(6, 40, mono=False)
        ta.setText(entry.notes)
        result = JOptionPane.showConfirmDialog(
            self._main_panel, self._scroll_of(ta), "Notes for context #%d (%s)" % (row + 1, entry.role),
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
        )
        if result == JOptionPane.OK_OPTION:
            entry.notes = ta.getText()
            self._table_model.fireTableRowsUpdated(row, row)

    def _view_selected_entry(self):
        rows = self._get_selected_rows()
        if len(rows) != 1:
            JOptionPane.showMessageDialog(self._main_panel, "Select exactly one row to view.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        row = rows[0]
        entry = self._table_model.entries[row]
        req_resp = entry.req_resp

        req_text = ""
        try:
            raw_req = req_resp.getRequest()
            if raw_req is not None:
                req_text = self._helpers.bytesToString(raw_req)
        except Exception as e:
            req_text = "Error reading request: %s" % str(e)

        resp_text = "(no response captured)"
        try:
            raw_resp = req_resp.getResponse()
            if raw_resp is not None and len(raw_resp) > 0:
                resp_text = self._helpers.bytesToString(raw_resp)
        except Exception as e:
            resp_text = "Error reading response: %s" % str(e)

        req_area = self._text_area(24, 65, mono=True)
        req_area.setText(req_text)
        req_area.setEditable(False)
        req_area.setCaretPosition(0)
        resp_area = self._text_area(24, 65, mono=True)
        resp_area.setText(resp_text)
        resp_area.setEditable(False)
        resp_area.setCaretPosition(0)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                            self._labeled_pane("REQUEST", req_area),
                            self._labeled_pane("RESPONSE", resp_area))
        split.setDividerLocation(460)
        split.setPreferredSize(Dimension(980, 520))
        split.setBorder(BorderFactory.createEmptyBorder())
        JOptionPane.showMessageDialog(
            self._main_panel, split,
            "Context #%d -- %s  (this local view is unredacted and untruncated)" % (row + 1, entry.role),
            JOptionPane.PLAIN_MESSAGE
        )

    def _show_context_table_popup(self, component, x, y):
        menu = JPopupMenu()
        menu.add(JMenuItem("View Full Request/Response", actionPerformed=lambda e: self._view_selected_entry()))
        menu.add(JMenuItem("Edit Notes...", actionPerformed=lambda e: self._edit_selected_notes()))
        menu.add(JMenuItem("Duplicate", actionPerformed=lambda e: self._do_duplicate_selected()))
        menu.addSeparator()
        menu.add(JMenuItem("Remove Selected", actionPerformed=lambda e: self._do_remove_selected_rows()))
        menu.show(component, x, y)

    def _update_context_status_label(self):
        n = self._table_model.getRowCount()
        selected = len(self._context_table.getSelectedRows())
        base = "1 context captured" if n == 1 else "%d contexts captured" % n
        if 0 < selected < n:
            base += "  (%d selected -- dispatch will use just these)" % selected
            self._context_status_label.setForeground(self._theme.accent)
        elif selected > 0 and selected == n and n > 0:
            base += "  (all selected)"
            self._context_status_label.setForeground(self._theme.text_secondary)
        else:
            self._context_status_label.setForeground(self._theme.text_secondary)
        self._context_status_label.setText(base)

    def _on_context_selection_changed(self, event):
        if event.getValueIsAdjusting():
            return
        self._update_context_status_label()

    # -----------------------------------------------------------------
    # Source / branch combo helpers
    # -----------------------------------------------------------------

    def _get_source_text(self):
        val = self._source_combo.getSelectedItem()
        return str(val).strip() if val is not None else ""

    def _get_branch_text(self):
        val = self._branch_combo.getSelectedItem()
        return str(val).strip() if val is not None else ""

    def _refresh_source_info(self):
        name = self._get_source_text()
        src = self._sources_by_name.get(name)
        if src:
            gh = src.get("githubRepo", {}) or {}
            owner = gh.get("owner", "")
            repo = gh.get("repo", "")
            priv = "private" if gh.get("isPrivate") else "public"
            default_branch = (gh.get("defaultBranch") or {}).get("displayName", "")
            self._source_info_label.setText(
                "-> %s/%s (%s), default branch: %s" % (owner, repo, priv, default_branch or "?")
            )
            branches = [b.get("displayName", "") for b in (gh.get("branches", []) or [])]
            model = DefaultComboBoxModel()
            for b in branches:
                if b:
                    model.addElement(b)
            if model.getSize() == 0 and default_branch:
                model.addElement(default_branch)
            self._branch_combo.setModel(model)
            if default_branch:
                self._branch_combo.setSelectedItem(default_branch)
        else:
            self._source_info_label.setText(" ")

    def _on_source_selection_changed(self, event):
        if event.getStateChange() == ItemEvent.SELECTED:
            self._refresh_source_info()

    # -----------------------------------------------------------------
    # Redaction / bundle building
    # -----------------------------------------------------------------

    def _parse_header_lines(self, header_lines):
        headers = {}
        lines = list(header_lines) if header_lines is not None else []
        for h in lines[1:]:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers

    def _redact_headers(self, headers, enabled):
        if not enabled:
            return dict(headers)
        out = {}
        for k, v in headers.items():
            if k.lower() in SENSITIVE_HEADERS:
                out[k] = "REDACTED (%d chars)" % len(v)
            else:
                out[k] = v
        return out

    def _redact_body(self, body, enabled):
        if not enabled or not body:
            return body
        try:
            return BODY_SECRET_KEY_RE.sub(lambda m: m.group(1) + "\"REDACTED\"", body)
        except Exception:
            return body

    def _truncate(self, s, max_chars):
        if s is None:
            return s
        if max_chars is None or max_chars <= 0 or len(s) <= max_chars:
            return s
        return s[:max_chars] + ("\n...[truncated, showing %d of %d chars]" % (max_chars, len(s)))

    def _is_binary_content_type(self, content_type):
        if not content_type:
            return False
        ct = content_type.split(";")[0].strip().lower()
        if ct in BINARY_CONTENT_TYPES_EXACT:
            return True
        if BINARY_CONTENT_TYPE_VND_RE.match(ct):
            return True
        for prefix in BINARY_CONTENT_TYPE_PREFIXES:
            if ct.startswith(prefix):
                return True
        return False

    def _build_context_dict(self, index, entry, max_body_chars, redact_enabled):
        req_resp = entry.req_resp
        result = {"index": index, "role": entry.role, "notes": entry.notes or ""}

        try:
            info_req = self._helpers.analyzeRequest(req_resp)
            method = info_req.getMethod()
            url = str(info_req.getUrl())
            req_headers = self._parse_header_lines(info_req.getHeaders())
            raw_req = req_resp.getRequest()
            req_body = ""
            if raw_req is not None:
                body_bytes = raw_req[info_req.getBodyOffset():]
                req_body = self._helpers.bytesToString(body_bytes)
            req_body = self._redact_body(req_body, redact_enabled)
            req_body = self._truncate(req_body, max_body_chars)
            result["request"] = {
                "method": method,
                "url": url,
                "headers": self._redact_headers(req_headers, redact_enabled),
                "body": req_body,
            }
        except Exception as e:
            result["request"] = {"error": "Failed to parse captured request: %s" % str(e)}

        raw_resp = None
        try:
            raw_resp = req_resp.getResponse()
        except Exception:
            raw_resp = None

        if raw_resp is None or len(raw_resp) == 0:
            result["response"] = None
        else:
            try:
                info_resp = self._helpers.analyzeResponse(raw_resp)
                status = info_resp.getStatusCode()
                resp_headers = self._parse_header_lines(info_resp.getHeaders())
                body_bytes = raw_resp[info_resp.getBodyOffset():]
                content_type = resp_headers.get("Content-Type", "") or resp_headers.get("content-type", "")
                if self._is_binary_content_type(content_type):
                    resp_body = "[binary content omitted: %s, %d bytes]" % (
                        content_type or "unknown", len(body_bytes)
                    )
                    truncated = False
                else:
                    resp_body_full = self._helpers.bytesToString(body_bytes)
                    truncated = bool(max_body_chars) and max_body_chars > 0 and len(resp_body_full) > max_body_chars
                    resp_body = self._truncate(resp_body_full, max_body_chars)
                result["response"] = {
                    "status": status,
                    "headers": self._redact_headers(resp_headers, redact_enabled),
                    "body": resp_body,
                    "body_truncated": truncated,
                }
            except Exception as e:
                result["response"] = {"error": "Failed to parse captured response: %s" % str(e)}

        return result

    def _build_prompt(self, task_type, hypothesis_text, bundle_json_str, contexts_count):
        skill_name, framing = TASK_FRAMING.get(task_type, TASK_FRAMING["Custom / Freeform"])
        parts = [framing]

        if hypothesis_text and hypothesis_text.strip():
            parts.append("\nOperator-supplied hypothesis / focus for this bundle:\n" + hypothesis_text.strip())

        intro = (
            "Below is a bundle of " + str(contexts_count) + " HTTP transaction(s) captured directly "
            "in Burp Suite. Each entry carries the role/identity it was captured under, any operator "
            "notes, the exact request, and the exact response observed when one was captured -- a "
            "null response means the request was never actually sent from Burp, so treat that as a "
            "coverage gap, not as evidence of anything. Sensitive header/body values may appear as "
            "REDACTED; treat REDACTED values as present-but-unknown, not as absent.\n\n"
            "Work within AGENTS.md's gating rules throughout this session: state findings as "
            "specific, falsifiable claims grounded only in what's actually in this bundle; if the "
            "right next step is a live request against the target that isn't already captured here, "
            "propose it and stop for operator approval rather than sending it yourself."
        )
        parts.append("\n" + intro)
        parts.append("\nBundle (JSON):\n```json\n" + bundle_json_str + "\n```")
        return "\n".join(parts)

    def _assemble_bundle_and_prompt(self, entries_snapshot, task_type, hypothesis_text,
                                     redact_enabled, max_body_chars):
        contexts = []
        for i, entry in enumerate(entries_snapshot):
            contexts.append(self._build_context_dict(i + 1, entry, max_body_chars, redact_enabled))
        bundle = {
            "bundle_type": "siren_burp_capture",
            "bundle_version": 1,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "task_type": task_type,
            "operator_hypothesis": hypothesis_text or "",
            "contexts": contexts,
        }
        bundle_json_str = json.dumps(bundle, indent=2)
        prompt_str = self._build_prompt(task_type, hypothesis_text, bundle_json_str, len(contexts))
        return bundle_json_str, prompt_str

    def _get_dispatch_entries(self):
        """Selected rows in Captured Contexts if any are selected, else all
        rows. Shared by Dispatch, Send-as-Follow-up, and Preview so the three
        always agree on what "the current bundle" means."""
        selected = list(self._context_table.getSelectedRows())
        if len(selected) > 0:
            idxs = sorted(selected)
            total = len(self._table_model.entries)
            return [self._table_model.entries[i] for i in idxs if 0 <= i < total]
        return list(self._table_model.entries)

    # -----------------------------------------------------------------
    # Async infrastructure
    # -----------------------------------------------------------------

    def _run_async(self, worker_fn, on_success, on_error, on_finally=None):
        """Runs worker_fn() on a background thread; on_success/on_error/
        on_finally always run back on the EDT. worker_fn must not touch any
        Swing component directly -- read what it needs from the EDT first
        and pass plain values in via closure."""

        def _runner():
            try:
                result = worker_fn()

                def _ok():
                    on_success(result)
                SwingUtilities.invokeLater(_ok)
            except JulesApiError as e:
                msg = str(e)

                def _err():
                    on_error(msg)
                SwingUtilities.invokeLater(_err)
            except Exception as e:
                msg = "Unexpected error: %s" % str(e)

                def _err2():
                    on_error(msg)
                SwingUtilities.invokeLater(_err2)
            finally:
                if on_finally is not None:
                    def _fin():
                        on_finally()
                    SwingUtilities.invokeLater(_fin)

        threading.Thread(target=_runner).start()

    def _log(self, msg):
        def _do():
            ts = time.strftime("%H:%M:%S")
            self._append_log_block("[%s] %s\n" % (ts, msg))
        if SwingUtilities.isEventDispatchThread():
            _do()
        else:
            SwingUtilities.invokeLater(_do)

    def _classify_log_line_color(self, line_text):
        """Best-effort color for one physical line of the log. Only ever
        changes how a line is *painted* -- the text inserted is identical to
        what the plain-JTextArea version of this method would have shown."""
        if "[-] " in line_text or "FAILED" in line_text:
            return self._theme.danger
        if "[+] " in line_text:
            return self._theme.success
        if "[i] " in line_text:
            return self._theme.accent
        if line_text.startswith("  ") or line_text.startswith("    ") or line_text.startswith("      "):
            return self._theme.text_secondary
        return self._theme.text_primary

    def _append_log_block(self, block):
        """Inserts a (possibly multi-line) log block into the styled log
        document, coloring each physical line independently so a single
        _log() call spanning a status line plus indented detail lines (e.g.
        an activity update) still reads correctly line by line."""
        doc = self._log_area.getStyledDocument()
        for sub in block.split("\n"):
            attrs = SimpleAttributeSet()
            StyleConstants.setForeground(attrs, self._classify_log_line_color(sub))
            try:
                doc.insertString(doc.getLength(), sub + "\n", attrs)
            except Exception:
                pass
        self._log_area.setCaretPosition(doc.getLength())

    # -----------------------------------------------------------------
    # Jules REST API client
    # -----------------------------------------------------------------

    def _jules_request(self, api_key, http_method, path, body_obj=None, timeout=30):
        url = self.JULES_BASE_URL + path
        headers = {"x-goog-api-key": api_key}
        data = None
        if body_obj is not None:
            data = json.dumps(body_obj)
            headers["Content-Type"] = "application/json"

        req = urllib2.Request(url, data=data, headers=headers)
        req.get_method = lambda: http_method
        try:
            resp = urllib2.urlopen(req, timeout=timeout)
            raw = resp.read()
            return json.loads(raw) if raw else {}
        except urllib2.HTTPError as e:
            raw_err = ""
            try:
                raw_err = e.read()
            except Exception:
                pass
            message = "HTTP %s %s" % (e.code, getattr(e, "reason", ""))
            api_status = None
            if raw_err:
                try:
                    err_json = json.loads(raw_err)
                    inner = err_json.get("error", {}) if isinstance(err_json, dict) else {}
                    if inner.get("message"):
                        message = inner.get("message")
                    api_status = inner.get("status")
                except Exception:
                    message = "%s -- %s" % (message, raw_err[:300])
            raise JulesApiError(message, status_code=e.code, api_status=api_status)
        except urllib2.URLError as e:
            reason = getattr(e, "reason", str(e))
            raise JulesApiError("Network error reaching Jules API: %s" % str(reason))
        except socket.timeout:
            raise JulesApiError("Request to Jules API timed out after %ds." % timeout)

    # -----------------------------------------------------------------
    # Actions
    # -----------------------------------------------------------------

    def _do_test_connection(self, event):
        api_key = self._get_api_key()
        if not api_key:
            JOptionPane.showMessageDialog(self._main_panel, "Enter your Jules API key first.",
                                           "Missing API key", JOptionPane.WARNING_MESSAGE)
            return
        self._log("Testing connection to the Jules REST API...")

        def worker():
            return self._jules_request(api_key, "GET", "/sources?pageSize=1")

        def on_success(_result):
            self._log("[+] Connection OK -- API key is valid.")
            JOptionPane.showMessageDialog(self._main_panel, "Connected successfully.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)

        def on_error(msg):
            self._log("[-] Connection test failed: %s" % msg)
            JOptionPane.showMessageDialog(self._main_panel, msg, "Connection failed", JOptionPane.ERROR_MESSAGE)

        self._run_async(worker, on_success, on_error)

    def _do_fetch_sources(self, event):
        api_key = self._get_api_key()
        if not api_key:
            JOptionPane.showMessageDialog(self._main_panel, "Enter your Jules API key first.",
                                           "Missing API key", JOptionPane.WARNING_MESSAGE)
            return
        self._log("Fetching connected sources from Jules...")

        def worker():
            result = self._jules_request(api_key, "GET", "/sources?pageSize=100")
            return result.get("sources", []) or []

        def on_success(sources):
            self._sources_by_name = {}
            model = DefaultComboBoxModel()
            model.addElement("")
            for s in sources:
                name = s.get("name", "")
                if not name:
                    continue
                self._sources_by_name[name] = s
                model.addElement(name)
            self._source_combo.setModel(model)
            self._refresh_source_info()
            self._log("[+] Fetched %d source(s)." % len(sources))
            if len(sources) == 0:
                self._log("    No sources connected yet -- install the Jules GitHub app from the "
                           "Jules web app, then try again.")

        def on_error(msg):
            self._log("[-] Failed to fetch sources: %s" % msg)

        self._run_async(worker, on_success, on_error)

    def _dispatch_to_jules(self, event):
        api_key = self._get_api_key()
        if not api_key:
            JOptionPane.showMessageDialog(self._main_panel, "Please provide a valid Jules API key.",
                                           "Missing API key", JOptionPane.ERROR_MESSAGE)
            return

        if not self._scope_checkbox.isSelected():
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Please confirm the scope/authorization checkbox before dispatching.\n\n"
                "This mirrors Audit Gate 0 in AGENTS.md: confirm the target is in the program's "
                "current published scope and that scripted/automated testing is permitted, before "
                "any bundle leaves Burp.",
                "Scope not confirmed", JOptionPane.WARNING_MESSAGE
            )
            return

        entries_snapshot = self._get_dispatch_entries()
        if len(entries_snapshot) == 0:
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Capture at least one request first (right-click a request/response anywhere in "
                "Burp -> Siren -> Add as...).",
                "No contexts captured", JOptionPane.WARNING_MESSAGE
            )
            return

        source = self._get_source_text()
        branch = self._get_branch_text()
        title = self._title_field.getText().strip()
        task_type = str(self._task_type_combo.getSelectedItem())
        hypothesis_text = self._hypothesis_area.getText()
        automation_display = str(self._automation_combo.getSelectedItem())
        automation_value = self.AUTOMATION_MODE_MAP.get(automation_display)
        require_plan_approval = self._plan_approval_checkbox.isSelected()
        redact_enabled = self._redact_checkbox.isSelected()
        max_body_chars = int(self._max_body_spinner.getValue())
        total_contexts = self._table_model.getRowCount()

        self._set_dispatch_enabled(False)
        if len(entries_snapshot) < total_contexts:
            self._log("Preparing bundle from %d of %d captured context(s) (selected rows only) "
                       "for a new session..." % (len(entries_snapshot), total_contexts))
        else:
            self._log("Preparing bundle from %d captured context(s) for a new session..." % len(entries_snapshot))

        def worker():
            bundle_json_str, prompt_str = self._assemble_bundle_and_prompt(
                entries_snapshot, task_type, hypothesis_text, redact_enabled, max_body_chars
            )
            self._last_bundle_json = bundle_json_str
            self._last_prompt = prompt_str

            body_obj = {"prompt": prompt_str, "title": title or "Siren Differential Audit"}
            if source:
                body_obj["sourceContext"] = {
                    "source": source,
                    "githubRepoContext": {"startingBranch": branch or "main"},
                }
            if automation_value:
                body_obj["automationMode"] = automation_value
            if require_plan_approval:
                body_obj["requirePlanApproval"] = True
            self._log("Creating new Jules session (skill focus: %s)..." % task_type)
            return self._jules_request(api_key, "POST", "/sessions", body_obj=body_obj)

        def on_success(resp):
            name = resp.get("name", "") if resp else ""
            sid = name.split("/")[-1] if name else ""
            if not sid:
                self._log("[+] Session created, but no session name was returned in the response.")
                return
            entry = SessionEntry(sid, resp.get("title", title), task_type)
            entry.state = resp.get("state", "UNKNOWN")
            idx = self._session_table_model.add_entry(entry)
            self._select_session_row(idx)
            self._log("[+] Created Jules session %s (state: %s)." % (sid, entry.state))
            self._persist_all_settings()
            self._persist_tracked_sessions()
            self._update_sessions_summary_label()
            if not self._auto_refresh_checkbox.isSelected():
                self._auto_refresh_checkbox.setSelected(True)  # triggers listener -> starts timer, refreshes all
            else:
                self._refresh_session(entry, True)

        def on_error(msg):
            self._log("[-] Dispatch failed: %s" % msg)
            JOptionPane.showMessageDialog(self._main_panel, msg, "Jules API Error", JOptionPane.ERROR_MESSAGE)

        def on_finally():
            self._set_dispatch_enabled(True)

        self._run_async(worker, on_success, on_error, on_finally)

    def _do_send_followup(self, event):
        rows = self._get_selected_session_rows()
        if len(rows) != 1:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Select exactly one session in the table below to send a "
                                           "follow-up to.", "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        entry = self._session_table_model.entries[rows[0]]

        api_key = self._get_api_key()
        if not api_key:
            JOptionPane.showMessageDialog(self._main_panel, "Please provide a valid Jules API key.",
                                           "Missing API key", JOptionPane.ERROR_MESSAGE)
            return
        if not self._scope_checkbox.isSelected():
            JOptionPane.showMessageDialog(
                self._main_panel, "Please confirm the scope/authorization checkbox before dispatching.",
                "Scope not confirmed", JOptionPane.WARNING_MESSAGE
            )
            return

        entries_snapshot = self._get_dispatch_entries()
        if len(entries_snapshot) == 0:
            JOptionPane.showMessageDialog(self._main_panel, "Capture at least one request first.",
                                           "No contexts captured", JOptionPane.WARNING_MESSAGE)
            return

        task_type = str(self._task_type_combo.getSelectedItem())
        hypothesis_text = self._hypothesis_area.getText()
        redact_enabled = self._redact_checkbox.isSelected()
        max_body_chars = int(self._max_body_spinner.getValue())
        total_contexts = self._table_model.getRowCount()

        self._set_followup_enabled(False)
        if len(entries_snapshot) < total_contexts:
            self._log("Preparing bundle from %d of %d captured context(s) (selected rows only) "
                       "for session %s..." % (len(entries_snapshot), total_contexts, entry.session_id))
        else:
            self._log("Preparing bundle from %d captured context(s) for session %s..."
                       % (len(entries_snapshot), entry.session_id))

        def worker():
            bundle_json_str, prompt_str = self._assemble_bundle_and_prompt(
                entries_snapshot, task_type, hypothesis_text, redact_enabled, max_body_chars
            )
            self._last_bundle_json = bundle_json_str
            self._last_prompt = prompt_str
            self._jules_request(
                api_key, "POST", "/sessions/%s:sendMessage" % urllib.quote(entry.session_id, safe=""),
                body_obj={"prompt": prompt_str}
            )
            return None

        def on_success(_result):
            self._log("[+] Bundle sent as a follow-up message to session %s." % entry.session_id)
            self._log("    Jules replies asynchronously -- Refresh Selected / Auto-refresh will "
                       "pick up its response.")
            self._refresh_session(entry, True)

        def on_error(msg):
            self._log("[-] Follow-up failed for session %s: %s" % (entry.session_id, msg))
            JOptionPane.showMessageDialog(self._main_panel, msg, "Jules API Error", JOptionPane.ERROR_MESSAGE)

        def on_finally():
            self._update_session_action_buttons()

        self._run_async(worker, on_success, on_error, on_finally)

    def _do_approve_plan(self, event):
        rows = self._get_selected_session_rows()
        if len(rows) != 1:
            JOptionPane.showMessageDialog(self._main_panel, "Select exactly one session to approve its plan.",
                                           "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        entry = self._session_table_model.entries[rows[0]]

        api_key = self._get_api_key()
        if not api_key:
            JOptionPane.showMessageDialog(self._main_panel, "Enter your Jules API key first.",
                                           "Missing API key", JOptionPane.WARNING_MESSAGE)
            return

        def worker():
            return self._jules_request(
                api_key, "POST", "/sessions/%s:approvePlan" % urllib.quote(entry.session_id, safe=""), body_obj={}
            )

        def on_success(_result):
            self._log("[+] Plan approved for session %s." % entry.session_id)
            self._refresh_session(entry, True)

        def on_error(msg):
            self._log("[-] Approve plan failed for session %s: %s" % (entry.session_id, msg))

        self._log("Approving plan for session %s..." % entry.session_id)
        self._run_async(worker, on_success, on_error)

    def _refresh_session(self, entry, silent=True):
        api_key = self._get_api_key()
        if not api_key:
            if not silent:
                self._log("[-] Enter your Jules API key first.")
            return
        session_id = entry.session_id

        def worker():
            session_obj = self._jules_request(api_key, "GET", "/sessions/%s" % urllib.quote(session_id, safe=""))
            activities_obj = self._jules_request(
                api_key, "GET", "/sessions/%s/activities?pageSize=50" % urllib.quote(session_id, safe="")
            )
            return (session_obj, activities_obj)

        def on_success(result):
            session_obj, activities_obj = result
            self._apply_session_update(entry, session_obj)
            self._apply_new_activities(entry, activities_obj.get("activities", []) or [])
            entry.last_refreshed = time.time()
            row = self._session_table_model.index_of(entry)
            if row >= 0:
                self._session_table_model.fire_row_updated(row)
            self._update_sessions_summary_label()
            self._update_session_action_buttons()
            self._persist_tracked_sessions()

        def on_error(msg):
            self._log("[-] Refresh failed for session %s: %s" % (session_id, msg))

        self._run_async(worker, on_success, on_error)

    def _refresh_all_sessions_core(self):
        for entry in list(self._session_table_model.entries):
            self._refresh_session(entry, True)

    def _do_refresh_all_sessions(self, event):
        if self._session_table_model.getRowCount() == 0:
            JOptionPane.showMessageDialog(self._main_panel, "No sessions tracked yet.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        self._log("Refreshing all %d tracked session(s)..." % self._session_table_model.getRowCount())
        self._refresh_all_sessions_core()

    def _do_refresh_selected_sessions(self, event):
        rows = self._get_selected_session_rows()
        if not rows:
            JOptionPane.showMessageDialog(self._main_panel, "Select one or more sessions first.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        for r in rows:
            self._refresh_session(self._session_table_model.entries[r], False)

    def _apply_session_update(self, entry, session_obj):
        entry.state = session_obj.get("state", "UNKNOWN")
        new_title = session_obj.get("title")
        if new_title:
            entry.title = new_title
        url = session_obj.get("url")
        if url:
            entry.web_url = url
        outputs = session_obj.get("outputs", []) or []
        for out in outputs:
            pr = out.get("pullRequest")
            if pr and pr.get("url") and pr.get("url") not in entry.seen_pr_urls:
                entry.seen_pr_urls.add(pr.get("url"))
                self._log("[+] [%s] Pull request ready: %s -- %s"
                          % (entry.session_id, pr.get("url"), pr.get("title", "")))

    def _apply_new_activities(self, entry, activities):
        for act in activities:
            act_id = act.get("id") or act.get("name")
            if not act_id or act_id in entry.seen_activity_ids:
                continue
            entry.seen_activity_ids.add(act_id)
            formatted = self._format_activity(act)
            if formatted:
                entry.activity_lines.append(formatted)
                self._log("[%s] %s" % (entry.session_id, formatted))

    def _format_activity(self, act):
        originator = act.get("originator", "?")
        desc = act.get("description", "")
        lines = ["  [activity] (%s) %s" % (originator, desc)]

        if "agentMessaged" in act:
            lines.append("      Jules: %s" % act["agentMessaged"].get("agentMessage", ""))
        if "userMessaged" in act:
            lines.append("      You: %s" % act["userMessaged"].get("userMessage", ""))
        if "planGenerated" in act:
            plan = act["planGenerated"].get("plan", {}) or {}
            steps = plan.get("steps", []) or []
            lines.append("      Plan proposed (%d step(s)):" % len(steps))
            for step in steps:
                idx = step.get("index", 0)
                lines.append("        %d. %s -- %s" % (idx + 1, step.get("title", ""), step.get("description", "")))
            lines.append("      (Awaiting your approval -- use the Approve Plan button if this looks right.)")
        if "progressUpdated" in act:
            pu = act["progressUpdated"]
            lines.append("      Progress: %s -- %s" % (pu.get("title", ""), pu.get("description", "")))
        if "sessionFailed" in act:
            lines.append("      FAILED: %s" % act["sessionFailed"].get("reason", ""))
        if "sessionCompleted" in act:
            lines.append("      Session completed.")

        for art in (act.get("artifacts", []) or []):
            if "changeSet" in art:
                gp = (art["changeSet"] or {}).get("gitPatch", {}) or {}
                lines.append("      Change proposed: %s" % gp.get("suggestedCommitMessage", ""))
            if "bashOutput" in art:
                bo = art["bashOutput"] or {}
                lines.append("      $ %s (exit %s)" % (bo.get("command", ""), bo.get("exitCode", "")))

        return "\n".join(lines)

    def _on_poll_tick(self, event):
        for entry in list(self._session_table_model.entries):
            if entry.state not in ("COMPLETED", "FAILED"):
                self._refresh_session(entry, True)

    def _on_auto_refresh_toggled(self, event):
        if event.getStateChange() == ItemEvent.SELECTED:
            if self._poll_timer is None:
                self._poll_timer = SwingTimer(10000, self._on_poll_tick)
                self._poll_timer.setRepeats(True)
            self._poll_timer.start()
            self._log("Auto-refresh enabled for all tracked sessions (every 10s).")
            self._refresh_all_sessions_core()
        else:
            if self._poll_timer is not None:
                self._poll_timer.stop()
            self._log("Auto-refresh disabled.")

    # -----------------------------------------------------------------
    # Session table: selection, attach, remove, view
    # -----------------------------------------------------------------

    def _get_selected_session_rows(self):
        return list(self._sessions_table.getSelectedRows())

    def _select_session_row(self, idx):
        if idx is None or idx < 0:
            return
        self._sessions_table.setRowSelectionInterval(idx, idx)
        rect = self._sessions_table.getCellRect(idx, 0, True)
        self._sessions_table.scrollRectToVisible(rect)
        self._update_session_action_buttons()

    def _on_session_selection_changed(self, event):
        if event.getValueIsAdjusting():
            return
        self._update_session_action_buttons()

    def _update_session_action_buttons(self):
        rows = self._get_selected_session_rows()
        single = len(rows) == 1
        entry = self._session_table_model.entries[rows[0]] if single else None
        self._followup_btn.setEnabled(single)
        self._approve_plan_btn.setEnabled(single and entry.state == "AWAITING_PLAN_APPROVAL")
        self._open_browser_btn.setEnabled(single and bool(entry.web_url))
        self._view_activity_btn.setEnabled(single)
        self._refresh_selected_btn.setEnabled(len(rows) >= 1)
        self._remove_session_btn.setEnabled(len(rows) >= 1)

    def _set_followup_enabled(self, enabled):
        self._followup_btn.setEnabled(enabled)

    def _update_sessions_summary_label(self):
        entries = self._session_table_model.entries
        n = len(entries)
        if n == 0:
            self._sessions_summary_label.setText("No sessions tracked yet.")
            self._sessions_summary_label.setForeground(self._theme.text_muted)
            return
        awaiting_plan = sum(1 for e in entries if e.state == "AWAITING_PLAN_APPROVAL")
        awaiting_feedback = sum(1 for e in entries if e.state == "AWAITING_USER_FEEDBACK")
        in_progress = sum(1 for e in entries if e.state in ("QUEUED", "PLANNING", "IN_PROGRESS"))
        completed = sum(1 for e in entries if e.state == "COMPLETED")
        failed = sum(1 for e in entries if e.state == "FAILED")
        bits = []
        if awaiting_plan:
            bits.append("%d awaiting plan approval" % awaiting_plan)
        if awaiting_feedback:
            bits.append("%d awaiting your input" % awaiting_feedback)
        if in_progress:
            bits.append("%d in progress" % in_progress)
        if completed:
            bits.append("%d completed" % completed)
        if failed:
            bits.append("%d failed" % failed)
        detail = ", ".join(bits) if bits else "state unknown"
        if n == 1:
            self._sessions_summary_label.setText("1 session tracked -- %s" % detail)
        else:
            self._sessions_summary_label.setText("%d sessions tracked -- %s" % (n, detail))

        if failed:
            self._sessions_summary_label.setForeground(self._theme.danger)
        elif awaiting_plan or awaiting_feedback:
            self._sessions_summary_label.setForeground(self._theme.warning)
        elif in_progress:
            self._sessions_summary_label.setForeground(self._theme.accent)
        elif completed:
            self._sessions_summary_label.setForeground(self._theme.success)
        else:
            self._sessions_summary_label.setForeground(self._theme.text_secondary)

    def _do_attach_by_id(self, event):
        sid = self._attach_id_field.getText().strip()
        if not sid:
            return
        if self._session_table_model.find_by_id(sid) is not None:
            JOptionPane.showMessageDialog(self._main_panel, "Session %s is already tracked." % sid, "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        entry = SessionEntry(sid)
        idx = self._session_table_model.add_entry(entry)
        self._attach_id_field.setText("")
        self._select_session_row(idx)
        self._log("Attached session %s." % sid)
        self._persist_tracked_sessions()
        self._update_sessions_summary_label()
        self._refresh_session(entry, True)

    def _do_attach_existing(self, event):
        api_key = self._get_api_key()
        if not api_key:
            JOptionPane.showMessageDialog(self._main_panel, "Enter your Jules API key first.",
                                           "Missing API key", JOptionPane.WARNING_MESSAGE)
            return

        def worker():
            result = self._jules_request(api_key, "GET", "/sessions?pageSize=30")
            return result.get("sessions", []) or []

        def on_success(sessions):
            if not sessions:
                JOptionPane.showMessageDialog(self._main_panel, "No sessions found on your account yet.",
                                               "Siren", JOptionPane.INFORMATION_MESSAGE)
                return
            list_model = DefaultListModel()
            rows = []
            for s in sessions:
                name = s.get("name", "")
                sid = name.split("/")[-1] if name else s.get("id", "")
                already = self._session_table_model.find_by_id(sid) is not None
                label = "%s -- %s [%s]%s" % (
                    sid, s.get("title", "(untitled)"), s.get("state", "?"),
                    "  (already tracked)" if already else ""
                )
                list_model.addElement(label)
                rows.append((sid, s.get("title", "")))

            jlist = JList(list_model)
            jlist.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
            jlist.setVisibleRowCount(12)
            jlist.setFont(self._theme.MONO_FONT_SMALL)
            jlist.setBackground(self._theme.input_bg)
            jlist.setForeground(self._theme.text_primary)
            jlist.setSelectionBackground(self._theme.accent)
            jlist.setSelectionForeground(self._theme.accent_fg)
            scroll = self._scroll_of(jlist, Dimension(560, 280))
            result = JOptionPane.showConfirmDialog(
                self._main_panel, scroll, "Select session(s) to attach", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
            )
            if result != JOptionPane.OK_OPTION:
                return
            added = 0
            last_idx = -1
            for i in list(jlist.getSelectedIndices()):
                sid, title = rows[i]
                if self._session_table_model.find_by_id(sid) is not None:
                    continue
                entry = SessionEntry(sid, title)
                last_idx = self._session_table_model.add_entry(entry)
                self._refresh_session(entry, True)
                added += 1
            if added:
                self._log("Attached %d session(s)." % added)
                self._select_session_row(last_idx)
                self._persist_tracked_sessions()
            self._update_sessions_summary_label()

        def on_error(msg):
            self._log("[-] Failed to fetch sessions: %s" % msg)

        self._run_async(worker, on_success, on_error)

    def _do_remove_selected_sessions(self, event):
        rows = self._get_selected_session_rows()
        if not rows:
            JOptionPane.showMessageDialog(self._main_panel, "Select one or more sessions first.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return
        self._session_table_model.remove_rows(rows)
        self._update_session_action_buttons()
        self._update_sessions_summary_label()
        self._persist_tracked_sessions()
        self._log("Stopped tracking %d session(s) (they still exist in Jules, just no longer shown here)."
                  % len(rows))

    def _do_view_activity_log(self, event):
        rows = self._get_selected_session_rows()
        if len(rows) != 1:
            JOptionPane.showMessageDialog(self._main_panel, "Select exactly one session to view its log.",
                                           "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        entry = self._session_table_model.entries[rows[0]]
        text = "\n\n".join(entry.activity_lines) if entry.activity_lines else "(no activity yet -- try Refresh)"
        area = self._text_area(26, 80, mono=True)
        area.setText(text)
        area.setEditable(False)
        area.setCaretPosition(0)
        header = entry.session_id
        if entry.title:
            header += "  --  " + entry.title
        if entry.task_type:
            header += "  [" + entry.task_type + "]"
        JOptionPane.showMessageDialog(self._main_panel, self._scroll_of(area), "Activity Log -- " + header,
                                       JOptionPane.PLAIN_MESSAGE)

    def _do_open_selected_in_browser(self, event):
        rows = self._get_selected_session_rows()
        if len(rows) != 1:
            return
        entry = self._session_table_model.entries[rows[0]]
        if not entry.web_url:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "No web URL yet for this session -- try Refresh Selected first.",
                                           "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        self._open_url_in_browser(entry.web_url)

    def _show_sessions_table_popup(self, component, x, y):
        menu = JPopupMenu()
        menu.add(JMenuItem("View Activity Log", actionPerformed=lambda e: self._do_view_activity_log(None)))
        menu.add(JMenuItem("Refresh Selected", actionPerformed=lambda e: self._do_refresh_selected_sessions(None)))
        menu.add(JMenuItem("Approve Plan", actionPerformed=lambda e: self._do_approve_plan(None)))
        menu.add(JMenuItem("Open in Browser", actionPerformed=lambda e: self._do_open_selected_in_browser(None)))
        menu.addSeparator()
        menu.add(JMenuItem("Send Bundle as Follow-up", actionPerformed=lambda e: self._do_send_followup(None)))
        menu.addSeparator()
        menu.add(JMenuItem("Remove from List", actionPerformed=lambda e: self._do_remove_selected_sessions(None)))
        menu.show(component, x, y)

    def _do_preview_bundle(self, event):
        entries_snapshot = self._get_dispatch_entries()
        if not entries_snapshot:
            JOptionPane.showMessageDialog(self._main_panel, "Capture at least one request first.", "Siren",
                                           JOptionPane.INFORMATION_MESSAGE)
            return

        task_type = str(self._task_type_combo.getSelectedItem())
        hypothesis_text = self._hypothesis_area.getText()
        redact_enabled = self._redact_checkbox.isSelected()
        max_body_chars = int(self._max_body_spinner.getValue())

        bundle_json_str, prompt_str = self._assemble_bundle_and_prompt(
            entries_snapshot, task_type, hypothesis_text, redact_enabled, max_body_chars
        )
        self._last_bundle_json = bundle_json_str
        self._last_prompt = prompt_str

        area = self._text_area(30, 90, mono=True)
        area.setText(prompt_str)
        area.setEditable(False)
        area.setCaretPosition(0)
        JOptionPane.showMessageDialog(
            self._main_panel, self._scroll_of(area, Dimension(960, 560)),
            "Prompt Preview (%d context(s)) -- nothing has been sent yet" % len(entries_snapshot),
            JOptionPane.PLAIN_MESSAGE
        )

    def _do_copy_prompt(self, event):
        if not self._last_prompt:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Nothing to copy yet -- use Preview Bundle or dispatch first.",
                                           "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(self._last_prompt), None)
        self._log("[i] Prompt copied to clipboard (%d chars)." % len(self._last_prompt))

    def _do_export_bundle(self, event):
        if not self._last_bundle_json:
            JOptionPane.showMessageDialog(self._main_panel,
                                           "Nothing to export yet -- use Preview Bundle or dispatch first.",
                                           "Siren", JOptionPane.INFORMATION_MESSAGE)
            return
        chooser = JFileChooser()
        chooser.setSelectedFile(File("siren-bundle-%d.json" % long(time.time())))
        result = chooser.showSaveDialog(self._main_panel)
        if result == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            try:
                fh = open(f.getAbsolutePath(), "w")
                try:
                    fh.write(self._last_bundle_json)
                finally:
                    fh.close()
                self._log("[+] Bundle exported to %s" % f.getAbsolutePath())
            except Exception as e:
                JOptionPane.showMessageDialog(self._main_panel, "Failed to write file: %s" % str(e),
                                               "Error", JOptionPane.ERROR_MESSAGE)

    # -----------------------------------------------------------------
    # Misc
    # -----------------------------------------------------------------

    def _get_api_key(self):
        chars = self._api_key_field.getPassword()
        return "".join(chars).strip() if chars else ""

    def _set_dispatch_enabled(self, enabled):
        self._dispatch_btn.setEnabled(enabled)

    def _open_url_in_browser(self, url):
        if not url:
            return
        try:
            if Desktop.isDesktopSupported():
                d = Desktop.getDesktop()
                if d.isSupported(Desktop.Action.BROWSE):
                    d.browse(URI(url))
                    return
            self._log("[i] Can't open a browser from this environment. URL: %s" % url)
        except Exception as e:
            self._log("[i] Could not open browser (%s). URL: %s" % (str(e), url))
