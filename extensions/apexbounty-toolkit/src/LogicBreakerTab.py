# -*- coding: utf-8 -*-
"""
LogicBreakerTab.py - Tab 1: State-Aware Logic Breaker
Implements live flow capture, junk filtering, baseline management,
stateful sequence execution, pruning, and differential result reporting.
Compatible with Jython 2.7 and Python 3.x environments.
"""

import sys
import os
import time
import json
import base64
import threading

try:
    from java.awt import (
        BorderLayout, FlowLayout, Dimension, GridBagLayout,
        GridBagConstraints, Insets, Color, Font, Toolkit
    )
    from java.awt.datatransfer import StringSelection
    from javax.swing import (
        JPanel, JButton, JLabel, JTable, JScrollPane, JSplitPane,
        JSeparator, SwingUtilities, JOptionPane, ListSelectionModel,
        JProgressBar, JTextField, JCheckBox, JComboBox, JDialog,
        JTextArea, JPopupMenu, JMenuItem, JFileChooser, BorderFactory
    )
    from javax.swing.table import DefaultTableModel, TableRowSorter
except ImportError:
    pass

from ApexToolkitLogic import (
    LogicBreakerEngine, JunkFilter, TokenExtractor, RequestMutator, to_str
)

def req_to_b64(req_bytes):
    if not req_bytes:
        return ""
    if isinstance(req_bytes, str):
        try:
            return base64.b64encode(req_bytes.encode('latin1')).decode('ascii')
        except Exception:
            return base64.b64encode(req_bytes).decode('ascii')
    try:
        return base64.b64encode(bytes(req_bytes)).decode('ascii')
    except Exception:
        return ""

def b64_to_req(b64_str):
    if not b64_str:
        return bytearray()
    try:
        return bytearray(base64.b64decode(b64_str))
    except Exception:
        return bytearray()

def copy_to_clipboard(text):
    try:
        selection = StringSelection(text)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, None)
    except Exception:
        pass

def generate_curl(host, port, use_https, request_bytes):
    req_str = to_str(request_bytes)
    parts = req_str.split('\r\n\r\n', 1)
    headers_part = parts[0]
    body_part = parts[1] if len(parts) > 1 else ''

    lines = headers_part.splitlines()
    if not lines:
        return ""

    first_line = lines[0]
    tokens = first_line.split(' ')
    method = tokens[0] if len(tokens) > 0 else 'GET'
    path = tokens[1] if len(tokens) > 1 else '/'

    scheme = 'https' if use_https else 'http'
    port_str = "" if (use_https and port == 443) or (not use_https and port == 80) else (":" + str(port))
    url = "%s://%s%s%s" % (scheme, host, port_str, path)

    curl_parts = ["curl -i -s -k -X %s \"%s\"" % (method, url)]

    for line in lines[1:]:
        if ':' in line:
            curl_parts.append("-H \"%s\"" % line.replace('"', '\\"'))

    if body_part:
        curl_parts.append("--data-raw \"%s\"" % body_part.replace('"', '\\"'))

    return " \\\n  ".join(curl_parts)


class FlowCaptureManager(object):
    """
    Background flow capture manager that polls Burp Proxy History
    for in-scope, session-matched, non-junk requests.
    """

    def __init__(self, callbacks, helpers, junk_filter, on_step_captured_cb, on_status_change_cb):
        self.callbacks = callbacks
        self.helpers = helpers
        self.junk_filter = junk_filter
        self.on_step_captured_cb = on_step_captured_cb
        self.on_status_change_cb = on_status_change_cb

        self.is_capturing = False
        self.start_time_ms = 0
        self.start_host = None
        self.session_identifiers = {}
        self.seen_fingerprints = set()
        self.inactivity_timeout_sec = 60
        self.last_capture_time = 0
        self.poll_thread = None

    def start_capture(self, start_service=None, start_req_bytes=None):
        self.is_capturing = True
        self.start_time_ms = int(time.time() * 1000)
        self.last_capture_time = time.time()
        self.seen_fingerprints.clear()
        self.session_identifiers.clear()

        if start_req_bytes and start_service:
            self.start_host = start_service.getHost()
            req_info = self.helpers.analyzeRequest(start_service, start_req_bytes)
            headers = list(req_info.getHeaders()) if req_info.getHeaders() else []
            for h in headers:
                if h.lower().startswith('cookie:'):
                    self.session_identifiers['cookie'] = h.split(':', 1)[1].strip()
                elif h.lower().startswith('authorization:'):
                    self.session_identifiers['auth'] = h.split(':', 1)[1].strip()

        if self.on_status_change_cb:
            self.on_status_change_cb("Capturing... (0 steps)")

        self.poll_thread = threading.Thread(target=self._poll_loop)
        self.poll_thread.daemon = True
        self.poll_thread.start()

    def stop_capture(self):
        self.is_capturing = False
        if self.on_status_change_cb:
            self.on_status_change_cb("Stopped")

    def _poll_loop(self):
        step_count = 0
        while self.is_capturing:
            try:
                history = self.callbacks.getProxyHistory()
                if history:
                    recent_history = history[-200:] if len(history) > 200 else history
                    for item in reversed(recent_history): # Scan recent 200 items
                        if not self.is_capturing:
                            break

                        service = item.getHttpService()
                        req_bytes = item.getRequest()
                        if not service or not req_bytes:
                            continue

                        host = service.getHost()
                        if self.start_host and host.lower() != self.start_host.lower():
                            try:
                                req_url = self.helpers.analyzeRequest(service, req_bytes).getUrl()
                                if not self.callbacks.isInScope(req_url):
                                    continue
                            except Exception:
                                continue

                        req_info = self.helpers.analyzeRequest(service, req_bytes)
                        url = req_info.getUrl()
                        method = req_info.getMethod()
                        path = url.getPath() if url else "/"
                        url_str = str(url) if url else ""

                        resp_bytes = item.getResponse()
                        status_code = 200
                        content_type = ""
                        resp_len = 0
                        resp_str = ""

                        if resp_bytes:
                            resp_info = self.helpers.analyzeResponse(resp_bytes)
                            status_code = resp_info.getStatusCode()
                            resp_len = len(resp_bytes)
                            resp_headers = resp_info.getHeaders()
                            if resp_headers:
                                for rh in resp_headers:
                                    if rh.lower().startswith('content-type:'):
                                        content_type = rh.split(':', 1)[1].strip()
                            resp_str = to_str(resp_bytes)

                        is_junk, reason = self.junk_filter.is_junk(method, path, content_type, url_str, status_code)
                        if is_junk:
                            continue

                        item_id = str(hash(item)) if hasattr(item, '__hash__') else str(id(item))
                        fp = "%s %s %s %s %s" % (method, host, path, str(len(req_bytes)), item_id)
                        if fp in self.seen_fingerprints:
                            continue

                        self.seen_fingerprints.add(fp)
                        step_count += 1
                        self.last_capture_time = time.time()

                        step_data = {
                            'http_service': service,
                            'request_bytes': req_bytes,
                            'method': method,
                            'host': host,
                            'port': service.getPort(),
                            'protocol': service.getProtocol(),
                            'path': path,
                            'status': str(status_code),
                            'length': str(resp_len),
                            'content_type': content_type,
                            'source': 'Captured',
                            'response_body': resp_str,
                            'notes': 'Auto captured step %d' % step_count,
                            'name': method + " " + path
                        }

                        if self.on_step_captured_cb:
                            def dispatch_step(sd=step_data, sc=step_count):
                                self.on_step_captured_cb(sd)
                                if self.on_status_change_cb and self.is_capturing:
                                    self.on_status_change_cb("Capturing... (%d steps)" % sc)
                            SwingUtilities.invokeLater(dispatch_step)

                if time.time() - self.last_capture_time > self.inactivity_timeout_sec:
                    self.stop_capture()
                    if self.on_status_change_cb:
                        def dispatch_timeout():
                            self.on_status_change_cb("Stopped (Inactivity timeout)")
                        SwingUtilities.invokeLater(dispatch_timeout)
                    break

            except Exception:
                pass

            time.sleep(0.4)


class BaselineManager(object):
    """
    Handles persisting and loading clean baselines to Burp settings and fallback JSON file.
    """
    SETTING_KEY = "apexbounty_logic_breaker_baselines"

    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.file_path = os.path.expanduser("~/.apexbounty_logic_breaker_baselines.json")

    def load_baselines(self):
        try:
            saved_str = self.callbacks.loadExtensionSetting(self.SETTING_KEY)
            if saved_str:
                return json.loads(saved_str)
        except Exception:
            pass

        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass

        return {}

    def save_baseline(self, name, steps):
        baselines = self.load_baselines()
        serializable_steps = []

        for s in steps:
            req_b64 = req_to_b64(s.get('request_bytes'))
            serializable_steps.append({
                'method': s.get('method', 'GET'),
                'host': s.get('host', ''),
                'port': s.get('port', 80),
                'protocol': s.get('protocol', 'http'),
                'path': s.get('path', '/'),
                'status': s.get('status', 'N/A'),
                'length': s.get('length', 'N/A'),
                'content_type': s.get('content_type', ''),
                'source': s.get('source', 'Baseline'),
                'notes': s.get('notes', ''),
                'request_b64': req_b64,
                'name': s.get('name', '')
            })

        baselines[name] = serializable_steps
        json_str = json.dumps(baselines)

        try:
            self.callbacks.saveExtensionSetting(self.SETTING_KEY, json_str)
        except Exception:
            pass

        try:
            with open(self.file_path, 'w') as f:
                f.write(json_str)
        except Exception:
            pass


class LogicBreakerTab(object):
    """
    Main Logic Breaker Tab UI and Controller.
    """

    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.recorded_requests = []
        self.baseline_requests = []
        self.attack_results = []
        self.is_attacking = False
        self.is_cancel_requested = False

        self.junk_filter = JunkFilter()
        self.baseline_manager = BaselineManager(callbacks)
        self.token_refresh_lock = threading.Lock()

        self.capture_manager = FlowCaptureManager(
            callbacks, helpers, self.junk_filter,
            self._on_step_captured, self._on_capture_status_changed
        )

        self._init_ui()
        self._load_saved_baselines_combo()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout(5, 5))

        # --- Top Control Bar ---
        top_bar = JPanel(BorderLayout())
        ctrl_left = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))

        lbl_title = JLabel("Logic Breaker")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0))

        self.btn_start_capture = JButton("Start Flow Capture", actionPerformed=self._on_start_capture)
        self.btn_stop_capture = JButton("Stop Flow Capture", actionPerformed=self._on_stop_capture)
        self.btn_stop_capture.setEnabled(False)

        self.lbl_capture_status = JLabel("Status: Idle")

        self.btn_finalize = JButton("Finalize Baseline", actionPerformed=self._on_finalize_baseline)

        self.combo_baselines = JComboBox()
        self.combo_baselines.setPreferredSize(Dimension(160, 25))
        self.btn_load_baseline = JButton("Load Baseline", actionPerformed=self._on_load_baseline)

        self.btn_filter_settings = JButton("Filter Rules...", actionPerformed=self._on_open_filter_settings)

        ctrl_left.add(lbl_title)
        ctrl_left.add(JSeparator(1))
        ctrl_left.add(self.btn_start_capture)
        ctrl_left.add(self.btn_stop_capture)
        ctrl_left.add(self.lbl_capture_status)
        ctrl_left.add(JSeparator(1))
        ctrl_left.add(self.btn_finalize)
        ctrl_left.add(self.combo_baselines)
        ctrl_left.add(self.btn_load_baseline)
        ctrl_left.add(self.btn_filter_settings)

        ctrl_right = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 5))
        self.btn_attack = JButton("Run Permutations", actionPerformed=self._on_run_attack)
        self.btn_cancel = JButton("Cancel Attack", actionPerformed=self._on_cancel_attack)
        self.btn_cancel.setEnabled(False)
        self.btn_clear = JButton("Clear All", actionPerformed=self._on_clear_sequence)

        ctrl_right.add(self.btn_attack)
        ctrl_right.add(self.btn_cancel)
        ctrl_right.add(self.btn_clear)

        top_bar.add(ctrl_left, BorderLayout.WEST)
        top_bar.add(ctrl_right, BorderLayout.EAST)

        # Progress bar panel under top bar
        prog_panel = JPanel(BorderLayout(5, 0))
        prog_panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 5, 10))
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setStringPainted(True)
        self.progress_bar.setString("Ready")
        prog_panel.add(self.progress_bar, BorderLayout.CENTER)

        top_container = JPanel(BorderLayout())
        top_container.add(top_bar, BorderLayout.NORTH)
        top_container.add(prog_panel, BorderLayout.SOUTH)

        # --- Sequence Table Section ---
        seq_panel = JPanel(BorderLayout(5, 5))
        seq_toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))

        seq_label = JLabel(" Sequence Steps (Live Editable)")
        seq_label.setFont(seq_label.getFont().deriveFont(1, 12.0) if seq_label.getFont() else None)

        btn_del_seq = JButton("Delete Selected", actionPerformed=self._on_delete_seq_steps)
        btn_up_seq = JButton("Move Up", actionPerformed=self._on_move_seq_up)
        btn_down_seq = JButton("Move Down", actionPerformed=self._on_move_seq_down)
        btn_edit_seq = JButton("Edit Request", actionPerformed=self._on_edit_seq_step)
        btn_reset_seq = JButton("Reset to Baseline", actionPerformed=self._on_reset_to_baseline)
        btn_mark_auth = JButton("Set Token Generator", actionPerformed=self._on_mark_auth_generator)

        lbl_seq_search = JLabel("Search:")
        self.txt_seq_search = JTextField(12)
        self.txt_seq_search.addActionListener(self._on_seq_search)

        seq_toolbar.add(seq_label)
        seq_toolbar.add(JSeparator(1))
        seq_toolbar.add(btn_del_seq)
        seq_toolbar.add(btn_up_seq)
        seq_toolbar.add(btn_down_seq)
        seq_toolbar.add(btn_edit_seq)
        seq_toolbar.add(btn_mark_auth)
        seq_toolbar.add(btn_reset_seq)
        seq_toolbar.add(JSeparator(1))
        seq_toolbar.add(lbl_seq_search)
        seq_toolbar.add(self.txt_seq_search)

        self.seq_table_model = DefaultTableModel(
            ["#", "Source", "Method", "Host", "Path", "Status", "Length", "Content-Type", "Notes"], 0
        )
        self.seq_table = JTable(self.seq_table_model)
        self.seq_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.seq_sorter = TableRowSorter(self.seq_table_model)
        self.seq_table.setRowSorter(self.seq_sorter)

        seq_scroll = JScrollPane(self.seq_table)

        seq_panel.add(seq_toolbar, BorderLayout.NORTH)
        seq_panel.add(seq_scroll, BorderLayout.CENTER)

        # --- Results Table Section ---
        res_panel = JPanel(BorderLayout(5, 5))
        res_toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))

        res_label = JLabel(" Permutation Attack Results")
        res_label.setFont(res_label.getFont().deriveFont(1, 12.0) if res_label.getFont() else None)

        lbl_res_search = JLabel("Search Results:")
        self.txt_res_search = JTextField(15)
        self.txt_res_search.addActionListener(self._on_res_search)

        res_toolbar.add(res_label)
        res_toolbar.add(JSeparator(1))
        res_toolbar.add(lbl_res_search)
        res_toolbar.add(self.txt_res_search)

        self.results_table_model = DefaultTableModel(
            ["#", "Permutation", "Description", "Steps Executed", "Final Status", "Final Length", "Diff / State Result"], 0
        )
        self.results_table = JTable(self.results_table_model)
        self.results_sorter = TableRowSorter(self.results_table_model)
        self.results_table.setRowSorter(self.results_sorter)

        # Context Menu for Results Table
        self._init_results_context_menu()

        res_scroll = JScrollPane(self.results_table)

        res_panel.add(res_toolbar, BorderLayout.NORTH)
        res_panel.add(res_scroll, BorderLayout.CENTER)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, seq_panel, res_panel)
        split_pane.setResizeWeight(0.45)

        self.panel.add(top_container, BorderLayout.NORTH)
        self.panel.add(split_pane, BorderLayout.CENTER)

    def _init_results_context_menu(self):
        self.results_popup = JPopupMenu()

        menu_repeater = JMenuItem("Send Final Request to Repeater", actionPerformed=self._on_res_send_repeater)
        menu_curl = JMenuItem("Copy Final Request as cURL", actionPerformed=self._on_res_copy_curl)
        menu_export_json = JMenuItem("Export Results as JSON Report", actionPerformed=self._on_res_export_json)
        menu_export_md = JMenuItem("Export Results as Markdown Report", actionPerformed=self._on_res_export_md)

        self.results_popup.add(menu_repeater)
        self.results_popup.add(menu_curl)
        self.results_popup.addSeparator()
        self.results_popup.add(menu_export_json)
        self.results_popup.add(menu_export_md)

        self.results_table.setComponentPopupMenu(self.results_popup)

    def get_component(self):
        return self.panel

    # --------------------------------------------------------------------------
    # Request Addition & Flow Capture Callbacks
    # --------------------------------------------------------------------------
    def add_request(self, http_service, request_bytes, source="Manual"):
        req_info = self.helpers.analyzeRequest(http_service, request_bytes)
        url = req_info.getUrl()
        method = req_info.getMethod()
        host = http_service.getHost()
        port = http_service.getPort()
        protocol = http_service.getProtocol()
        path = url.getPath() if url else "/"

        step_dict = {
            'http_service': http_service,
            'request_bytes': request_bytes,
            'method': method,
            'host': host,
            'port': port,
            'protocol': protocol,
            'path': path,
            'status': 'N/A',
            'length': str(len(request_bytes)),
            'content_type': '',
            'source': source,
            'notes': '%s step' % source,
            'name': method + " " + path
        }
        self.recorded_requests.append(step_dict)
        self._refresh_sequence_table()

    def start_flow_from_request(self, http_service, request_bytes):
        self.add_request(http_service, request_bytes, source="Start Point")
        self._on_start_capture(None)

    def _on_step_captured(self, step_data):
        self.recorded_requests.append(step_data)
        self._refresh_sequence_table()

    def _on_capture_status_changed(self, status_text):
        def update():
            self.lbl_capture_status.setText("Status: " + status_text)
            if "Capturing" in status_text:
                self.btn_start_capture.setEnabled(False)
                self.btn_stop_capture.setEnabled(True)
            else:
                self.btn_start_capture.setEnabled(True)
                self.btn_stop_capture.setEnabled(False)
        SwingUtilities.invokeLater(update)

    def _on_start_capture(self, event):
        start_svc = self.recorded_requests[0]['http_service'] if self.recorded_requests else None
        start_req = self.recorded_requests[0]['request_bytes'] if self.recorded_requests else None
        self.capture_manager.start_capture(start_svc, start_req)

    def _on_stop_capture(self, event):
        self.capture_manager.stop_capture()

    # --------------------------------------------------------------------------
    # Sequence Table Management & Pruning
    # --------------------------------------------------------------------------
    def _refresh_sequence_table(self):
        def update():
            self.seq_table_model.setRowCount(0)
            for idx, step in enumerate(self.recorded_requests):
                notes = step.get('notes', '')
                if step.get('is_auth_generator'):
                    notes = "[Token Generator] " + notes
                self.seq_table_model.addRow([
                    str(idx + 1),
                    step.get('source', 'Manual'),
                    step.get('method', 'GET'),
                    step.get('host', ''),
                    step.get('path', '/'),
                    step.get('status', 'N/A'),
                    step.get('length', 'N/A'),
                    step.get('content_type', ''),
                    notes
                ])
        SwingUtilities.invokeLater(update)

    def _on_mark_auth_generator(self, event):
        selected_row = self.seq_table.getSelectedRow()
        if selected_row < 0:
            JOptionPane.showMessageDialog(self.panel, "Please select a step to set as Token Generator.")
            return

        model_idx = self.seq_table.convertRowIndexToModel(selected_row)
        for idx, step in enumerate(self.recorded_requests):
            step['is_auth_generator'] = (idx == model_idx)

        self._refresh_sequence_table()
        JOptionPane.showMessageDialog(self.panel, "Step #" + str(model_idx + 1) + " set as Token Generator.")

    def _on_delete_seq_steps(self, event):
        selected_rows = self.seq_table.getSelectedRows()
        if not selected_rows:
            return

        # Convert view indices to model indices
        model_indices = [self.seq_table.convertRowIndexToModel(r) for r in selected_rows]
        model_indices.sort(reverse=True)

        for idx in model_indices:
            if 0 <= idx < len(self.recorded_requests):
                del self.recorded_requests[idx]

        self._refresh_sequence_table()

    def _on_move_seq_up(self, event):
        selected_row = self.seq_table.getSelectedRow()
        if selected_row <= 0:
            return
        model_idx = self.seq_table.convertRowIndexToModel(selected_row)
        if model_idx > 0:
            self.recorded_requests[model_idx - 1], self.recorded_requests[model_idx] = \
                self.recorded_requests[model_idx], self.recorded_requests[model_idx - 1]
            self._refresh_sequence_table()
            self.seq_table.setRowSelectionInterval(selected_row - 1, selected_row - 1)

    def _on_move_seq_down(self, event):
        selected_row = self.seq_table.getSelectedRow()
        if selected_row < 0 or selected_row >= len(self.recorded_requests) - 1:
            return
        model_idx = self.seq_table.convertRowIndexToModel(selected_row)
        if model_idx < len(self.recorded_requests) - 1:
            self.recorded_requests[model_idx + 1], self.recorded_requests[model_idx] = \
                self.recorded_requests[model_idx], self.recorded_requests[model_idx + 1]
            self._refresh_sequence_table()
            self.seq_table.setRowSelectionInterval(selected_row + 1, selected_row + 1)

    def _on_edit_seq_step(self, event):
        selected_row = self.seq_table.getSelectedRow()
        if selected_row < 0:
            JOptionPane.showMessageDialog(self.panel, "Please select a sequence step to edit.")
            return

        model_idx = self.seq_table.convertRowIndexToModel(selected_row)
        step = self.recorded_requests[model_idx]

        dialog = JDialog(JOptionPane.getFrameForComponent(self.panel), "Edit Request Step #" + str(model_idx + 1), True)
        dialog.setLayout(BorderLayout(5, 5))
        dialog.setSize(650, 450)

        txt_editor = JTextArea(to_str(step['request_bytes']))
        txt_editor.setFont(Font("Monospaced", Font.PLAIN, 12))
        scroll = JScrollPane(txt_editor)

        btn_save = JButton("Save Changes")
        btn_cancel = JButton("Cancel")

        def save_action(e):
            new_text = txt_editor.getText()
            step['request_bytes'] = new_text.encode('latin1') if hasattr(new_text, 'encode') else new_text
            step['length'] = str(len(step['request_bytes']))
            self._refresh_sequence_table()
            dialog.dispose()

        def cancel_action(e):
            dialog.dispose()

        btn_save.addActionListener(save_action)
        btn_cancel.addActionListener(cancel_action)

        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_panel.add(btn_save)
        btn_panel.add(btn_cancel)

        dialog.add(scroll, BorderLayout.CENTER)
        dialog.add(btn_panel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(self.panel)
        dialog.setVisible(True)

    def _on_clear_sequence(self, event):
        self.recorded_requests = []
        self.attack_results = []
        self._refresh_sequence_table()
        self.results_table_model.setRowCount(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setString("Cleared")

    # --------------------------------------------------------------------------
    # Baselines Persistence & Loading
    # --------------------------------------------------------------------------
    def _on_finalize_baseline(self, event):
        if not self.recorded_requests:
            JOptionPane.showMessageDialog(self.panel, "No sequence steps to finalize.")
            return

        name = JOptionPane.showInputDialog(self.panel, "Enter a name for this baseline:", "Finalize Flow Baseline", JOptionPane.PLAIN_MESSAGE)
        if not name or not name.strip():
            return

        name = name.strip()
        self.baseline_requests = [dict(s) for s in self.recorded_requests]
        self.baseline_manager.save_baseline(name, self.recorded_requests)

        JOptionPane.showMessageDialog(self.panel, "Baseline '%s' saved successfully!" % name)
        self._load_saved_baselines_combo()

    def _load_saved_baselines_combo(self):
        baselines = self.baseline_manager.load_baselines()
        self.combo_baselines.removeAllItems()
        for b_name in baselines.keys():
            self.combo_baselines.addItem(b_name)

    def _on_load_baseline(self, event):
        selected_name = self.combo_baselines.getSelectedItem()
        if not selected_name:
            return

        baselines = self.baseline_manager.load_baselines()
        if selected_name not in baselines:
            return

        steps_raw = baselines[selected_name]
        self.recorded_requests = []

        for s in steps_raw:
            host = s.get('host', '')
            port = int(s.get('port', 80))
            protocol = s.get('protocol', 'http')
            use_https = (protocol.lower() == 'https') or (port == 443)
            http_svc = self.helpers.buildHttpService(host, port, use_https) if host else None
            req_b = b64_to_req(s.get('request_b64', ''))

            step_dict = {
                'http_service': http_svc,
                'request_bytes': req_b,
                'method': s.get('method', 'GET'),
                'host': host,
                'port': port,
                'protocol': protocol,
                'path': s.get('path', '/'),
                'status': s.get('status', 'N/A'),
                'length': s.get('length', 'N/A'),
                'content_type': s.get('content_type', ''),
                'source': 'Baseline: ' + str(selected_name),
                'notes': s.get('notes', ''),
                'name': s.get('name', s.get('method', 'GET') + " " + s.get('path', '/'))
            }
            self.recorded_requests.append(step_dict)

        self.baseline_requests = [dict(r) for r in self.recorded_requests]
        self._refresh_sequence_table()
        self.progress_bar.setString("Loaded baseline: " + str(selected_name))

    def _on_reset_to_baseline(self, event):
        if not self.baseline_requests:
            JOptionPane.showMessageDialog(self.panel, "No finalized baseline active in current session.")
            return

        self.recorded_requests = [dict(b) for b in self.baseline_requests]
        self._refresh_sequence_table()

    # --------------------------------------------------------------------------
    # Filter Settings Dialog
    # --------------------------------------------------------------------------
    def _on_open_filter_settings(self, event):
        dialog = JDialog(JOptionPane.getFrameForComponent(self.panel), "Junk Filter Settings", True)
        dialog.setLayout(GridBagLayout())
        dialog.setSize(500, 350)
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 10, 5, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL

        chk_enabled = JCheckBox("Enable Junk Filter", self.junk_filter.config.get('enabled', True))
        chk_ext = JCheckBox("Filter Excluded Extensions", self.junk_filter.config.get('filter_extensions', True))
        chk_ct = JCheckBox("Filter Excluded Content-Types", self.junk_filter.config.get('filter_content_types', True))
        chk_pat = JCheckBox("Filter Excluded Path Patterns", self.junk_filter.config.get('filter_patterns', True))
        chk_interesting = JCheckBox("Interesting Only Mode (POST/PUT/API/Errors)", self.junk_filter.config.get('interesting_only', False))

        txt_ext = JTextField(", ".join(self.junk_filter.config.get('excluded_extensions', [])))
        txt_ct = JTextField(", ".join(self.junk_filter.config.get('excluded_content_types', [])))
        txt_pat = JTextField(", ".join(self.junk_filter.config.get('excluded_patterns', [])))

        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2
        dialog.add(chk_enabled, gbc)

        gbc.gridy = 1; dialog.add(chk_ext, gbc)
        gbc.gridy = 2; dialog.add(txt_ext, gbc)

        gbc.gridy = 3; dialog.add(chk_ct, gbc)
        gbc.gridy = 4; dialog.add(txt_ct, gbc)

        gbc.gridy = 5; dialog.add(chk_pat, gbc)
        gbc.gridy = 6; dialog.add(txt_pat, gbc)

        gbc.gridy = 7; dialog.add(chk_interesting, gbc)

        btn_save = JButton("Save")
        btn_cancel = JButton("Cancel")

        def save_opts(e):
            self.junk_filter.config['enabled'] = chk_enabled.isSelected()
            self.junk_filter.config['filter_extensions'] = chk_ext.isSelected()
            self.junk_filter.config['filter_content_types'] = chk_ct.isSelected()
            self.junk_filter.config['filter_patterns'] = chk_pat.isSelected()
            self.junk_filter.config['interesting_only'] = chk_interesting.isSelected()

            self.junk_filter.config['excluded_extensions'] = [x.strip() for x in txt_ext.getText().split(',') if x.strip()]
            self.junk_filter.config['excluded_content_types'] = [x.strip() for x in txt_ct.getText().split(',') if x.strip()]
            self.junk_filter.config['excluded_patterns'] = [x.strip() for x in txt_pat.getText().split(',') if x.strip()]
            dialog.dispose()

        btn_save.addActionListener(save_opts)
        btn_cancel.addActionListener(lambda e: dialog.dispose())

        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_panel.add(btn_save)
        btn_panel.add(btn_cancel)

        gbc.gridy = 8; dialog.add(btn_panel, gbc)

        dialog.setLocationRelativeTo(self.panel)
        dialog.setVisible(True)

    # --------------------------------------------------------------------------
    # Stateful Attack Execution
    # --------------------------------------------------------------------------
    def _on_run_attack(self, event):
        if not self.recorded_requests:
            JOptionPane.showMessageDialog(self.panel, "Please add or capture sequence steps first.")
            return

        if self.is_attacking:
            return

        self.is_attacking = True
        self.is_cancel_requested = False
        self.btn_attack.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.results_table_model.setRowCount(0)
        self.attack_results = []

        t = threading.Thread(target=self._execute_attack_thread)
        t.daemon = True
        t.start()

    def _on_cancel_attack(self, event):
        if self.is_attacking:
            self.is_cancel_requested = True
            self.progress_bar.setString("Cancelling...")

    def _execute_attack_thread(self):
        try:
            permutations = LogicBreakerEngine.generate_permutations(self.recorded_requests)
            total_perms = len(permutations)

            baseline_status = "N/A"
            baseline_len = "N/A"
            baseline_state = {'cookies': {}, 'headers': {}, 'body_tokens': {}}

            # Execute Baseline first if available
            for idx, perm in enumerate(permutations):
                if self.is_cancel_requested:
                    break

                name = perm['name']
                desc = perm['description']
                seq = perm['sequence']

                def update_prog(i=idx, n=total_perms, nm=name):
                    p = int(((i + 1) * 100.0) / n)
                    self.progress_bar.setValue(p)
                    self.progress_bar.setString("Running %d/%d - %s" % (i + 1, n, nm))
                SwingUtilities.invokeLater(update_prog)

                # Initialize per-permutation state with cached baseline tokens if using baseline state or carry forward
                state_dict = {
                    'cookies': dict(baseline_state['cookies']),
                    'headers': dict(baseline_state['headers']),
                    'body_tokens': dict(baseline_state['body_tokens'])
                }

                final_status = "N/A"
                final_len = "N/A"
                final_resp_body = ""
                last_http_service = None
                last_request_bytes = None

                for step_idx, step in enumerate(seq):
                    if self.is_cancel_requested:
                        break

                    service = step.get('http_service')
                    req_b = step.get('request_bytes')

                    if not service or not req_b:
                        continue

                    last_http_service = service

                    # Apply carry-forward state or baseline tokens
                    if state_dict and (perm.get('carry_state') or perm.get('use_baseline_state')):
                        req_b = RequestMutator.apply_state(req_b, state_dict)

                    # Mass assignment injection if specified
                    if perm.get('inject_mass_assignment_idx') == step_idx:
                        req_str = to_str(req_b)
                        if '?' in req_str:
                            req_str = req_str.replace('?', '?role=admin&is_admin=true&', 1)
                        elif '\r\n\r\n' in req_str:
                            parts = req_str.split('\r\n\r\n', 1)
                            if parts[1].strip().startswith('{'):
                                try:
                                    j = json.loads(parts[1].strip())
                                    j['role'] = 'admin'
                                    j['is_admin'] = True
                                    req_str = parts[0] + '\r\n\r\n' + json.dumps(j)
                                except Exception:
                                    req_str = parts[0] + '\r\n\r\n' + parts[1] + '&role=admin&is_admin=true'
                            else:
                                req_str = parts[0] + '\r\n\r\n' + parts[1] + '&role=admin&is_admin=true'
                        req_b = req_str.encode('latin1') if hasattr(req_str, 'encode') else req_str

                    last_request_bytes = req_b

                    try:
                        resp = self.callbacks.makeHttpRequest(service, req_b)
                        if resp and resp.getResponse():
                            resp_info = self.helpers.analyzeResponse(resp.getResponse())
                            final_status = str(resp_info.getStatusCode())
                            final_len = str(len(resp.getResponse()))
                            final_resp_body = to_str(resp.getResponse())

                            # Automatic token refresh if 401/403 received on non-auth generator step
                            if resp_info.getStatusCode() in (401, 403) and not step.get('is_auth_generator'):
                                self._refresh_auth_tokens(baseline_state, state_dict)
                                req_b_retry = RequestMutator.apply_state(req_b, state_dict)
                                retry_resp = self.callbacks.makeHttpRequest(service, req_b_retry)
                                if retry_resp and retry_resp.getResponse():
                                    retry_info = self.helpers.analyzeResponse(retry_resp.getResponse())
                                    final_status = str(retry_info.getStatusCode())
                                    final_len = str(len(retry_resp.getResponse()))
                                    final_resp_body = to_str(retry_resp.getResponse())
                                    resp = retry_resp

                            # Extract tokens for next step carry-forward
                            extracted = TokenExtractor.extract_tokens(resp.getResponse())
                            state_dict['cookies'].update(extracted.get('cookies', {}))
                            state_dict['headers'].update(extracted.get('headers', {}))
                            state_dict['body_tokens'].update(extracted.get('body_tokens', {}))

                            if idx == 0:
                                baseline_state['cookies'].update(extracted.get('cookies', {}))
                                baseline_state['headers'].update(extracted.get('headers', {}))
                                baseline_state['body_tokens'].update(extracted.get('body_tokens', {}))
                    except Exception as ex:
                        final_status = "Error"
                        final_resp_body = str(ex)

                if idx == 0:
                    baseline_status = final_status
                    baseline_len = final_len

                is_anomaly, result_diff = LogicBreakerEngine.analyze_differential_results(
                    baseline_status, baseline_len, final_status, final_len, final_resp_body
                )

                res_item = {
                    'num': str(idx + 1),
                    'name': name,
                    'desc': desc,
                    'steps_executed': str(len(seq)),
                    'final_status': final_status,
                    'final_len': final_len,
                    'result_diff': result_diff,
                    'is_anomaly': is_anomaly,
                    'last_service': last_http_service,
                    'last_request_bytes': last_request_bytes
                }
                self.attack_results.append(res_item)

                def add_res_row(r=res_item):
                    self.results_table_model.addRow([
                        r['num'], r['name'], r['desc'], r['steps_executed'],
                        r['final_status'], r['final_len'], r['result_diff']
                    ])
                SwingUtilities.invokeLater(add_res_row)

        finally:
            self.is_attacking = False
            def reenable_btn():
                self.btn_attack.setEnabled(True)
                self.btn_cancel.setEnabled(False)
                if self.is_cancel_requested:
                    self.progress_bar.setString("Attack cancelled")
                else:
                    self.progress_bar.setValue(100)
                    self.progress_bar.setString("Permutation attack complete!")
            SwingUtilities.invokeLater(reenable_btn)

    def _refresh_auth_tokens(self, baseline_state, state_dict):
        with self.token_refresh_lock:
            auth_step = None
            for step in self.recorded_requests:
                if step.get('is_auth_generator'):
                    auth_step = step
                    break
            if not auth_step and self.recorded_requests:
                auth_step = self.recorded_requests[0]

            if auth_step and auth_step.get('http_service') and auth_step.get('request_bytes'):
                try:
                    resp = self.callbacks.makeHttpRequest(auth_step['http_service'], auth_step['request_bytes'])
                    if resp and resp.getResponse():
                        extracted = TokenExtractor.extract_tokens(resp.getResponse())
                        baseline_state['cookies'].update(extracted.get('cookies', {}))
                        baseline_state['headers'].update(extracted.get('headers', {}))
                        baseline_state['body_tokens'].update(extracted.get('body_tokens', {}))
                        state_dict['cookies'].update(extracted.get('cookies', {}))
                        state_dict['headers'].update(extracted.get('headers', {}))
                        state_dict['body_tokens'].update(extracted.get('body_tokens', {}))
                except Exception:
                    pass

    # --------------------------------------------------------------------------
    # Search / Filters & Results Actions
    # --------------------------------------------------------------------------
    def _on_seq_search(self, event):
        txt = self.txt_seq_search.getText()
        if not txt:
            self.seq_sorter.setRowFilter(None)
        else:
            from javax.swing import RowFilter
            self.seq_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + txt))

    def _on_res_search(self, event):
        txt = self.txt_res_search.getText()
        if not txt:
            self.results_sorter.setRowFilter(None)
        else:
            from javax.swing import RowFilter
            self.results_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + txt))

    def _get_selected_result_item(self):
        sel_row = self.results_table.getSelectedRow()
        if sel_row < 0:
            return None
        model_idx = self.results_table.convertRowIndexToModel(sel_row)
        if 0 <= model_idx < len(self.attack_results):
            return self.attack_results[model_idx]
        return None

    def _on_res_send_repeater(self, event):
        res = self._get_selected_result_item()
        if not res or not res['last_service'] or not res['last_request_bytes']:
            JOptionPane.showMessageDialog(self.panel, "No request available for selected result.")
            return

        svc = res['last_service']
        req_b = res['last_request_bytes']
        use_https = (svc.getProtocol().lower() == 'https') or (svc.getPort() == 443)
        self.callbacks.sendToRepeater(
            svc.getHost(), svc.getPort(), use_https, req_b, "LogicBreaker #" + res['num']
        )

    def _on_res_copy_curl(self, event):
        res = self._get_selected_result_item()
        if not res or not res['last_service'] or not res['last_request_bytes']:
            return

        svc = res['last_service']
        req_b = res['last_request_bytes']
        use_https = (svc.getProtocol().lower() == 'https') or (svc.getPort() == 443)
        curl_cmd = generate_curl(svc.getHost(), svc.getPort(), use_https, req_b)
        copy_to_clipboard(curl_cmd)
        JOptionPane.showMessageDialog(self.panel, "cURL command copied to clipboard!")

    def _on_res_export_json(self, event):
        if not self.attack_results:
            JOptionPane.showMessageDialog(self.panel, "No results to export.")
            return

        chooser = JFileChooser()
        chooser.setDialogTitle("Export Logic Breaker Results as JSON")
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            target_file = chooser.getSelectedFile().getAbsolutePath()
            if not target_file.endswith('.json'):
                target_file += '.json'

            export_data = []
            for r in self.attack_results:
                export_data.append({
                    'num': r['num'],
                    'name': r['name'],
                    'desc': r['desc'],
                    'steps_executed': r['steps_executed'],
                    'final_status': r['final_status'],
                    'final_len': r['final_len'],
                    'result_diff': r['result_diff'],
                    'is_anomaly': r['is_anomaly']
                })

            try:
                with open(target_file, 'w') as f:
                    json.dump(export_data, f, indent=2)
                JOptionPane.showMessageDialog(self.panel, "Results exported to " + target_file)
            except Exception as ex:
                JOptionPane.showMessageDialog(self.panel, "Export failed: " + str(ex))

    def _on_res_export_md(self, event):
        if not self.attack_results:
            JOptionPane.showMessageDialog(self.panel, "No results to export.")
            return

        chooser = JFileChooser()
        chooser.setDialogTitle("Export Logic Breaker Results as Markdown")
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            target_file = chooser.getSelectedFile().getAbsolutePath()
            if not target_file.endswith('.md'):
                target_file += '.md'

            lines = [
                "# Logic Breaker Attack Report",
                "Generated: " + time.strftime("%Y-%m-%d %H:%M:%S"),
                "",
                "| # | Permutation | Description | Steps | Status | Length | Result / State Diff |",
                "|---|-------------|-------------|-------|--------|--------|---------------------|"
            ]

            for r in self.attack_results:
                lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
                    r['num'], r['name'], r['desc'], r['steps_executed'],
                    r['final_status'], r['final_len'], r['result_diff']
                ))

            try:
                with open(target_file, 'w') as f:
                    f.write("\n".join(lines))
                JOptionPane.showMessageDialog(self.panel, "Markdown report exported to " + target_file)
            except Exception as ex:
                JOptionPane.showMessageDialog(self.panel, "Export failed: " + str(ex))
