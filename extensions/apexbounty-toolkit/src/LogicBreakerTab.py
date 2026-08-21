# -*- coding: utf-8 -*-
"""
LogicBreakerTab.py - Tab 1: State-Aware Logic Breaker
Implements sequence recorder, table pruning, auth generator designation, thread-safe token substitution,
permutation attack generation, baseline replay, and export/import.
"""

import threading
import json
from java.awt import BorderLayout, FlowLayout, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.lang import Boolean, String
from javax.swing import (
    JPanel, JButton, JLabel, JTable, JScrollPane, JSplitPane,
    JSeparator, SwingUtilities, JOptionPane, JCheckBox, JFileChooser
)
from javax.swing.table import DefaultTableModel
from ApexToolkitLogic import LogicBreakerEngine, log_info, log_error, save_setting, load_setting


class SequenceTableModel(DefaultTableModel):
    """
    Custom TableModel to render 'Include' and 'Auth Generator' columns as native JCheckBoxes.
    """
    def __init__(self, headers, row_count):
        DefaultTableModel.__init__(self, headers, row_count)

    def getColumnClass(self, col):
        if col in (1, 2):  # 'Include' and 'Auth Generator' columns
            return Boolean
        return String

    def isCellEditable(self, row, col):
        return col in (1, 2)


class LogicBreakerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers

        self.recorded_requests = []  # list of step dicts
        self.baseline_requests = []  # active baseline list
        self.is_recording = False
        self.is_attacking = False
        self.auth_lock = threading.Lock()  # Thread lock for concurrent auth token refresh

        self._init_ui()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        top_panel = JPanel(BorderLayout())

        # Bar 1: Controls & Recording
        ctrl_bar1 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))

        lbl_title = JLabel("State-Aware Logic Breaker")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0))

        ctrl_bar1.add(lbl_title)
        ctrl_bar1.add(JSeparator(1))

        self.btn_record = JButton("Start Recording", actionPerformed=self._on_toggle_recording)
        self.chk_in_scope = JCheckBox("In-Scope Only", True)
        self.chk_auto_tokens = JCheckBox("Auto-Substitute Tokens", True)

        self.btn_load_history = JButton("Load from History", actionPerformed=self._on_load_history)
        self.btn_export = JButton("Export JSON", actionPerformed=self._on_export_json)
        self.btn_import = JButton("Import JSON", actionPerformed=self._on_import_json)

        ctrl_bar1.add(self.btn_record)
        ctrl_bar1.add(self.chk_in_scope)
        ctrl_bar1.add(self.chk_auto_tokens)
        ctrl_bar1.add(JSeparator(1))
        ctrl_bar1.add(self.btn_load_history)
        ctrl_bar1.add(self.btn_export)
        ctrl_bar1.add(self.btn_import)

        # Bar 2: Pruning, Baseline & Attack Action Bar
        ctrl_bar2 = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))

        self.btn_remove_selected = JButton("Remove Selected", actionPerformed=self._on_remove_selected)
        self.btn_clear = JButton("Clear Sequence", actionPerformed=self._on_clear_sequence)
        self.btn_set_baseline = JButton("Set as Baseline", actionPerformed=self._on_set_baseline)
        self.btn_replay_baseline = JButton("Replay Baseline", actionPerformed=self._on_replay_baseline)
        self.btn_attack = JButton("Run Permutation Attack", actionPerformed=self._on_run_attack)

        self.lbl_status = JLabel("Sequence Steps: 0 (Baseline: 0)")

        ctrl_bar2.add(self.btn_remove_selected)
        ctrl_bar2.add(self.btn_clear)
        ctrl_bar2.add(self.btn_set_baseline)
        ctrl_bar2.add(self.btn_replay_baseline)
        ctrl_bar2.add(self.btn_attack)
        ctrl_bar2.add(JSeparator(1))
        ctrl_bar2.add(self.lbl_status)

        top_panel.add(ctrl_bar1, BorderLayout.NORTH)
        top_panel.add(ctrl_bar2, BorderLayout.SOUTH)

        # Sequence Steps Table
        headers = ["Step #", "Include", "Auth Generator", "Method", "Host", "Path"]
        self.seq_table_model = SequenceTableModel(headers, 0)
        self.seq_table = JTable(self.seq_table_model)
        self.seq_table.getColumnModel().getColumn(0).setPreferredWidth(50)
        self.seq_table.getColumnModel().getColumn(1).setPreferredWidth(60)
        self.seq_table.getColumnModel().getColumn(2).setPreferredWidth(100)

        seq_scroll = JScrollPane(self.seq_table)

        seq_panel = JPanel(BorderLayout())
        seq_panel.add(JLabel(" Captured Workflow Sequence"), BorderLayout.NORTH)
        seq_panel.add(seq_scroll, BorderLayout.CENTER)

        # Results Table
        self.results_table_model = DefaultTableModel(
            ["Permutation", "Description", "Steps Executed", "Final Status", "Final Length"], 0
        )
        self.results_table = JTable(self.results_table_model)
        res_scroll = JScrollPane(self.results_table)

        res_panel = JPanel(BorderLayout())
        res_panel.add(JLabel(" Permutation Attack Results"), BorderLayout.NORTH)
        res_panel.add(res_scroll, BorderLayout.CENTER)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, seq_panel, res_panel)
        split_pane.setResizeWeight(0.45)

        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(split_pane, BorderLayout.CENTER)

    def get_component(self):
        return self.panel

    def _on_toggle_recording(self, event):
        self.is_recording = not self.is_recording
        if self.is_recording:
            self.btn_record.setText("Stop Recording")
            log_info(self.callbacks, "Logic Breaker Flow Recording Started.")
        else:
            self.btn_record.setText("Start Recording")
            log_info(self.callbacks, "Logic Breaker Flow Recording Stopped.")

    def handle_proxy_request(self, message_info):
        """
        Called when a proxy request is processed. Captures in-scope non-static traffic.
        """
        if not self.is_recording:
            return

        http_service = message_info.getHttpService()
        req_bytes = message_info.getRequest()
        if not http_service or not req_bytes:
            return

        req_info = self.helpers.analyzeRequest(http_service, req_bytes)
        url = req_info.getUrl()
        if not url:
            return

        path = url.getPath()
        if LogicBreakerEngine.is_static_asset(path):
            return

        if self.chk_in_scope.isSelected() and not self.callbacks.isInScope(url):
            return

        method = req_info.getMethod()
        host = http_service.getHost()
        port = http_service.getPort()
        protocol = http_service.getProtocol()
        use_https = (protocol.lower() == "https")
        req_str = self.helpers.bytesToString(req_bytes)

        is_auth = any(term in path.lower() for term in ['login', 'auth', 'token', 'oauth'])

        step_dict = {
            'http_service': http_service,
            'request_bytes': req_bytes,
            'request_str': req_str,
            'method': method,
            'host': host,
            'port': port,
            'use_https': use_https,
            'path': path,
            'name': method + " " + path,
            'include': True,
            'is_auth_generator': is_auth
        }
        self.recorded_requests.append(step_dict)
        step_num = len(self.recorded_requests)

        def update_ui():
            self.seq_table_model.addRow([str(step_num), True, is_auth, method, host, path])
            self._update_status_label()

        SwingUtilities.invokeLater(update_ui)

    def add_request(self, http_service, request_bytes):
        """
        Called when a user sends a request to Logic Breaker via right-click context menu.
        """
        req_info = self.helpers.analyzeRequest(http_service, request_bytes)
        url = req_info.getUrl()
        method = req_info.getMethod()
        host = http_service.getHost()
        port = http_service.getPort()
        protocol = http_service.getProtocol()
        use_https = (protocol.lower() == "https")
        path = url.getPath() if url else "/"
        req_str = self.helpers.bytesToString(request_bytes)

        is_auth = any(term in path.lower() for term in ['login', 'auth', 'token', 'oauth'])

        step_dict = {
            'http_service': http_service,
            'request_bytes': request_bytes,
            'request_str': req_str,
            'method': method,
            'host': host,
            'port': port,
            'use_https': use_https,
            'path': path,
            'name': method + " " + path,
            'include': True,
            'is_auth_generator': is_auth
        }
        self.recorded_requests.append(step_dict)
        step_num = len(self.recorded_requests)

        def update_ui():
            self.seq_table_model.addRow([str(step_num), True, is_auth, method, host, path])
            self._update_status_label()

        SwingUtilities.invokeLater(update_ui)

    def _on_load_history(self, event):
        def load_thread():
            try:
                history = self.callbacks.getProxyHistory()
                if not history:
                    return

                count = 0
                for item in history:
                    http_service = item.getHttpService()
                    req_bytes = item.getRequest()
                    if not http_service or not req_bytes:
                        continue

                    req_info = self.helpers.analyzeRequest(http_service, req_bytes)
                    url = req_info.getUrl()
                    if not url:
                        continue

                    path = url.getPath()
                    if LogicBreakerEngine.is_static_asset(path):
                        continue

                    if self.chk_in_scope.isSelected() and not self.callbacks.isInScope(url):
                        continue

                    method = req_info.getMethod()
                    host = http_service.getHost()
                    port = http_service.getPort()
                    protocol = http_service.getProtocol()
                    use_https = (protocol.lower() == "https")
                    req_str = self.helpers.bytesToString(req_bytes)

                    is_auth = any(term in path.lower() for term in ['login', 'auth', 'token', 'oauth'])

                    step_dict = {
                        'http_service': http_service,
                        'request_bytes': req_bytes,
                        'request_str': req_str,
                        'method': method,
                        'host': host,
                        'port': port,
                        'use_https': use_https,
                        'path': path,
                        'name': method + " " + path,
                        'include': True,
                        'is_auth_generator': is_auth
                    }
                    self.recorded_requests.append(step_dict)
                    count += 1

                def refresh_ui():
                    self._refresh_table_from_recorded()
                    self._update_status_label()
                    JOptionPane.showMessageDialog(self.panel, "Loaded " + str(count) + " requests from Proxy History.")

                SwingUtilities.invokeLater(refresh_ui)

            except Exception as ex:
                log_error(self.callbacks, "Failed to load proxy history", ex)

        t = threading.Thread(target=load_thread)
        t.daemon = True
        t.start()

    def _on_remove_selected(self, event):
        selected_rows = self.seq_table.getSelectedRows()
        if not selected_rows:
            return

        rows_to_remove = sorted(list(selected_rows), reverse=True)
        for r in rows_to_remove:
            if 0 <= r < len(self.recorded_requests):
                del self.recorded_requests[r]

        self._refresh_table_from_recorded()
        self._update_status_label()

    def _on_clear_sequence(self, event):
        self.recorded_requests = []
        self.baseline_requests = []
        self.seq_table_model.setRowCount(0)
        self.results_table_model.setRowCount(0)
        self._update_status_label()

    def _on_set_baseline(self, event):
        for row_idx in range(self.seq_table_model.getRowCount()):
            inc_val = self.seq_table_model.getValueAt(row_idx, 1)
            auth_val = self.seq_table_model.getValueAt(row_idx, 2)
            if row_idx < len(self.recorded_requests):
                self.recorded_requests[row_idx]['include'] = bool(inc_val)
                self.recorded_requests[row_idx]['is_auth_generator'] = bool(auth_val)

        self.baseline_requests = [step for step in self.recorded_requests if step.get('include', True)]
        self._update_status_label()
        JOptionPane.showMessageDialog(self.panel, "Set " + str(len(self.baseline_requests)) + " requests as baseline sequence.")

    def _on_export_json(self, event):
        json_str = LogicBreakerEngine.export_sequence_to_json(self.recorded_requests)
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Logic Breaker Sequence JSON")
        ret = chooser.showSaveDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            try:
                writer = open(f.getAbsolutePath(), 'w')
                writer.write(json_str)
                writer.close()
                JOptionPane.showMessageDialog(self.panel, "Exported sequence successfully!")
            except Exception as ex:
                log_error(self.callbacks, "Export failed", ex)

    def _on_import_json(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Import Logic Breaker Sequence JSON")
        ret = chooser.showOpenDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            try:
                reader = open(f.getAbsolutePath(), 'r')
                content = reader.read()
                reader.close()
                imported = LogicBreakerEngine.import_sequence_from_json(content)
                if imported:
                    for step in imported:
                        service = self.helpers.buildHttpService(
                            step.get('host', ''),
                            step.get('port', 80),
                            step.get('use_https', False)
                        )
                        step['http_service'] = service
                        step['request_bytes'] = self.helpers.stringToBytes(step.get('request_str', ''))
                        self.recorded_requests.append(step)

                    self._refresh_table_from_recorded()
                    self._update_status_label()
                    JOptionPane.showMessageDialog(self.panel, "Imported " + str(len(imported)) + " steps.")
            except Exception as ex:
                log_error(self.callbacks, "Import failed", ex)

    def _get_auth_generator_step(self, sequence):
        for step in sequence:
            if step.get('is_auth_generator', False):
                return step
        return sequence[0] if sequence else None

    def _on_replay_baseline(self, event):
        sequence_to_run = self.baseline_requests if self.baseline_requests else [s for s in self.recorded_requests if s.get('include', True)]
        if not sequence_to_run:
            JOptionPane.showMessageDialog(self.panel, "No requests in baseline sequence to replay.")
            return

        def replay_thread():
            token_map = {}
            results_summary = []

            # Pre-flight thread-safe Auth Generator refresh
            if self.chk_auto_tokens.isSelected():
                auth_step = self._get_auth_generator_step(sequence_to_run)
                if auth_step:
                    with self.auth_lock:
                        try:
                            auth_resp = self.callbacks.makeHttpRequest(auth_step.get('http_service'), self.helpers.stringToBytes(auth_step.get('request_str', '')))
                            if auth_resp and auth_resp.getResponse():
                                auth_resp_str = self.helpers.bytesToString(auth_resp.getResponse())
                                token_map.update(LogicBreakerEngine.extract_dynamic_tokens(auth_resp_str))
                        except Exception as ex:
                            log_error(self.callbacks, "Auth Generator pre-flight refresh error", ex)

            for idx, step in enumerate(sequence_to_run):
                service = step.get('http_service')
                req_str = step.get('request_str', '')

                if self.chk_auto_tokens.isSelected() and token_map:
                    req_str = LogicBreakerEngine.substitute_tokens(req_str, token_map)

                req_b = self.helpers.stringToBytes(req_str)
                try:
                    resp = self.callbacks.makeHttpRequest(service, req_b)
                    if resp and resp.getResponse():
                        resp_str = self.helpers.bytesToString(resp.getResponse())
                        if self.chk_auto_tokens.isSelected():
                            extracted = LogicBreakerEngine.extract_dynamic_tokens(resp_str)
                            token_map.update(extracted)

                        resp_info = self.helpers.analyzeResponse(resp.getResponse())
                        results_summary.append("Step " + str(idx + 1) + ": " + str(resp_info.getStatusCode()))
                    else:
                        results_summary.append("Step " + str(idx + 1) + ": No Response")
                except Exception as ex:
                    results_summary.append("Step " + str(idx + 1) + " Error: " + str(ex))

            def show_res():
                JOptionPane.showMessageDialog(self.panel, "Baseline Replay Complete:\n" + "\n".join(results_summary))

            SwingUtilities.invokeLater(show_res)

        t = threading.Thread(target=replay_thread)
        t.daemon = True
        t.start()

    def _on_run_attack(self, event):
        sequence_to_run = self.baseline_requests if self.baseline_requests else [s for s in self.recorded_requests if s.get('include', True)]
        if not sequence_to_run:
            JOptionPane.showMessageDialog(self.panel, "Please capture or select requests for sequence first.")
            return

        if self.is_attacking:
            return

        self.is_attacking = True
        self.btn_attack.setEnabled(False)
        self.results_table_model.setRowCount(0)

        t = threading.Thread(target=self._execute_attack_thread, args=(sequence_to_run,))
        t.daemon = True
        t.start()

    def _execute_attack_thread(self, sequence_to_run):
        try:
            permutations = LogicBreakerEngine.generate_permutations(sequence_to_run)

            for perm in permutations:
                name = perm['name']
                desc = perm['description']
                seq = perm['sequence']
                steps_str = str(len(seq)) + " steps"

                final_status = "N/A"
                final_length = "N/A"
                token_map = {}

                # Pre-flight Auth Refresh for permutation sequence
                if self.chk_auto_tokens.isSelected():
                    auth_step = self._get_auth_generator_step(sequence_to_run)
                    if auth_step:
                        with self.auth_lock:
                            try:
                                auth_resp = self.callbacks.makeHttpRequest(auth_step.get('http_service'), self.helpers.stringToBytes(auth_step.get('request_str', '')))
                                if auth_resp and auth_resp.getResponse():
                                    auth_resp_str = self.helpers.bytesToString(auth_resp.getResponse())
                                    token_map.update(LogicBreakerEngine.extract_dynamic_tokens(auth_resp_str))
                            except Exception as ex:
                                log_error(self.callbacks, "Auth Generator attack pre-flight refresh error", ex)

                for step in seq:
                    service = step.get('http_service')
                    req_str = step.get('request_str', '')

                    if self.chk_auto_tokens.isSelected() and token_map:
                        req_str = LogicBreakerEngine.substitute_tokens(req_str, token_map)

                    req_b = self.helpers.stringToBytes(req_str)

                    try:
                        resp = self.callbacks.makeHttpRequest(service, req_b)
                        if resp and resp.getResponse():
                            resp_bytes = resp.getResponse()
                            resp_str = self.helpers.bytesToString(resp_bytes)

                            if self.chk_auto_tokens.isSelected():
                                extracted = LogicBreakerEngine.extract_dynamic_tokens(resp_str)
                                token_map.update(extracted)

                            resp_info = self.helpers.analyzeResponse(resp_bytes)
                            final_status = str(resp_info.getStatusCode())
                            final_length = str(len(resp_bytes))
                    except Exception as ex:
                        final_status = "Error: " + str(ex)

                def add_res_row(n=name, d=desc, st=steps_str, s=final_status, l=final_length):
                    self.results_table_model.addRow([n, d, st, s, l])

                SwingUtilities.invokeLater(add_res_row)

        finally:
            self.is_attacking = False
            def reenable():
                self.btn_attack.setEnabled(True)
            SwingUtilities.invokeLater(reenable)

    def _refresh_table_from_recorded(self):
        self.seq_table_model.setRowCount(0)
        for idx, step in enumerate(self.recorded_requests):
            inc = step.get('include', True)
            is_auth = step.get('is_auth_generator', False)
            method = step.get('method', 'GET')
            host = step.get('host', '')
            path = step.get('path', '/')
            self.seq_table_model.addRow([str(idx + 1), inc, is_auth, method, host, path])

    def _update_status_label(self):
        steps_cnt = len(self.recorded_requests)
        base_cnt = len(self.baseline_requests)
        self.lbl_status.setText("Sequence Steps: " + str(steps_cnt) + " (Baseline: " + str(base_cnt) + ")")
