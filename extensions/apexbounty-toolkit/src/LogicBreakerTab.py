# -*- coding: utf-8 -*-
"""
LogicBreakerTab.py - Tab 1: State-Aware Logic Breaker
Implements sequence builder, permutation generation, and attack execution.
"""

import threading
from java.awt import BorderLayout, FlowLayout, Dimension, GridBagLayout, GridBagConstraints, Insets
from javax.swing import (
    JPanel, JButton, JLabel, JTable, JScrollPane, JSplitPane,
    JSeparator, SwingUtilities, JOptionPane, ListSelectionModel,
    JTextField, JCheckBox, BoxLayout
)
from javax.swing.table import DefaultTableModel
from ApexToolkitLogic import LogicBreakerEngine, NoiseFilter, CorrelationEngine

class LogicBreakerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.recorded_requests = [] # list of dicts: {'http_service', 'request_bytes', 'method', 'host', 'path'}
        self.is_attacking = False

        self._init_ui()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Top Container Box
        top_container = JPanel()
        top_container.setLayout(BoxLayout(top_container, BoxLayout.Y_AXIS))

        # Row 1: Action Controls Panel
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        lbl_title = JLabel("State-Aware Logic Breaker")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0)) # Bold, 14pt

        self.btn_attack = JButton("Run Permutation Attack", actionPerformed=self._on_run_attack)
        self.btn_clear = JButton("Clear Sequence", actionPerformed=self._on_clear_sequence)
        self.lbl_status = JLabel("Sequence Count: 0")

        control_panel.add(lbl_title)
        control_panel.add(JSeparator(1)) # Vertical
        control_panel.add(self.btn_attack)
        control_panel.add(self.btn_clear)
        control_panel.add(self.lbl_status)

        # Row 2: Ingestion & History Polling Panel
        polling_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        lbl_start = JLabel("Start Req #:")
        self.txt_start_id = JTextField("1", 4)
        lbl_end = JLabel("End Req #:")
        self.txt_end_id = JTextField("100", 4)
        self.chk_in_scope = JCheckBox("In-Scope Only", True)

        lbl_noise = JLabel("Noise Filter Regex:")
        self.txt_noise_regex = JTextField(
            r"/api/metrics|/ping|/analytics|/telemetry|/health|\.(js|css|woff2?|ttf|svg|png|jpg|jpeg|gif|ico)",
            20
        )

        self.btn_fetch_history = JButton("Fetch Proxy History Range", actionPerformed=self._on_fetch_history)

        polling_panel.add(lbl_start)
        polling_panel.add(self.txt_start_id)
        polling_panel.add(lbl_end)
        polling_panel.add(self.txt_end_id)
        polling_panel.add(self.chk_in_scope)
        polling_panel.add(lbl_noise)
        polling_panel.add(self.txt_noise_regex)
        polling_panel.add(self.btn_fetch_history)

        top_container.add(control_panel)
        top_container.add(polling_panel)

        # Main Split: Top = Sequence Table, Bottom = Results Table
        self.seq_table_model = DefaultTableModel(["Step #", "Method", "Host", "Path"], 0)
        self.seq_table = JTable(self.seq_table_model)
        seq_scroll = JScrollPane(self.seq_table)
        seq_scroll.setBorder(None)

        seq_panel = JPanel(BorderLayout())
        seq_panel.setBorder(None)

        seq_header_panel = JPanel(BorderLayout())
        seq_label = JLabel("  Recorded Sequence Steps (Send from Proxy context menu or fetch history)")

        seq_btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 2))
        self.btn_move_up = JButton("Move Up", actionPerformed=self._on_move_up)
        self.btn_move_down = JButton("Move Down", actionPerformed=self._on_move_down)
        self.btn_duplicate = JButton("Duplicate Step", actionPerformed=self._on_duplicate)
        self.btn_delete = JButton("Delete Step", actionPerformed=self._on_delete)

        seq_btn_panel.add(self.btn_move_up)
        seq_btn_panel.add(self.btn_move_down)
        seq_btn_panel.add(self.btn_duplicate)
        seq_btn_panel.add(self.btn_delete)

        seq_header_panel.add(seq_label, BorderLayout.WEST)
        seq_header_panel.add(seq_btn_panel, BorderLayout.EAST)

        seq_panel.add(seq_header_panel, BorderLayout.NORTH)
        seq_panel.add(seq_scroll, BorderLayout.CENTER)

        # Results Table
        self.results_table_model = DefaultTableModel(["Permutation", "Description", "Steps Executed", "Final Status", "Final Length"], 0)
        self.results_table = JTable(self.results_table_model)
        res_scroll = JScrollPane(self.results_table)

        res_panel = JPanel(BorderLayout())
        res_label = JLabel("  Permutation Attack Results")
        res_panel.add(res_label, BorderLayout.NORTH)
        res_panel.add(res_scroll, BorderLayout.CENTER)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, seq_panel, res_panel)
        split_pane.setResizeWeight(0.4)

        self.panel.add(top_container, BorderLayout.NORTH)
        self.panel.add(split_pane, BorderLayout.CENTER)

    def get_component(self):
        return self.panel

    def add_request(self, http_service, request_bytes):
        """
        Called when a user sends a request to Logic Breaker via context menu.
        """
        req_info = self.helpers.analyzeRequest(http_service, request_bytes)
        url = req_info.getUrl()
        method = req_info.getMethod()
        host = http_service.getHost()
        path = url.getPath() if url else "/"

        step_dict = {
            'http_service': http_service,
            'request_bytes': request_bytes,
            'method': method,
            'host': host,
            'path': path,
            'name': method + " " + path
        }
        self.recorded_requests.append(step_dict)

        step_num = len(self.recorded_requests)

        def update_ui():
            self.seq_table_model.addRow([str(step_num), method, host, path])
            self.lbl_status.setText("Sequence Count: " + str(step_num))

        SwingUtilities.invokeLater(update_ui)

    def _on_fetch_history(self, event):
        if not self.callbacks:
            JOptionPane.showMessageDialog(self.panel, "Callbacks unavailable (Standalone / CLI mode).")
            return

        t = threading.Thread(target=self._fetch_history_thread)
        t.daemon = True
        t.start()

    def _fetch_history_thread(self):
        try:
            start_idx = int(self.txt_start_id.getText().strip()) if self.txt_start_id.getText().strip() else 1
            end_idx = int(self.txt_end_id.getText().strip()) if self.txt_end_id.getText().strip() else 999999
            in_scope_only = self.chk_in_scope.isSelected()
            noise_regex = self.txt_noise_regex.getText().strip()

            history = self.callbacks.getProxyHistory()
            if not history:
                def notify_empty():
                    JOptionPane.showMessageDialog(self.panel, "Proxy history is empty.")
                SwingUtilities.invokeLater(notify_empty)
                return

            added_count = 0

            for idx, item in enumerate(history):
                req_num = idx + 1
                if req_num < start_idx:
                    continue
                if req_num > end_idx:
                    break

                http_service = item.getHttpService()
                request_bytes = item.getRequest()
                response_bytes = item.getResponse()

                if not http_service or not request_bytes:
                    continue

                req_info = self.helpers.analyzeRequest(http_service, request_bytes)
                url = req_info.getUrl()
                url_str = url.toString() if url else ("http://" + http_service.getHost() + ":" + str(http_service.getPort()))

                if in_scope_only and url and not self.callbacks.isInScope(url):
                    continue

                mime_type = ""
                if response_bytes:
                    try:
                        resp_info = self.helpers.analyzeResponse(response_bytes)
                        mime_type = resp_info.getInferredMimeType()
                    except Exception:
                        pass

                path = url.getPath() if url else "/"
                if NoiseFilter.should_filter(url_str, mime_type=mime_type, custom_regex_pattern=noise_regex):
                    continue

                method = req_info.getMethod()
                host = http_service.getHost()

                step_dict = {
                    'http_service': http_service,
                    'request_bytes': request_bytes,
                    'method': method,
                    'host': host,
                    'path': path,
                    'name': method + " " + path,
                    'req_num': req_num
                }

                self.recorded_requests.append(step_dict)
                added_count += 1

            def update_ui_after_fetch(count=added_count):
                self._refresh_seq_table()
                JOptionPane.showMessageDialog(self.panel, "Ingested " + str(count) + " requests from Proxy History.")

            SwingUtilities.invokeLater(update_ui_after_fetch)

        except Exception as ex:
            def notify_err(e=ex):
                JOptionPane.showMessageDialog(self.panel, "Error fetching history: " + str(e))
            SwingUtilities.invokeLater(notify_err)

    def _refresh_seq_table(self):
        """Refreshes the sequence table rows from self.recorded_requests."""
        self.seq_table_model.setRowCount(0)
        for i, req in enumerate(self.recorded_requests):
            self.seq_table_model.addRow([str(i + 1), req['method'], req['host'], req['path']])
        self.lbl_status.setText("Sequence Count: " + str(len(self.recorded_requests)))

    def _on_move_up(self, event):
        row = self.seq_table.getSelectedRow()
        if row > 0 and row < len(self.recorded_requests):
            self.recorded_requests[row], self.recorded_requests[row - 1] = (
                self.recorded_requests[row - 1], self.recorded_requests[row]
            )
            self._refresh_seq_table()
            self.seq_table.setRowSelectionInterval(row - 1, row - 1)

    def _on_move_down(self, event):
        row = self.seq_table.getSelectedRow()
        if row >= 0 and row < len(self.recorded_requests) - 1:
            self.recorded_requests[row], self.recorded_requests[row + 1] = (
                self.recorded_requests[row + 1], self.recorded_requests[row]
            )
            self._refresh_seq_table()
            self.seq_table.setRowSelectionInterval(row + 1, row + 1)

    def _on_duplicate(self, event):
        row = self.seq_table.getSelectedRow()
        if row >= 0 and row < len(self.recorded_requests):
            dup_item = dict(self.recorded_requests[row])
            self.recorded_requests.insert(row + 1, dup_item)
            self._refresh_seq_table()
            self.seq_table.setRowSelectionInterval(row + 1, row + 1)

    def _on_delete(self, event):
        row = self.seq_table.getSelectedRow()
        if row >= 0 and row < len(self.recorded_requests):
            self.recorded_requests.pop(row)
            self._refresh_seq_table()
            new_row = min(row, len(self.recorded_requests) - 1)
            if new_row >= 0:
                self.seq_table.setRowSelectionInterval(new_row, new_row)

    def _on_clear_sequence(self, event):
        self.recorded_requests = []
        self.seq_table_model.setRowCount(0)
        self.results_table_model.setRowCount(0)
        self.lbl_status.setText("Sequence Count: 0")

    def _on_run_attack(self, event):
        if not self.recorded_requests:
            JOptionPane.showMessageDialog(self.panel, "Please send at least one request to the Logic Breaker sequence first.")
            return

        if self.is_attacking:
            return

        self.is_attacking = True
        self.btn_attack.setEnabled(False)
        self.results_table_model.setRowCount(0)

        # Run attack in background thread to avoid freezing Burp UI
        t = threading.Thread(target=self._execute_attack_thread)
        t.daemon = True
        t.start()

    def _execute_attack_thread(self):
        try:
            permutations = LogicBreakerEngine.generate_permutations(self.recorded_requests)

            for perm in permutations:
                name = perm['name']
                desc = perm['description']
                seq = perm['sequence']
                steps_str = str(len(seq)) + " steps"

                final_status = "N/A"
                final_length = "N/A"

                # Maintain per-permutation state token map
                token_map = {}

                # Execute sequence steps in order with state correlation
                for step in seq:
                    service = step['http_service']
                    req_b = step['request_bytes']

                    try:
                        if self.helpers:
                            req_str = self.helpers.bytesToString(req_b)
                        else:
                            req_str = str(req_b)

                        # Apply correlated state tokens from previous steps
                        if token_map:
                            req_str = CorrelationEngine.apply_tokens(req_str, token_map)

                        if self.helpers:
                            modified_req_b = self.helpers.stringToBytes(req_str)
                        else:
                            modified_req_b = req_str

                        resp = self.callbacks.makeHttpRequest(service, modified_req_b) if self.callbacks else None
                        if resp and resp.getResponse():
                            resp_bytes = resp.getResponse()
                            resp_info = self.helpers.analyzeResponse(resp_bytes)
                            final_status = str(resp_info.getStatusCode())
                            final_length = str(len(resp_bytes))

                            # Extract state tokens from response to pass to subsequent steps
                            body_offset = resp_info.getBodyOffset()
                            headers_list = resp_info.getHeaders()
                            headers_str = "\r\n".join(headers_list) if headers_list else ""

                            if self.helpers:
                                body_bytes = resp_bytes[body_offset:]
                                body_str = self.helpers.bytesToString(body_bytes)
                            else:
                                body_str = str(resp_bytes[body_offset:])

                            extracted_tokens = CorrelationEngine.extract_tokens(headers_str, body_str)
                            token_map.update(extracted_tokens)

                    except Exception as ex:
                        final_status = "Error: " + str(ex)

                def add_res_row(n=name, d=desc, st=steps_str, s=final_status, l=final_length):
                    self.results_table_model.addRow([n, d, st, s, l])

                SwingUtilities.invokeLater(add_res_row)

        finally:
            self.is_attacking = False
            def reenable_btn():
                self.btn_attack.setEnabled(True)
            SwingUtilities.invokeLater(reenable_btn)
