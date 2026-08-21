# -*- coding: utf-8 -*-
"""
LogicBreakerTab.py - Tab 1: State-Aware Logic Breaker
Implements sequence builder, permutation generation, non-destructive step management,
pre-flight warnings, token correlation replay, and per-step result logging.
"""

import threading
from java.awt import BorderLayout, FlowLayout, Dimension
from javax.swing import (
    JPanel, JButton, JLabel, JTable, JScrollPane, JSplitPane,
    JSeparator, SwingUtilities, JOptionPane, ListSelectionModel
)
from javax.swing.table import DefaultTableModel
from ApexToolkitLogic import LogicBreakerEngine, CorrelationEngine

class LogicBreakerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.recorded_requests = [] # list of dicts: {'http_service', 'request_bytes', 'method', 'host', 'path', 'included', 'name'}
        self.attack_results = [] # list of dicts with permutation details and step_logs
        self.is_attacking = False
        self.should_stop = False
        self.results_lock = threading.Lock()

        self._init_ui()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Top Control Panel
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        lbl_title = JLabel("State-Aware Logic Breaker")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0)) # Bold, 14pt

        self.btn_attack = JButton("Run Permutation Attack", actionPerformed=self._on_run_attack)
        self.btn_stop = JButton("Stop Attack", actionPerformed=self._on_stop_attack)
        self.btn_stop.setEnabled(False)
        self.btn_clear = JButton("Clear Sequence", actionPerformed=self._on_clear_sequence)

        self.btn_toggle_step = JButton("Toggle Include", actionPerformed=self._on_toggle_step)
        self.btn_move_up = JButton("Move Up", actionPerformed=self._on_move_up)
        self.btn_move_down = JButton("Move Down", actionPerformed=self._on_move_down)

        self.lbl_status = JLabel("Sequence Count: 0")

        control_panel.add(lbl_title)
        control_panel.add(JSeparator(1)) # Vertical
        control_panel.add(self.btn_attack)
        control_panel.add(self.btn_stop)
        control_panel.add(self.btn_clear)
        control_panel.add(JSeparator(1))
        control_panel.add(self.btn_toggle_step)
        control_panel.add(self.btn_move_up)
        control_panel.add(self.btn_move_down)
        control_panel.add(JSeparator(1))
        control_panel.add(self.lbl_status)

        # Main Split: Top = Sequence Table, Bottom = Results Table & Request/Response Inspector
        self.seq_table_model = DefaultTableModel(["Step #", "Included", "Method", "Host", "Path"], 0)
        self.seq_table = JTable(self.seq_table_model)
        seq_scroll = JScrollPane(self.seq_table)
        seq_scroll.setBorder(None)

        seq_panel = JPanel(BorderLayout())
        seq_panel.setBorder(None)
        seq_label = JLabel("  Recorded Sequence Steps (Send from Proxy / Repeater context menu)")
        seq_panel.add(seq_label, BorderLayout.NORTH)
        seq_panel.add(seq_scroll, BorderLayout.CENTER)

        # Results Table
        self.results_table_model = DefaultTableModel(
            ["Permutation", "Description", "Steps Executed", "Final Status", "Final Length", "Step Summary"], 0
        )
        self.results_table = JTable(self.results_table_model)
        self.results_table.getSelectionModel().addListSelectionListener(self._on_row_selected)
        res_scroll = JScrollPane(self.results_table)

        # Request / Response Message Viewers for inspecting selected permutation results
        self.req_editor = self.callbacks.createMessageEditor(None, False)
        self.resp_editor = self.callbacks.createMessageEditor(None, False)

        inspector_split = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            self.req_editor.getComponent(),
            self.resp_editor.getComponent()
        )
        inspector_split.setResizeWeight(0.5)

        res_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, res_scroll, inspector_split)
        res_split.setResizeWeight(0.5)

        res_panel = JPanel(BorderLayout())
        res_label = JLabel("  Permutation Attack Results")
        res_panel.add(res_label, BorderLayout.NORTH)
        res_panel.add(res_split, BorderLayout.CENTER)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, seq_panel, res_panel)
        split_pane.setResizeWeight(0.35)

        self.panel.add(control_panel, BorderLayout.NORTH)
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
            'name': method + " " + path,
            'included': True
        }
        self.recorded_requests.append(step_dict)

        step_num = len(self.recorded_requests)

        def update_ui():
            self.seq_table_model.addRow([str(step_num), "Yes", method, host, path])
            self.lbl_status.setText("Sequence Count: " + str(step_num))

        SwingUtilities.invokeLater(update_ui)

    def _refresh_seq_table_ui(self):
        self.seq_table_model.setRowCount(0)
        for idx, req in enumerate(self.recorded_requests):
            inc_str = "Yes" if req.get('included', True) else "No (Pruned)"
            self.seq_table_model.addRow([str(idx + 1), inc_str, req['method'], req['host'], req['path']])
        self.lbl_status.setText("Sequence Count: " + str(len(self.recorded_requests)))

    def _on_toggle_step(self, event):
        row = self.seq_table.getSelectedRow()
        if 0 <= row < len(self.recorded_requests):
            curr = self.recorded_requests[row].get('included', True)
            self.recorded_requests[row]['included'] = not curr
            self._refresh_seq_table_ui()

    def _on_move_up(self, event):
        row = self.seq_table.getSelectedRow()
        if row > 0 and row < len(self.recorded_requests):
            self.recorded_requests[row], self.recorded_requests[row - 1] = (
                self.recorded_requests[row - 1], self.recorded_requests[row]
            )
            self._refresh_seq_table_ui()
            self.seq_table.setRowSelectionInterval(row - 1, row - 1)

    def _on_move_down(self, event):
        row = self.seq_table.getSelectedRow()
        if 0 <= row < len(self.recorded_requests) - 1:
            self.recorded_requests[row], self.recorded_requests[row + 1] = (
                self.recorded_requests[row + 1], self.recorded_requests[row]
            )
            self._refresh_seq_table_ui()
            self.seq_table.setRowSelectionInterval(row + 1, row + 1)

    def _on_clear_sequence(self, event):
        self.recorded_requests = []
        with self.results_lock:
            self.attack_results = []
        self.seq_table_model.setRowCount(0)
        self.results_table_model.setRowCount(0)
        self.lbl_status.setText("Sequence Count: 0")

    def _on_stop_attack(self, event):
        if self.is_attacking:
            self.should_stop = True
            self.btn_stop.setEnabled(False)

    def _on_run_attack(self, event):
        if not self.recorded_requests:
            JOptionPane.showMessageDialog(self.panel, "Please send at least one request to the Logic Breaker sequence first.")
            return

        active_steps = [s for s in self.recorded_requests if s.get('included', True)]
        if not active_steps:
            JOptionPane.showMessageDialog(self.panel, "All sequence steps are currently pruned/excluded. Please enable at least one step.")
            return

        if self.is_attacking:
            return

        # Pre-flight Attack Calculation & Scope Gate Check
        permutations = LogicBreakerEngine.generate_permutations(self.recorded_requests)
        total_requests = sum(len(p['sequence']) for p in permutations)
        unique_hosts = list(set(s['host'] for s in active_steps))

        confirm_msg = (
            "Pre-Flight Attack Confirmation:\n\n"
            "• Active Permutations: " + str(len(permutations)) + "\n"
            "• Estimated Total Requests: " + str(total_requests) + "\n"
            "• Target Host(s): " + ", ".join(unique_hosts) + "\n\n"
            "Do you want to proceed with executing this permutation attack sequence?"
        )
        choice = JOptionPane.showConfirmDialog(self.panel, confirm_msg, "Confirm Attack Run", JOptionPane.YES_NO_OPTION)
        if choice != JOptionPane.YES_OPTION:
            return

        self.is_attacking = True
        self.should_stop = False
        self.btn_attack.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.results_table_model.setRowCount(0)
        with self.results_lock:
            self.attack_results = []

        # Run attack in background thread
        t = threading.Thread(target=self._execute_attack_thread, args=(permutations,))
        t.daemon = True
        t.start()

    def _execute_attack_thread(self, permutations):
        try:
            for perm in permutations:
                if self.should_stop:
                    break

                name = perm['name']
                desc = perm['description']
                seq = perm['sequence']
                steps_str = str(len(seq)) + " steps"

                step_logs = []
                step_summary_parts = []
                running_tokens = {}

                final_status = "N/A"
                final_length = "N/A"

                for idx, step in enumerate(seq):
                    if self.should_stop:
                        break

                    service = step['http_service']
                    req_b = step['request_bytes']
                    req_str = self.helpers.bytesToString(req_b)

                    # Dynamic Token Propagation across steps
                    updated_req_str = CorrelationEngine.apply_token_updates(req_str, running_tokens)
                    updated_req_b = self.helpers.stringToBytes(updated_req_str)

                    try:
                        resp = self.callbacks.makeHttpRequest(service, updated_req_b)
                        status = "Err"
                        length = "0"
                        resp_b = None

                        if resp and resp.getResponse():
                            resp_b = resp.getResponse()
                            resp_info = self.helpers.analyzeResponse(resp_b)
                            status = str(resp_info.getStatusCode())
                            length = str(len(resp_b))
                            resp_str = self.helpers.bytesToString(resp_b)

                            # Extract new tokens from response
                            new_tokens = CorrelationEngine.extract_tokens(resp_str)
                            running_tokens.update(new_tokens)

                        final_status = status
                        final_length = length

                        step_logs.append({
                            'step_name': step.get('name', 'Step ' + str(idx + 1)),
                            'status': status,
                            'length': length,
                            'req_bytes': updated_req_b,
                            'resp_bytes': resp_b
                        })
                        step_summary_parts.append("S" + str(idx + 1) + ": " + status)

                    except Exception as ex:
                        final_status = "Error: " + str(ex)
                        step_summary_parts.append("S" + str(idx + 1) + ": Error")

                step_summary = ", ".join(step_summary_parts)

                result_record = {
                    'name': name,
                    'description': desc,
                    'steps_count': steps_str,
                    'final_status': final_status,
                    'final_length': final_length,
                    'summary': step_summary,
                    'step_logs': step_logs
                }

                with self.results_lock:
                    self.attack_results.append(result_record)

                def add_res_row(n=name, d=desc, st=steps_str, s=final_status, l=final_length, sum_str=step_summary):
                    self.results_table_model.addRow([n, d, st, s, l, sum_str])

                SwingUtilities.invokeLater(add_res_row)

        finally:
            self.is_attacking = False
            self.should_stop = False
            def reenable_ui():
                self.btn_attack.setEnabled(True)
                self.btn_stop.setEnabled(False)
            SwingUtilities.invokeLater(reenable_ui)

    def _on_row_selected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.results_table.getSelectedRow()
        rec = None
        with self.results_lock:
            if 0 <= row < len(self.attack_results):
                rec = self.attack_results[row]

        if rec and rec['step_logs']:
            last_step = rec['step_logs'][-1]
            if last_step['req_bytes']:
                self.req_editor.setMessage(last_step['req_bytes'], False)
            if last_step['resp_bytes']:
                self.resp_editor.setMessage(last_step['resp_bytes'], False)
            else:
                self.resp_editor.setMessage(self.helpers.stringToBytes("No Response Recorded"), False)
