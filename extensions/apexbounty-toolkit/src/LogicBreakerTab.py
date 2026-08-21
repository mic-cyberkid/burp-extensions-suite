# -*- coding: utf-8 -*-
"""
LogicBreakerTab.py - Tab 1: State-Aware Logic Breaker
Implements sequence builder, permutation generation, and attack execution.
"""

import threading
from java.awt import BorderLayout, FlowLayout, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.util.concurrent import CopyOnWriteArrayList
from javax.swing import (
    JPanel, JButton, JLabel, JTable, JScrollPane, JSplitPane,
    JSeparator, SwingUtilities, JOptionPane, ListSelectionModel
)
from javax.swing.table import DefaultTableModel
from ApexToolkitLogic import LogicBreakerEngine

class LogicBreakerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.recorded_requests = CopyOnWriteArrayList() # Thread-safe storage for sequence steps
        self.is_attacking = False

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
        self.lbl_status = JLabel("Sequence Count: 0")

        control_panel.add(lbl_title)
        control_panel.add(JSeparator(1)) # Vertical
        control_panel.add(self.btn_attack)
        control_panel.add(self.btn_stop)
        control_panel.add(self.btn_clear)
        control_panel.add(self.lbl_status)

        # Main Split: Top = Sequence Table, Bottom = Results Table
        self.seq_table_model = DefaultTableModel(["Step #", "Method", "Host", "Path"], 0)
        self.seq_table = JTable(self.seq_table_model)
        seq_scroll = JScrollPane(self.seq_table)
        seq_scroll.setBorder(None)

        seq_panel = JPanel(BorderLayout())
        seq_panel.setBorder(None)
        seq_label = JLabel("  Recorded Sequence Steps (Send from Proxy / Repeater context menu)")
        seq_panel.add(seq_label, BorderLayout.NORTH)
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
            'name': method + " " + path
        }
        self.recorded_requests.add(step_dict)

        step_num = len(self.recorded_requests)

        def update_ui():
            self.seq_table_model.addRow([str(step_num), method, host, path])
            self.lbl_status.setText("Sequence Count: " + str(step_num))

        SwingUtilities.invokeLater(update_ui)

    def _on_clear_sequence(self, event):
        self.recorded_requests = CopyOnWriteArrayList()
        self.seq_table_model.setRowCount(0)
        self.results_table_model.setRowCount(0)
        self.lbl_status.setText("Sequence Count: 0")

    def _on_stop_attack(self, event):
        self.is_attacking = False
        self.btn_stop.setEnabled(False)

    def _on_run_attack(self, event):
        if not self.recorded_requests:
            JOptionPane.showMessageDialog(self.panel, "Please send at least one request to the Logic Breaker sequence first.")
            return

        if self.is_attacking:
            return

        # Pre-flight scope safety check across all recorded steps
        out_of_scope_urls = []
        for req in self.recorded_requests:
            req_info = self.helpers.analyzeRequest(req['http_service'], req['request_bytes'])
            url = req_info.getUrl()
            if url and not self.callbacks.isInScope(url):
                out_of_scope_urls.append(str(url))

        if out_of_scope_urls:
            confirm = JOptionPane.showConfirmDialog(
                self.panel,
                "Warning: " + str(len(out_of_scope_urls)) + " target request(s) are OUT OF SCOPE.\nDo you want to proceed anyway?",
                "Scope Safety Warning",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )
            if confirm != JOptionPane.YES_OPTION:
                return

        self.is_attacking = True
        self.btn_attack.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.results_table_model.setRowCount(0)

        # Run attack in background thread to avoid freezing Burp UI
        t = threading.Thread(target=self._execute_attack_thread)
        t.daemon = True
        t.start()

    def _execute_attack_thread(self):
        try:
            permutations = LogicBreakerEngine.generate_permutations(list(self.recorded_requests))

            for perm in permutations:
                if not self.is_attacking:
                    break

                name = perm['name']
                desc = perm['description']
                seq = perm['sequence']
                steps_str = str(len(seq)) + " steps"

                final_status = "N/A"
                final_length = "N/A"

                # Execute sequence steps in order
                for step in seq:
                    if not self.is_attacking:
                        break

                    service = step['http_service']
                    req_b = step['request_bytes']

                    try:
                        resp = self.callbacks.makeHttpRequest(service, req_b)
                        if resp and resp.getResponse():
                            resp_info = self.helpers.analyzeResponse(resp.getResponse())
                            final_status = str(resp_info.getStatusCode())
                            final_length = str(len(resp.getResponse()))
                    except Exception as ex:
                        final_status = "Error: " + str(ex)

                def add_res_row(n=name, d=desc, st=steps_str, s=final_status, l=final_length):
                    self.results_table_model.addRow([n, d, st, s, l])

                SwingUtilities.invokeLater(add_res_row)

        finally:
            self.is_attacking = False
            def reenable_ui():
                self.btn_attack.setEnabled(True)
                self.btn_stop.setEnabled(False)
            SwingUtilities.invokeLater(reenable_ui)
