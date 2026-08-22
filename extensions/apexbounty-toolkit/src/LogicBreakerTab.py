# -*- coding: utf-8 -*-
"""
LogicBreakerTab.py - Tab 1: State-Aware Logic Breaker
Implements flow capture session controls, sequence builder, pruning/restoration,
and baseline permutation attack execution.
"""

import threading
from java.awt import BorderLayout, FlowLayout
from javax.swing import (
    JPanel, JButton, JLabel, JTable, JScrollPane, JSplitPane,
    JSeparator, SwingUtilities, JOptionPane, JCheckBox
)
from javax.swing.table import DefaultTableModel
from ApexToolkitLogic import LogicBreakerEngine, FlowCaptureManager, NoiseScorer


class LogicBreakerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.capture_manager = FlowCaptureManager()
        self.is_attacking = False
        self.hide_noise = False

        self._init_ui()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Top Control Panel
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))

        lbl_title = JLabel("Logic Breaker (Flow Capture Mode)")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0))  # Bold, 14pt

        self.btn_start_capture = JButton("Start Capture", actionPerformed=self._on_start_capture)
        self.btn_pause_capture = JButton("Pause", actionPerformed=self._on_pause_capture)
        self.btn_stop_capture = JButton("Stop / Build Baseline", actionPerformed=self._on_stop_capture)

        self.btn_prune = JButton("Prune Step", actionPerformed=self._on_prune_step)
        self.btn_restore = JButton("Restore Step", actionPerformed=self._on_restore_step)
        self.btn_clear = JButton("Clear Flow", actionPerformed=self._on_clear_sequence)
        self.btn_attack = JButton("Run Permutation Attack", actionPerformed=self._on_run_attack)

        self.chk_hide_noise = JCheckBox("Hide Noise", actionPerformed=self._on_toggle_hide_noise)
        self.lbl_status = JLabel("Status: IDLE | Steps: 0")

        self.btn_pause_capture.setEnabled(False)
        self.btn_stop_capture.setEnabled(False)

        control_panel.add(lbl_title)
        control_panel.add(JSeparator(1))  # Vertical separator
        control_panel.add(self.btn_start_capture)
        control_panel.add(self.btn_pause_capture)
        control_panel.add(self.btn_stop_capture)
        control_panel.add(JSeparator(1))
        control_panel.add(self.btn_prune)
        control_panel.add(self.btn_restore)
        control_panel.add(self.btn_clear)
        control_panel.add(self.chk_hide_noise)
        control_panel.add(JSeparator(1))
        control_panel.add(self.btn_attack)
        control_panel.add(self.lbl_status)

        # Sequence Table
        self.seq_table_model = DefaultTableModel(["Step #", "Method", "Host", "Path", "Type", "Noise Score", "Status"], 0)
        self.seq_table = JTable(self.seq_table_model)
        seq_scroll = JScrollPane(self.seq_table)

        seq_panel = JPanel(BorderLayout())
        seq_label = JLabel("  Recorded Sequence Steps (Live Proxy Capture / Context Menu)")
        seq_panel.add(seq_label, BorderLayout.NORTH)
        seq_panel.add(seq_scroll, BorderLayout.CENTER)

        # Summary & Results Panel
        self.lbl_summary = JLabel("  Flow Summary: No active session")

        self.results_table_model = DefaultTableModel(["Permutation", "Description", "Steps Executed", "Final Status", "Final Length"], 0)
        self.results_table = JTable(self.results_table_model)
        res_scroll = JScrollPane(self.results_table)

        res_panel = JPanel(BorderLayout())
        res_panel.add(self.lbl_summary, BorderLayout.NORTH)
        res_panel.add(res_scroll, BorderLayout.CENTER)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, seq_panel, res_panel)
        split_pane.setResizeWeight(0.45)

        self.panel.add(control_panel, BorderLayout.NORTH)
        self.panel.add(split_pane, BorderLayout.CENTER)

    def get_component(self):
        return self.panel

    def start_flow_with_anchor(self, http_service, request_bytes):
        """
        Called when user selects "Start Flow Capture from this request" context menu action.
        """
        host = http_service.getHost()
        self.capture_manager.start_capture(
            anchor_request={'service': http_service, 'raw': request_bytes},
            name="Flow Session (" + str(host) + ")",
            scope_hosts=[host]
        )
        self.btn_start_capture.setEnabled(False)
        self.btn_pause_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(True)

        self.add_request(http_service, request_bytes, source="anchor")
        self._refresh_ui()

    def handle_proxy_message(self, messageInfo):
        """
        Ingests proxy traffic when flow capture is active.
        """
        if not self.capture_manager.active_session or self.capture_manager.active_session.status != 'CAPTURING':
            return

        http_service = messageInfo.getHttpService()
        req_bytes = messageInfo.getRequest()
        resp_bytes = messageInfo.getResponse()

        req_info = self.helpers.analyzeRequest(http_service, req_bytes)
        url = req_info.getUrl()
        method = req_info.getMethod()
        host = http_service.getHost()
        path = url.getPath() if url else "/"

        status_code = 200
        mime_type = ""
        resp_body = ""

        if resp_bytes:
            resp_info = self.helpers.analyzeResponse(resp_bytes)
            status_code = resp_info.getStatusCode()
            mime_type = resp_info.getInferredMimeType() or ""
            resp_body_offset = resp_info.getBodyOffset()
            resp_body = self.helpers.bytesToString(resp_bytes[resp_body_offset:])

        step = self.capture_manager.ingest_candidate(
            method=method,
            host=host,
            path=path,
            headers=str(req_info.getHeaders()),
            body=self.helpers.bytesToString(req_bytes[req_info.getBodyOffset():]),
            http_service=http_service,
            request_bytes=req_bytes,
            response_bytes=resp_bytes,
            status_code=status_code,
            response_body=resp_body,
            source="proxy",
            mime_type=mime_type
        )

        if step:
            SwingUtilities.invokeLater(self._refresh_ui)

    def add_request(self, http_service, request_bytes, source="manual"):
        """
        Appends manual request step to current flow session. Ensures session is capturing.
        """
        req_info = self.helpers.analyzeRequest(http_service, request_bytes)
        url = req_info.getUrl()
        method = req_info.getMethod()
        host = http_service.getHost()
        path = url.getPath() if url else "/"

        if not self.capture_manager.active_session:
            self.capture_manager.start_capture(name="Flow Session (" + str(host) + ")", scope_hosts=[host])
            self.btn_start_capture.setEnabled(False)
            self.btn_pause_capture.setEnabled(True)
            self.btn_stop_capture.setEnabled(True)
        elif self.capture_manager.active_session.status in ('PAUSED', 'BASELINE_READY'):
            self.capture_manager.active_session.status = 'CAPTURING'
            self.btn_start_capture.setEnabled(False)
            self.btn_pause_capture.setEnabled(True)
            self.btn_stop_capture.setEnabled(True)

        self.capture_manager.ingest_candidate(
            method=method,
            host=host,
            path=path,
            headers=str(req_info.getHeaders()),
            body=self.helpers.bytesToString(request_bytes[req_info.getBodyOffset():]),
            http_service=http_service,
            request_bytes=request_bytes,
            source=source
        )

        SwingUtilities.invokeLater(self._refresh_ui)

    def _on_start_capture(self, event):
        self.capture_manager.start_capture()
        self.btn_start_capture.setEnabled(False)
        self.btn_pause_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(True)
        self._refresh_ui()

    def _on_pause_capture(self, event):
        if self.capture_manager.active_session:
            if self.capture_manager.active_session.status == 'CAPTURING':
                self.capture_manager.pause_capture()
                self.btn_pause_capture.setText("Resume")
            elif self.capture_manager.active_session.status == 'PAUSED':
                self.capture_manager.resume_capture()
                self.btn_pause_capture.setText("Pause")
        self._refresh_ui()

    def _on_stop_capture(self, event):
        self.capture_manager.stop_capture()
        self.btn_start_capture.setEnabled(True)
        self.btn_pause_capture.setEnabled(False)
        self.btn_pause_capture.setText("Pause")
        self.btn_stop_capture.setEnabled(False)
        self._refresh_ui()

    def _on_prune_step(self, event):
        row = self.seq_table.getSelectedRow()
        session = self.capture_manager.active_session
        if session and row >= 0:
            visible_steps = session.get_active_steps(include_pruned=not self.hide_noise)
            if row < len(visible_steps):
                step = visible_steps[row]
                session.prune_step(step.step_id)
                self._refresh_ui()

    def _on_restore_step(self, event):
        row = self.seq_table.getSelectedRow()
        session = self.capture_manager.active_session
        if session and row >= 0:
            visible_steps = session.get_active_steps(include_pruned=not self.hide_noise)
            if row < len(visible_steps):
                step = visible_steps[row]
                session.restore_step(step.step_id)
                self._refresh_ui()

    def _on_clear_sequence(self, event):
        self.capture_manager.active_session = None
        self.btn_start_capture.setEnabled(True)
        self.btn_pause_capture.setEnabled(False)
        self.btn_pause_capture.setText("Pause")
        self.btn_stop_capture.setEnabled(False)
        self._refresh_ui()
        self.results_table_model.setRowCount(0)

    def _on_toggle_hide_noise(self, event):
        self.hide_noise = self.chk_hide_noise.isSelected()
        self._refresh_ui()

    def _refresh_ui(self):
        session = self.capture_manager.active_session
        self.seq_table_model.setRowCount(0)

        if not session:
            self.lbl_status.setText("Status: IDLE | Steps: 0")
            self.lbl_summary.setText("  Flow Summary: No active session")
            return

        steps = session.get_active_steps(include_pruned=not self.hide_noise)
        for idx, s in enumerate(steps):
            status_text = "PRUNED" if s.is_pruned else "ACTIVE"
            self.seq_table_model.addRow([
                str(s.sequence_index),
                s.method,
                s.host,
                s.path,
                s.classification,
                str(s.noise_score),
                status_text
            ])

        summary = session.get_summary()
        status_msg = "Status: " + str(summary['status']) + " | Steps: " + str(summary['total_steps'])
        self.lbl_status.setText(status_msg)

        summary_msg = (
            "  Flow Summary: " + str(summary['name']) + " | Active Steps: " + str(summary['active_steps']) +
            " | Relevant: " + str(summary['relevant_count']) + " | Noise: " + str(summary['noise_count']) +
            " | Pruned: " + str(summary['pruned_steps'])
        )
        self.lbl_summary.setText(summary_msg)

    def _on_run_attack(self, event):
        session = self.capture_manager.active_session
        if not session or not session.get_active_steps():
            JOptionPane.showMessageDialog(self.panel, "Please capture or add at least one step to the flow session first.")
            return

        if self.is_attacking:
            return

        self.is_attacking = True
        self.btn_attack.setEnabled(False)
        self.results_table_model.setRowCount(0)

        t = threading.Thread(target=self._execute_attack_thread)
        t.daemon = True
        t.start()

    def _execute_attack_thread(self):
        try:
            session = self.capture_manager.active_session
            active_steps = session.get_active_steps(include_pruned=False)

            # Map steps to engine format
            step_dicts = []
            for s in active_steps:
                step_dicts.append({
                    'name': s.method + " " + s.path,
                    'http_service': s.http_service,
                    'request_bytes': s.request_bytes,
                    'step_id': s.step_id
                })

            permutations = LogicBreakerEngine.generate_permutations(step_dicts)

            for perm in permutations:
                name = perm['name']
                desc = perm['description']
                seq = perm['sequence']
                steps_str = str(len(seq)) + " steps"

                final_status = "N/A"
                final_length = "N/A"

                for step in seq:
                    service = step.get('http_service')
                    req_b = step.get('request_bytes')

                    if service and req_b:
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
            def reenable_btn():
                self.btn_attack.setEnabled(True)
            SwingUtilities.invokeLater(reenable_btn)
