# -*- coding: utf-8 -*-
"""
RaceOrchestratorTab.py - Tab 3: Multi-Endpoint Race Orchestrator
Coordinates multi-threaded synchronized race conditions across distinct endpoints
using CountDownLatch, anomaly detection, and CSV result export.
"""

import threading
import time
from java.awt import BorderLayout, FlowLayout, Color, Component
from java.util.concurrent import CountDownLatch
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JTable, JScrollPane, JSplitPane,
    JSeparator, SwingUtilities, JOptionPane, JFileChooser
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer

from ApexToolkitLogic import RaceOrchestratorEngine, log_info, log_error


class AnomalyCellRenderer(DefaultTableCellRenderer):
    """
    Custom cell renderer to highlight 500 status codes and anomalous responses in red/yellow.
    """
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        status_val = str(table.getModel().getValueAt(row, 2))  # Status column
        flag_val = str(table.getModel().getValueAt(row, 4))    # Anomaly Flag column

        if not isSelected:
            if "500" in status_val or "Server Error" in flag_val:
                cell.setBackground(Color(255, 210, 210))  # Soft Red
                cell.setForeground(Color.BLACK)
            elif "Yes" in flag_val or "Deviating" in flag_val:
                cell.setBackground(Color(255, 255, 200))  # Soft Yellow
                cell.setForeground(Color.BLACK)
            else:
                cell.setBackground(Color.WHITE)
                cell.setForeground(Color.BLACK)
        return cell


class RaceOrchestratorTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers

        self.service_a = None
        self.bytes_a = None
        self.service_b = None
        self.bytes_b = None

        self.race_results = []  # stores (target_label, thread_id, status, length, flag_str, note, resp_obj)

        self._init_ui()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Top Controls Bar
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))

        lbl_title = JLabel("Multi-Endpoint Race Orchestrator")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0))

        control_panel.add(lbl_title)
        control_panel.add(JSeparator(1))

        control_panel.add(JLabel("Threads per Endpoint:"))
        self.txt_threads = JTextField("10", 5)
        control_panel.add(self.txt_threads)

        control_panel.add(JLabel("Delay (ms):"))
        self.txt_delay = JTextField("0", 5)
        control_panel.add(self.txt_delay)

        self.btn_run_race = JButton("Run Race Attack", actionPerformed=self._on_run_race)
        control_panel.add(self.btn_run_race)

        self.btn_export_csv = JButton("Export CSV", actionPerformed=self._on_export_csv)
        control_panel.add(self.btn_export_csv)

        # Requests View: Split Pane containing Request A editor and Request B editor
        self.editor_a = self.callbacks.createMessageEditor(None, True)
        self.editor_b = self.callbacks.createMessageEditor(None, True)

        panel_a = JPanel(BorderLayout())
        panel_a.add(JLabel(" Target Request A (Send via context menu)"), BorderLayout.NORTH)
        panel_a.add(self.editor_a.getComponent(), BorderLayout.CENTER)

        panel_b = JPanel(BorderLayout())
        panel_b.add(JLabel(" Target Request B (Send via context menu)"), BorderLayout.NORTH)
        panel_b.add(self.editor_b.getComponent(), BorderLayout.CENTER)

        req_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panel_a, panel_b)
        req_split.setResizeWeight(0.5)

        # Bottom Results Section: Table + Response Viewer
        self.results_table_model = DefaultTableModel(
            ["Target", "Thread ID", "Status", "Content Length", "Anomaly Flag", "Note"], 0
        )
        self.results_table = JTable(self.results_table_model)
        renderer = AnomalyCellRenderer()
        for col_idx in range(6):
            self.results_table.getColumnModel().getColumn(col_idx).setCellRenderer(renderer)

        self.results_table.getSelectionModel().addListSelectionListener(self._on_row_selected)
        res_scroll = JScrollPane(self.results_table)

        self.resp_editor = self.callbacks.createMessageEditor(None, False)

        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, res_scroll, self.resp_editor.getComponent())
        bottom_split.setResizeWeight(0.6)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, req_split, bottom_split)
        main_split.setResizeWeight(0.4)

        self.panel.add(control_panel, BorderLayout.NORTH)
        self.panel.add(main_split, BorderLayout.CENTER)

    def get_component(self):
        return self.panel

    def set_request_a(self, http_service, request_bytes):
        self.service_a = http_service
        self.bytes_a = request_bytes
        self.editor_a.setMessage(request_bytes, True)

    def set_request_b(self, http_service, request_bytes):
        self.service_b = http_service
        self.bytes_b = request_bytes
        self.editor_b.setMessage(request_bytes, True)

    def _on_export_csv(self, event):
        if not self.race_results:
            JOptionPane.showMessageDialog(self.panel, "No race attack results to export.")
            return

        csv_content = RaceOrchestratorEngine.export_race_results_csv(self.race_results)
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Race Results to CSV")
        ret = chooser.showSaveDialog(self.panel)
        if ret == JFileChooser.APPROVE_OPTION:
            f = chooser.getSelectedFile()
            try:
                writer = open(f.getAbsolutePath(), 'w')
                writer.write(csv_content)
                writer.close()
                JOptionPane.showMessageDialog(self.panel, "Race results exported successfully!")
            except Exception as ex:
                log_error(self.callbacks, "Export CSV failed", ex)

    def _on_run_race(self, event):
        req_a_bytes = self.editor_a.getMessage()
        req_b_bytes = self.editor_b.getMessage()

        if not req_a_bytes or not self.service_a:
            JOptionPane.showMessageDialog(self.panel, "Request A is not set. Please set Request A first.")
            return

        if not req_b_bytes or not self.service_b:
            self.service_b = self.service_a
            req_b_bytes = req_a_bytes
            self.editor_b.setMessage(req_b_bytes, True)

        try:
            threads_per_endpoint = int(self.txt_threads.getText().strip())
            delay_ms = int(self.txt_delay.getText().strip())
        except ValueError:
            JOptionPane.showMessageDialog(self.panel, "Threads and Delay must be valid integers.")
            return

        self.btn_run_race.setEnabled(False)
        self.results_table_model.setRowCount(0)
        self.race_results = []

        t = threading.Thread(
            target=self._race_orchestrator_thread,
            args=(req_a_bytes, req_b_bytes, threads_per_endpoint, delay_ms)
        )
        t.daemon = True
        t.start()

    def _race_orchestrator_thread(self, req_a_bytes, req_b_bytes, threads_per_endpoint, delay_ms):
        try:
            total_threads = threads_per_endpoint * 2
            start_latch = CountDownLatch(1)
            done_latch = CountDownLatch(total_threads)

            lock = threading.Lock()

            def worker_task(target_name, service, req_bytes, thread_id):
                start_latch.await()
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)

                try:
                    resp = self.callbacks.makeHttpRequest(service, req_bytes)
                    status = 0
                    length = 0

                    if resp and resp.getResponse():
                        resp_info = self.helpers.analyzeResponse(resp.getResponse())
                        status = resp_info.getStatusCode()
                        length = len(resp.getResponse())

                    is_anomaly, note = RaceOrchestratorEngine.classify_race_response(status, length)
                    flag_str = "Yes" if is_anomaly else "No"

                    with lock:
                        self.race_results.append((target_name, str(thread_id), str(status), str(length), flag_str, note, resp))

                    def add_row(t_name=target_name, tid=str(thread_id), st=str(status), l=str(length), flg=flag_str, nt=note):
                        self.results_table_model.addRow([t_name, tid, st, l, flg, nt])

                    SwingUtilities.invokeLater(add_row)
                except Exception as ex:
                    log_error(self.callbacks, "Race worker execution error for thread " + str(thread_id), ex)
                finally:
                    done_latch.countDown()

            threads = []
            for i in range(threads_per_endpoint):
                t1 = threading.Thread(target=worker_task, args=("Request A", self.service_a, req_a_bytes, "A-" + str(i + 1)))
                t2 = threading.Thread(target=worker_task, args=("Request B", self.service_b, req_b_bytes, "B-" + str(i + 1)))
                t1.daemon = True
                t2.daemon = True
                threads.append(t1)
                threads.append(t2)
                t1.start()
                t2.start()

            start_latch.countDown()
            done_latch.await()

        except Exception as ex:
            log_error(self.callbacks, "Race Orchestrator thread error", ex)
        finally:
            def reenable():
                self.btn_run_race.setEnabled(True)
            SwingUtilities.invokeLater(reenable)

    def _on_row_selected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.results_table.getSelectedRow()
        if 0 <= row < len(self.race_results):
            resp_obj = self.race_results[row][6]
            if resp_obj and resp_obj.getResponse():
                self.resp_editor.setMessage(resp_obj.getResponse(), False)
