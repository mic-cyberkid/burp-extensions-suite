# -*- coding: utf-8 -*-
"""
PrivilegeMatrixTab.py - Tab 4: Dynamic Privilege Matrix
Automated BOLA/IDOR detection via background session replays across 4 configured roles
with configuration persistence, replay throttling delay, and memory capping.
"""

import threading
import time
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Component, Dimension
from javax.swing import (
    JPanel, JButton, JLabel, JCheckBox, JTextArea, JScrollPane, JTable, JSplitPane,
    JSeparator, SwingUtilities, BorderFactory, JTabbedPane, JTextField, JOptionPane
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer

from ApexToolkitLogic import (
    PrivilegeMatrixEngine, log_info, log_error, save_setting, load_setting
)


class StatusColorCellRenderer(DefaultTableCellRenderer):
    """
    Renders role status columns with color codes:
    Green for 200 OK, Red for 401/403, Yellow for Redirects, Orange for 500s.
    """
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)

        val_str = str(value) if value is not None else ""
        if not isSelected and column >= 2:
            if "200" in val_str or "201" in val_str or "204" in val_str:
                cell.setBackground(Color(200, 245, 200))  # Soft Green
                cell.setForeground(Color.BLACK)
            elif "401" in val_str or "403" in val_str:
                cell.setBackground(Color(255, 210, 210))  # Soft Red
                cell.setForeground(Color.BLACK)
            elif "301" in val_str or "302" in val_str:
                cell.setBackground(Color(255, 255, 200))  # Soft Yellow
                cell.setForeground(Color.BLACK)
            elif "500" in val_str or "502" in val_str:
                cell.setBackground(Color(255, 220, 180))  # Soft Orange
                cell.setForeground(Color.BLACK)
            else:
                cell.setBackground(Color.WHITE)
                cell.setForeground(Color.BLACK)

        return cell


class PrivilegeMatrixTab(object):
    MAX_RECORD_CAP = 500  # Cap maximum stored matrix records to prevent OOM

    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.is_enabled = False

        self.matrix_records = []  # stores dicts with request/response info for each role

        self._init_ui()
        self._load_saved_settings()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        top_container = JPanel(BorderLayout())

        control_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))
        lbl_title = JLabel("Dynamic Privilege Matrix (BOLA / IDOR)")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0))

        self.chk_enable = JCheckBox("Enable Background Matrix Replay", False, actionPerformed=self._on_toggle_enabled)
        self.btn_clear = JButton("Clear Matrix Log", actionPerformed=self._on_clear_log)
        self.btn_save_config = JButton("Save Role Config", actionPerformed=self._on_save_config)

        control_panel.add(lbl_title)
        control_panel.add(JSeparator(1))
        control_panel.add(self.chk_enable)
        control_panel.add(self.btn_clear)
        control_panel.add(self.btn_save_config)

        control_panel.add(JLabel("Replay Delay (ms):"))
        self.txt_delay = JTextField("50", 4)
        control_panel.add(self.txt_delay)

        # Role Header Configuration Grid (4 roles: Admin, User A, User B, Unauth)
        grid_panel = JPanel(GridLayout(1, 4, 5, 5))
        grid_panel.setBorder(BorderFactory.createTitledBorder(" Role Auth Headers Configuration "))

        self.txt_admin = JTextArea("Authorization: Bearer ADMIN_TOKEN_HERE\nCookie: session=admin_sess", 3, 20)
        self.txt_usera = JTextArea("Authorization: Bearer USER_A_TOKEN_HERE\nCookie: session=user_a_sess", 3, 20)
        self.txt_userb = JTextArea("Authorization: Bearer USER_B_TOKEN_HERE\nCookie: session=user_b_sess", 3, 20)
        self.txt_unauth = JTextArea("# Unauth: Strips all auth headers", 3, 20)

        grid_panel.add(self._create_role_box("Role 1: Admin", self.txt_admin))
        grid_panel.add(self._create_role_box("Role 2: User A", self.txt_usera))
        grid_panel.add(self._create_role_box("Role 3: User B", self.txt_userb))
        grid_panel.add(self._create_role_box("Role 4: Unauth", self.txt_unauth))

        top_container.add(control_panel, BorderLayout.NORTH)
        top_container.add(grid_panel, BorderLayout.SOUTH)

        # Matrix Results Table
        self.matrix_table_model = DefaultTableModel(
            ["Method", "Path / Endpoint", "Admin Status", "User A Status", "User B Status", "Unauth Status"], 0
        )
        self.matrix_table = JTable(self.matrix_table_model)
        renderer = StatusColorCellRenderer()
        for c in range(6):
            self.matrix_table.getColumnModel().getColumn(c).setCellRenderer(renderer)

        self.matrix_table.getSelectionModel().addListSelectionListener(self._on_row_selected)
        table_scroll = JScrollPane(self.matrix_table)

        # Detail Viewers for role responses
        self.role_viewers = {}
        self.detail_tabbed_pane = JTabbedPane()

        roles = ["Admin", "User A", "User B", "Unauth"]
        for role in roles:
            editor = self.callbacks.createMessageEditor(None, False)
            self.role_viewers[role] = editor
            self.detail_tabbed_pane.addTab(role + " Response", editor.getComponent())

        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, self.detail_tabbed_pane)
        center_split.setResizeWeight(0.5)

        self.panel.add(top_container, BorderLayout.NORTH)
        self.panel.add(center_split, BorderLayout.CENTER)

    def _create_role_box(self, title, text_area):
        box = JPanel(BorderLayout())
        box.setBorder(BorderFactory.createTitledBorder(title))
        scroll = JScrollPane(text_area)
        box.add(scroll, BorderLayout.CENTER)
        return box

    def get_component(self):
        return self.panel

    def _load_saved_settings(self):
        admin = load_setting(self.callbacks, "pm_role_admin", "")
        usera = load_setting(self.callbacks, "pm_role_usera", "")
        userb = load_setting(self.callbacks, "pm_role_userb", "")
        unauth = load_setting(self.callbacks, "pm_role_unauth", "")
        delay = load_setting(self.callbacks, "pm_delay_ms", "50")

        if admin:
            self.txt_admin.setText(admin)
        if usera:
            self.txt_usera.setText(usera)
        if userb:
            self.txt_userb.setText(userb)
        if unauth:
            self.txt_unauth.setText(unauth)
        if delay:
            self.txt_delay.setText(delay)

    def _on_save_config(self, event):
        save_setting(self.callbacks, "pm_role_admin", self.txt_admin.getText())
        save_setting(self.callbacks, "pm_role_usera", self.txt_usera.getText())
        save_setting(self.callbacks, "pm_role_userb", self.txt_userb.getText())
        save_setting(self.callbacks, "pm_role_unauth", self.txt_unauth.getText())
        save_setting(self.callbacks, "pm_delay_ms", self.txt_delay.getText())
        JOptionPane.showMessageDialog(self.panel, "Privilege Matrix settings saved.")

    def _on_toggle_enabled(self, event):
        self.is_enabled = self.chk_enable.isSelected()

    def _on_clear_log(self, event):
        self.matrix_table_model.setRowCount(0)
        self.matrix_records = []

    def handle_proxy_request(self, message_info):
        """
        Called when a request passes through Burp Proxy.
        """
        if not self.is_enabled:
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
        # Filter static assets
        if any(path.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2']):
            return

        try:
            delay_ms = int(self.txt_delay.getText().strip())
        except Exception:
            delay_ms = 50

        # Spawn background thread to replay across roles
        t = threading.Thread(
            target=self._replay_matrix_thread,
            args=(http_service, req_bytes, req_info.getMethod(), path, delay_ms)
        )
        t.daemon = True
        t.start()

    def _replay_matrix_thread(self, http_service, req_bytes, method, path, delay_ms):
        raw_req = self.helpers.bytesToString(req_bytes)

        roles_config = [
            ("Admin", self.txt_admin.getText()),
            ("User A", self.txt_usera.getText()),
            ("User B", self.txt_userb.getText()),
            ("Unauth", self.txt_unauth.getText())
        ]

        role_statuses = {}
        role_responses = {}

        for role_name, role_headers in roles_config:
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

            modified_req_str = PrivilegeMatrixEngine.apply_role_headers(raw_req, role_headers)
            modified_req_bytes = self.helpers.stringToBytes(modified_req_str)

            try:
                resp = self.callbacks.makeHttpRequest(http_service, modified_req_bytes)
                status_str = "Error"
                if resp and resp.getResponse():
                    resp_info = self.helpers.analyzeResponse(resp.getResponse())
                    code = resp_info.getStatusCode()
                    status_str = str(code)
                    role_responses[role_name] = resp.getResponse()
                else:
                    role_responses[role_name] = None
                role_statuses[role_name] = status_str
            except Exception as ex:
                log_error(self.callbacks, "Privilege matrix replay error for role " + str(role_name), ex)
                role_statuses[role_name] = "Err"
                role_responses[role_name] = None

        record = {
            'method': method,
            'path': path,
            'statuses': role_statuses,
            'responses': role_responses
        }

        # Memory capping (max 500 entries)
        if len(self.matrix_records) >= self.MAX_RECORD_CAP:
            self.matrix_records.pop(0)

        self.matrix_records.append(record)

        def add_row():
            if self.matrix_table_model.getRowCount() >= self.MAX_RECORD_CAP:
                self.matrix_table_model.removeRow(0)

            self.matrix_table_model.addRow([
                method,
                path,
                role_statuses.get("Admin", "N/A"),
                role_statuses.get("User A", "N/A"),
                role_statuses.get("User B", "N/A"),
                role_statuses.get("Unauth", "N/A")
            ])

        SwingUtilities.invokeLater(add_row)

    def _on_row_selected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.matrix_table.getSelectedRow()
        if 0 <= row < len(self.matrix_records):
            rec = self.matrix_records[row]
            responses = rec['responses']
            for role_name, editor in self.role_viewers.items():
                resp_bytes = responses.get(role_name)
                if resp_bytes:
                    editor.setMessage(resp_bytes, False)
                else:
                    editor.setMessage(self.helpers.stringToBytes("No Response Recorded"), False)
