from burp import IBurpExtender
from burp import ITab
from burp import IContextMenuFactory
from javax.swing import JPanel, JScrollPane, JTextArea, JLabel, JButton, SwingUtilities, JTextField
from java.awt import BorderLayout, GridLayout, Font
from java.util import ArrayList
from javax.swing import JMenuItem
import sys
import os
import threading
import json
import base64

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # Resolve paths
        extension_file = callbacks.getExtensionFilename()
        base_dir = os.path.dirname(extension_file)
        common_dir = os.path.join(base_dir, "../../../common/python")

        if base_dir not in sys.path: sys.path.append(base_dir)
        if common_dir not in sys.path: sys.path.append(common_dir)

        # Deferred imports
        from JulesAILogic import JulesAILogic
        from burp_utils import get_logger
        from burp_shared import FindingReporter

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Jules AI Assistant")

        self._logger = get_logger("JulesAI")
        self._reporter = FindingReporter.get()

        # Initialize logic with config file
        config_path = os.path.join(os.path.expanduser("~"), "burp_jules_config.json")
        self.logic = JulesAILogic(config_path)

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._logger.info("Jules AI Assistant loaded. Integration with Google Jules API complete.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Chat/Analysis Area
        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        self.chat_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.chat_area.setText("Welcome to Jules AI (Integrated Agentic Edition).\n" + ("-"*60) + "\n")

        # Configuration Panel
        config_panel = JPanel(GridLayout(7, 2))

        config_panel.add(JLabel("X-Goog-Api-Key:"))
        self.api_key_field = JTextField(self.logic.config["api_key"])
        config_panel.add(self.api_key_field)

        config_panel.add(JLabel("API Endpoint:"))
        self.endpoint_field = JTextField(self.logic.config["endpoint"])
        config_panel.add(self.endpoint_field)

        config_panel.add(JLabel("Source ID (e.g. sources/github/...):"))
        self.source_id_field = JTextField(self.logic.config["source_id"])
        config_panel.add(self.source_id_field)

        config_panel.add(JLabel("Active Session ID:"))
        self.session_id_field = JTextField(self.logic.config["session_id"])
        config_panel.add(self.session_id_field)

        config_panel.add(JLabel("Max Tool Iterations:"))
        self.max_iter_field = JTextField("3")
        config_panel.add(self.max_iter_field)

        save_btn = JButton("Save Config", actionPerformed=lambda x: self.save_config())
        config_panel.add(save_btn)

        clear_btn = JButton("Clear Chat", actionPerformed=lambda x: self.chat_area.setText(""))
        config_panel.add(clear_btn)

        self.panel.add(config_panel, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.chat_area), BorderLayout.CENTER)

    def save_config(self):
        self.logic.config["api_key"] = self.api_key_field.getText()
        self.logic.config["endpoint"] = self.endpoint_field.getText()
        self.logic.config["source_id"] = self.source_id_field.getText()
        self.logic.config["session_id"] = self.session_id_field.getText()
        self.logic.save_config()
        self._callbacks.issueAlert("Jules AI Config Saved.")

    def getTabCaption(self):
        return "Jules AI"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
            menu_item = JMenuItem("Investigate with Jules AI", actionPerformed=lambda x: self.run_analysis(invocation))
            menu_list.add(menu_item)
        return menu_list

    def run_analysis(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return

        messageInfo = messages[0]
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        req_str = self._helpers.bytesToString(messageInfo.getRequest())
        resp_str = self._helpers.bytesToString(messageInfo.getResponse()) if messageInfo.getResponse() else ""

        self.chat_area.append("\n[+] Investigative Focus: {}\n".format(url))

        def task():
            try:
                # Ensure latest UI values are in logic config
                self.logic.config["api_key"] = self.api_key_field.getText()
                self.logic.config["endpoint"] = self.endpoint_field.getText()
                self.logic.config["source_id"] = self.source_id_field.getText()

                max_iter = int(self.max_iter_field.getText())

                # Format initial investigative prompt
                current_prompt = self.logic.format_analysis_prompt(url, req_str, resp_str)

                for i in range(max_iter):
                    SwingUtilities.invokeLater(lambda: self.chat_area.append("[...] Jules AI is reasoning (Step {}/{})...\n".format(i+1, max_iter)))

                    response_text = self.logic.call_jules(current_prompt)
                    SwingUtilities.invokeLater(lambda t=response_text: self.chat_area.append("Jules AI: " + t + "\n"))

                    tool_calls = self.logic.parse_tool_call(response_text)
                    if not tool_calls:
                        break

                    tool_results = []
                    for tc in tool_calls:
                        result = self.execute_tool(tc, messageInfo)
                        tool_results.append(result)
                        SwingUtilities.invokeLater(lambda r=result: self.chat_area.append("[Tool Result] " + str(r)[:500] + "...\n"))

                    current_prompt = "Tool results: " + json.dumps(tool_results)

                # Update Session ID in UI after run
                SwingUtilities.invokeLater(lambda: self.session_id_field.setText(self.logic.config["session_id"]))
                SwingUtilities.invokeLater(lambda: self.chat_area.append("-" * 60 + "\n"))

            except Exception as e:
                SwingUtilities.invokeLater(lambda err=e: self.chat_area.append("[!] Error in agent loop: " + str(err) + "\n"))

        threading.Thread(target=task).start()

    def execute_tool(self, tool_call, original_messageInfo):
        tool_name = tool_call.get("tool")
        params = tool_call.get("parameters", {})

        if tool_name == "http_request":
            url = params.get("url")
            method = params.get("method", "GET")
            headers = params.get("headers", [])
            body = params.get("body", "")

            try:
                from java.net import URL
                target_url = URL(url)
                port = target_url.getPort() if target_url.getPort() != -1 else (443 if target_url.getProtocol() == "https" else 80)
                service = self._helpers.buildHttpService(target_url.getHost(), port, target_url.getProtocol() == "https")

                req_headers = ["{} {} HTTP/1.1".format(method, target_url.getFile())]
                req_headers.extend(headers)

                request = self._helpers.buildHttpMessage(req_headers, self._helpers.stringToBytes(body))
                resp_info = self._callbacks.makeHttpRequest(service, request)

                if resp_info and resp_info.getResponse():
                    return {
                        "status": self._helpers.analyzeResponse(resp_info.getResponse()).getStatusCode(),
                        "response": self._helpers.bytesToString(resp_info.getResponse())[:2000]
                    }
                return "Failed to get response"
            except Exception as e:
                return "Error making request: " + str(e)

        elif tool_name == "base64_decode":
            data = params.get("data", "")
            try:
                return base64.b64decode(data)
            except:
                return "Invalid base64"

        elif tool_name == "report_finding":
            self._reporter.report(params)
            return "Finding reported successfully"

        return "Unknown tool: " + str(tool_name)
