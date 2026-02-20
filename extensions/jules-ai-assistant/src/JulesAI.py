from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from javax.swing import JPanel, JScrollPane, JTextArea, JLabel, JButton, SwingUtilities, JTextField, JSplitPane
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
        # Resolve paths without relying on __file__
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
        self.logic = JulesAILogic()

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._logger.info("Jules AI Assistant loaded. Tooling capabilities initialized.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Chat/Analysis Area
        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        self.chat_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.chat_area.setText("Welcome to Jules AI. Agentic capabilities are active.\n" + ("-"*60) + "\n")

        # Configuration Panel
        config_panel = JPanel(GridLayout(6, 2))
        config_panel.add(JLabel("AI API Endpoint:"))
        self.endpoint_field = JTextField("https://api.openai.com/v1/chat/completions")
        config_panel.add(self.endpoint_field)

        config_panel.add(JLabel("API Key:"))
        self.api_key_field = JTextField("")
        config_panel.add(self.api_key_field)

        config_panel.add(JLabel("Model:"))
        self.model_field = JTextField("gpt-4o")
        config_panel.add(self.model_field)

        config_panel.add(JLabel("System Prompt:"))
        self.system_prompt_field = JTextField(self.logic.system_prompt)
        config_panel.add(self.system_prompt_field)

        config_panel.add(JLabel("Max Tool Iterations:"))
        self.max_iter_field = JTextField("3")
        config_panel.add(self.max_iter_field)

        clear_btn = JButton("Clear Chat", actionPerformed=lambda x: self.chat_area.setText(""))
        config_panel.add(clear_btn)

        self.panel.add(config_panel, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.chat_area), BorderLayout.CENTER)

    def getTabCaption(self):
        return "Jules AI"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
            menu_item = JMenuItem("Ask Jules AI to Investigate", actionPerformed=lambda x: self.run_analysis(invocation))
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
                api_key = self.api_key_field.getText()
                endpoint = self.endpoint_field.getText()
                model = self.model_field.getText()
                system_prompt = self.system_prompt_field.getText()
                max_iter = int(self.max_iter_field.getText())

                # Conversation state
                convo = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": self.logic.format_analysis_prompt(url, req_str, resp_str)}
                ]

                for i in range(max_iter):
                    SwingUtilities.invokeLater(lambda: self.chat_area.append("[...] Jules AI is thinking (Step {}/{})...\n".format(i+1, max_iter)))

                    response_text = self.logic.call_llm(api_key, endpoint, convo, model=model)
                    SwingUtilities.invokeLater(lambda t=response_text: self.chat_area.append("Jules AI: " + t + "\n"))

                    convo.append({"role": "assistant", "content": response_text})

                    tool_calls = self.logic.parse_tool_call(response_text)
                    if not tool_calls:
                        break # No more tools requested

                    tool_results = []
                    for tc in tool_calls:
                        result = self.execute_tool(tc, messageInfo)
                        tool_results.append(result)
                        SwingUtilities.invokeLater(lambda r=result: self.chat_area.append("[Tool Result] " + str(r)[:500] + "...\n"))

                    # Feed results back to AI
                    convo.append({"role": "user", "content": "Tool results: " + json.dumps(tool_results)})

                SwingUtilities.invokeLater(lambda: self.chat_area.append("-" * 60 + "\n"))

            except Exception as e:
                SwingUtilities.invokeLater(lambda err=e: self.chat_area.append("[!] Error in analysis loop: " + str(err) + "\n"))

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

                # Construct request
                # Note: Burp helpers usually expect a list starting with the request line
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
