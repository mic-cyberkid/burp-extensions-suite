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

        self._logger.info("Jules AI Assistant loaded. Ready to unleash capabilities.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Chat/Analysis Area
        self.chat_area = JTextArea()
        self.chat_area.setEditable(False)
        self.chat_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.chat_area.setText("Welcome to Jules AI. Send a request to begin analysis.\n" + ("-"*60) + "\n")

        # Configuration Panel
        config_panel = JPanel(GridLayout(3, 2))
        config_panel.add(JLabel("AI API Endpoint:"))
        self.endpoint_field = JTextField("https://api.openai.com/v1/chat/completions")
        config_panel.add(self.endpoint_field)

        config_panel.add(JLabel("API Key:"))
        self.api_key_field = JTextField("") # Leave empty for simulation
        config_panel.add(self.api_key_field)

        clear_btn = JButton("Clear Chat", actionPerformed=lambda x: self.chat_area.setText(""))
        config_panel.add(clear_btn)

        # Combine
        self.panel.add(config_panel, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.chat_area), BorderLayout.CENTER)

    def getTabCaption(self):
        return "Jules AI"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or context == invocation.CONTEXT_PROXY_HISTORY or context == invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            menu_item = JMenuItem("Ask Jules AI for Analysis", actionPerformed=lambda x: self.run_analysis(invocation))
            menu_list.add(menu_item)
        return menu_list

    def run_analysis(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return

        messageInfo = messages[0]
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        req_str = self._helpers.bytesToString(request)
        resp_str = self._helpers.bytesToString(response) if response else ""

        self.chat_area.append("\n[+] Analyzing: {}\n".format(url))

        def task():
            prompt = self.logic.format_analysis_prompt(url, req_str, resp_str)
            api_key = self.api_key_field.getText()
            endpoint = self.endpoint_field.getText()

            # Show processing indicator
            SwingUtilities.invokeLater(lambda: self.chat_area.append("[...] Thinking...\n"))

            analysis = self.logic.call_api(api_key, endpoint, prompt)

            def update_ui(a=analysis):
                self.chat_area.append(a + "\n")
                self.chat_area.append("-" * 60 + "\n")

            SwingUtilities.invokeLater(update_ui)

        threading.Thread(target=task).start()
