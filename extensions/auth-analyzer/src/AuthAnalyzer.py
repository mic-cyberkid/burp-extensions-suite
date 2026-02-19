from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from javax.swing import JPanel, JScrollPane, JTable, JLabel, BorderLayout, JButton, JTextArea, SwingUtilities
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
from javax.swing import JMenuItem
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from AuthLogic import AuthLogic
from burp_utils import get_logger

logger = get_logger("AuthAnalyzer")

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Auth Bypass and Session Analyzer")

        self.logic = AuthLogic()

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        logger.info("Auth Analyzer loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Table for session tokens
        self.column_names = ["Token", "Entropy", "Type", "Findings"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)
        scroll_pane = JScrollPane(self.table)

        self.panel.add(JLabel("Session and Token Analysis"), BorderLayout.NORTH)
        self.panel.add(scroll_pane, BorderLayout.CENTER)

    def getTabCaption(self):
        return "Auth Analyzer"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We look for session tokens in both requests (Cookies/Headers) and responses (Set-Cookie/Body)
        if messageIsRequest:
            request_info = self._helpers.analyzeRequest(messageInfo)
            headers = request_info.getHeaders()
            for h in headers:
                if h.lower().startswith("authorization: bearer "):
                    token = h[21:].strip()
                    self.analyze_token(token)
                elif h.lower().startswith("cookie:"):
                    # Basic cookie parsing
                    cookies = h[7:].split(";")
                    for c in cookies:
                        if "=" in c:
                            name, val = c.split("=", 1)
                            self.analyze_token(val.strip())
        else:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            headers = response_info.getHeaders()
            for h in headers:
                if h.lower().startswith("set-cookie:"):
                    # Basic set-cookie parsing
                    content = h[11:].split(";")[0]
                    if "=" in content:
                        name, val = content.split("=", 1)
                        self.analyze_token(val.strip())

    def analyze_token(self, token):
        if not token or len(token) < 5:
            return

        # Check if already analyzed (avoid noise)
        # In a real tool, we would track this more robustly

        findings, entropy = self.logic.analyze_session_token(token)
        jwt_findings = self.logic.analyze_jwt(token)

        all_findings = findings + jwt_findings
        if not all_findings and entropy > 3.5:
            return # Skip boring tokens

        finding_str = ", ".join([f['name'] for f in all_findings])
        token_type = "JWT" if self.logic.decode_jwt(token) else "Opaque"

        row = [token[:50] + "...", "{:.2f}".format(entropy), token_type, finding_str]

        def update_table():
            self.table_model.addRow(row)
        SwingUtilities.invokeLater(update_table)

    # IContextMenuFactory implementation
    def createMenuItems(self, invocation):
        menu_list = ArrayList()

        context = invocation.getInvocationContext()
        # Only show in Repeater or Proxy request editor
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or context == invocation.CONTEXT_PROXY_HISTORY:
            menu_item = JMenuItem("Generate IDOR Mutants", actionPerformed=lambda x: self.generate_idor(invocation))
            menu_list.add(menu_item)

        return menu_list

    def generate_idor(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        messageInfo = messages[0]
        request_info = self._helpers.analyzeRequest(messageInfo)
        params = request_info.getParameters()

        param_dict = {}
        for p in params:
            param_dict[p.getName()] = p.getValue()

        mutations = self.logic.mutate_id_params(param_dict)

        if not mutations:
            self._callbacks.issueAlert("No ID-like parameters found to mutate.")
            return

        for mutation in mutations:
            for name, value in mutation.items():
                # In a real extension, we might send this to Repeater
                # For now, we'll log the suggested mutation
                logger.info("Suggested IDOR mutation: {} = {}".format(name, value))
                self._callbacks.issueAlert("IDOR Suggestion: {} -> {}".format(name, value))
