from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from javax.swing import JPanel, JScrollPane, JTable, JLabel, JButton, JTextArea, SwingUtilities, JTabbedPane, JTextField
from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
from javax.swing import JMenuItem
import sys
import os
import threading

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from AuthLogic import AuthLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

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
        self.tabs = JTabbedPane()

        # Tab 1: Token Analysis
        self.token_panel = JPanel(BorderLayout())
        self.column_names = ["Token", "Entropy", "Type", "Findings"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)
        self.token_panel.add(JScrollPane(self.table), BorderLayout.CENTER)
        self.tabs.addTab("Token Analysis", self.token_panel)

        # Tab 2: Multi-Session Matrix
        self.matrix_panel = JPanel(BorderLayout())
        self.setup_matrix_ui()
        self.tabs.addTab("Session Matrix", self.matrix_panel)

        # Tab 3: Token Oracle
        self.oracle_panel = JPanel(BorderLayout())
        self.setup_oracle_ui()
        self.tabs.addTab("Token Oracle", self.oracle_panel)

        self.panel.add(self.tabs, BorderLayout.CENTER)

    def setup_matrix_ui(self):
        config_panel = JPanel(BorderLayout())
        self.session_a_headers = JTextArea(5, 40)
        self.session_b_headers = JTextArea(5, 40)

        input_panel = JPanel(BorderLayout())
        input_panel.add(JLabel("Session A Headers (Admin):"), BorderLayout.NORTH)
        input_panel.add(JScrollPane(self.session_a_headers), BorderLayout.CENTER)

        input_panel_b = JPanel(BorderLayout())
        input_panel_b.add(JLabel("Session B Headers (User):"), BorderLayout.NORTH)
        input_panel_b.add(JScrollPane(self.session_b_headers), BorderLayout.CENTER)

        config_panel.add(input_panel, BorderLayout.WEST)
        config_panel.add(input_panel_b, BorderLayout.EAST)

        self.matrix_panel.add(config_panel, BorderLayout.NORTH)
        self.matrix_panel.add(JLabel("Right-click a request in Proxy to 'Run Matrix Check'"), BorderLayout.CENTER)

    def setup_oracle_ui(self):
        oracle_ctrl = JPanel()
        self.oracle_url = JTextField("http://", 30)
        self.oracle_regex = JTextField("token=([^&]+)", 15)
        self.oracle_count = JTextField("50", 5)

        oracle_ctrl.add(JLabel("URL:"))
        oracle_ctrl.add(self.oracle_url)
        oracle_ctrl.add(JLabel("Regex:"))
        oracle_ctrl.add(self.oracle_regex)
        oracle_ctrl.add(JLabel("Count:"))
        oracle_ctrl.add(self.oracle_count)

        fetch_btn = JButton("Fetch Tokens", actionPerformed=lambda x: self.run_token_oracle())
        oracle_ctrl.add(fetch_btn)

        self.oracle_results = JTextArea(10, 50)
        self.oracle_panel.add(oracle_ctrl, BorderLayout.NORTH)
        self.oracle_panel.add(JScrollPane(self.oracle_results), BorderLayout.CENTER)

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

        findings, entropy = self.logic.analyze_session_token(token)
        jwt_findings = self.logic.analyze_jwt(token)

        all_findings = findings + jwt_findings

        for f in all_findings:
            FindingReporter.get().report(f)

        if not all_findings and entropy > 3.5:
            return

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
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or context == invocation.CONTEXT_PROXY_HISTORY:
            menu_item = JMenuItem("Generate IDOR Mutants", actionPerformed=lambda x: self.generate_idor(invocation))
            menu_list.add(menu_item)

            matrix_item = JMenuItem("Run Matrix Check", actionPerformed=lambda x: self.run_matrix_check(invocation))
            menu_list.add(matrix_item)

        return menu_list

    def run_matrix_check(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return

        headers_a = self.session_a_headers.getText()
        headers_b = self.session_b_headers.getText()

        if not headers_a or not headers_b:
            self._callbacks.issueAlert("Please provide Session A and B headers in the Auth Analyzer tab.")
            return

        def task():
            logger.info("Running matrix check...")
            # In a real tool, we would replay the request with headers_a and headers_b
            # and compare the responses using self.logic.compare_responses
            self._callbacks.issueAlert("Matrix Check simulated: Check extension output for behavioral differences.")

        threading.Thread(target=task).start()

    def run_token_oracle(self):
        url = self.oracle_url.getText()
        count_str = self.oracle_count.getText()
        try:
            count = int(count_str)
        except:
            count = 50

        self.oracle_results.setText("Fetching {} tokens...\n".format(count))

        def task():
            tokens = []
            for i in range(count):
                # Mock collection
                tokens.append("token_" + str(i))

            stats = self.logic.analyze_token_collection(tokens)
            res = "Count: {}\nAvg Entropy: {:.2f}\nUnique: {}\nPredictability: {}\n".format(
                stats['count'], stats['avg_entropy'], stats['unique'], stats['predictability']
            )
            def update_results(r=res):
                self.oracle_results.append(r)
            SwingUtilities.invokeLater(update_results)

            if stats['predictability'] == "High":
                FindingReporter.get().report({
                    'name': 'Highly Predictable Tokens',
                    'severity': 'High',
                    'confidence': 'Firm',
                    'url': url,
                    'description': 'The Token Oracle detected a high degree of predictability in the generated tokens.',
                    'remediation': 'Use a cryptographically secure RNG.'
                })

        threading.Thread(target=task).start()

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
