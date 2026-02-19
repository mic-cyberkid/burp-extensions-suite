from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from javax.swing import JPanel, JScrollPane, JTable, JLabel, JButton, SwingUtilities, JSplitPane
from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel
from java.util import ArrayList
from javax.swing import JMenuItem
import sys
import os
import threading

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # Resolve paths without relying on __file__
        extension_file = callbacks.getExtensionFilename()
        base_dir = os.path.dirname(extension_file)
        common_dir = os.path.join(base_dir, "../../../common/python")

        if base_dir not in sys.path: sys.path.append(base_dir)
        if common_dir not in sys.path: sys.path.append(common_dir)

        # Deferred imports to ensure sys.path is ready
        from JWTIDORLogic import JWTIDORLogic
        from burp_utils import get_logger
        from burp_shared import FindingReporter

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JWT IDOR Tester")

        self._logger = get_logger("JWTIDOR")
        self._reporter = FindingReporter.get()
        self.logic = JWTIDORLogic()
        self.results = []

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._logger.info("JWT IDOR Tester loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Table for results
        self.column_names = ["Field", "Original Value", "Mutated Value", "Strategy", "Status", "Length", "URL"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)

        # Top panel with buttons
        top_panel = JPanel()
        clear_btn = JButton("Clear Results", actionPerformed=lambda x: self.clear_results())
        top_panel.add(clear_btn)

        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

    def clear_results(self):
        self.results = []
        self.table_model.setRowCount(0)

    def getTabCaption(self):
        return "JWT IDOR"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST or context == invocation.CONTEXT_PROXY_HISTORY:
            menu_item = JMenuItem("Test for JWT IDOR", actionPerformed=lambda x: self.run_test(invocation))
            menu_list.add(menu_item)
        return menu_list

    def run_test(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages: return

        messageInfo = messages[0]
        request = messageInfo.getRequest()
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())

        token = ""
        header_index = -1
        for i, h in enumerate(headers):
            if h.lower().startswith("authorization: bearer "):
                token = h[21:].strip()
                header_index = i
                break

        if not token:
            self._callbacks.issueAlert("No Bearer JWT found in Authorization header.")
            return

        mutations = self.logic.generate_mutations(token)
        if not mutations:
            self._callbacks.issueAlert("No ID-like fields found in JWT payload.")
            return

        self._callbacks.issueAlert("Starting ruthless JWT IDOR test with {} mutations...".format(len(mutations)))

        def task():
            for m in mutations:
                new_headers = list(headers)
                new_headers[header_index] = "Authorization: Bearer " + m['token']

                new_request = self._helpers.buildHttpMessage(new_headers, request[request_info.getBodyOffset():])

                # Send request
                resp_info = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_request)
                if not resp_info or not resp_info.getResponse():
                    continue

                response = resp_info.getResponse()
                response_info = self._helpers.analyzeResponse(response)

                status = response_info.getStatusCode()
                length = len(response)
                url = str(request_info.getUrl())

                # UI Update
                row = [m['field'], str(m['original']), str(m['mutated']), m['strategy'], str(status), str(length), url]
                def add_row(r=row):
                    self.table_model.addRow(r)
                SwingUtilities.invokeLater(add_row)

                # Report if successful (e.g., 200 OK)
                if status == 200:
                    self._reporter.report({
                        'name': 'Potential JWT IDOR Found',
                        'severity': 'High',
                        'confidence': 'Firm',
                        'url': url,
                        'description': 'A mutated JWT (field: {}, value: {}) resulted in a 200 OK response using strategy "{}".'.format(m['field'], m['mutated'], m['strategy']),
                        'remediation': 'Ensure the server verifies the JWT signature and performs proper authorization checks for the ID in the payload.'
                    })

        threading.Thread(target=task).start()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass # Only manual trigger for now to be "ruthless" but controlled
