from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, SwingUtilities
from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel
import sys
import os

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Resolve paths without relying on __file__
        extension_file = callbacks.getExtensionFilename()
        base_dir = os.path.dirname(extension_file)
        common_dir = os.path.join(base_dir, "../../../common/python")

        if base_dir not in sys.path: sys.path.append(base_dir)
        if common_dir not in sys.path: sys.path.append(common_dir)

        # Deferred imports to ensure sys.path is ready
        from GraphQLLogic import GraphQLLogic
        from burp_utils import get_logger
        from burp_shared import FindingReporter

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("GraphQL Security Auditor")

        self._logger = get_logger("GraphQLAuditor")
        self._reporter = FindingReporter.get()
        self.logic = GraphQLLogic()
        self.findings = []

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        self._logger.info("GraphQL Auditor loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        self.column_names = ["Issue", "URL", "Details"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)

        self.panel.add(JLabel("GraphQL Security Findings"), BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

    def getTabCaption(self):
        return "GraphQL Auditor"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        request = messageInfo.getRequest()
        if not request: return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        # Check if it is a GraphQL request
        body_offset = request_info.getBodyOffset()
        request_body = self._helpers.bytesToString(request[body_offset:])

        if messageIsRequest:
            if self.logic.is_graphql_request(url, request_body):
                # We could inject an introspection query here, but for now we stay passive
                pass
            return

        # Process response
        response = messageInfo.getResponse()
        if not response: return

        response_info = self._helpers.analyzeResponse(response)
        resp_body_offset = response_info.getBodyOffset()
        resp_body = self._helpers.bytesToString(response[resp_body_offset:])

        findings = self.logic.analyze_response(url, resp_body)

        for f in findings:
            self._reporter.report(f)

            row = [f['name'], url, f['description'][:100] + "..."]
            if row not in self.findings:
                self.findings.append(row)
                def update_table(r=row):
                    self.table_model.addRow(r)
                SwingUtilities.invokeLater(update_table)
