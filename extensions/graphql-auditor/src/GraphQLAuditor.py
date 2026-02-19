from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, BorderLayout, SwingUtilities
from javax.swing.table import DefaultTableModel
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from GraphQLLogic import GraphQLLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

logger = get_logger("GraphQLAuditor")

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("GraphQL Security Auditor")

        self.logic = GraphQLLogic()
        self.findings = []

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        logger.info("GraphQL Auditor loaded.")

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
            FindingReporter.get().report(f)

            row = [f['name'], url, f['description'][:100] + "..."]
            if row not in self.findings:
                self.findings.append(row)
                def update_table(r=row):
                    self.table_model.addRow(r)
                SwingUtilities.invokeLater(update_table)
