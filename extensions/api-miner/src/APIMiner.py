from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, SwingUtilities
from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from APIMinerLogic import APIMinerLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

logger = get_logger("APIMiner")

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("API Documentation & Swagger Miner")

        self.logic = APIMinerLogic()
        self.findings = []

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        logger.info("API Miner loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        self.column_names = ["Doc Type", "URL", "Endpoints Count"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)

        self.panel.add(JLabel("Discovered API Documentation"), BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

    def getTabCaption(self):
        return "API Miner"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        if not self.logic.is_api_doc(url):
            return

        response = messageInfo.getResponse()
        if not response: return

        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        findings = self.logic.analyze_response(url, body)

        for f in findings:
            FindingReporter.get().report(f)

            endpoints = self.logic.extract_endpoints(body)
            row = [f['name'], url, str(len(endpoints))]
            if row not in self.findings:
                self.findings.append(row)
                def update_table(r=row):
                    self.table_model.addRow(r)
                SwingUtilities.invokeLater(update_table)
