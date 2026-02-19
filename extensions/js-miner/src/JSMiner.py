from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, BorderLayout, SwingUtilities
from javax.swing.table import DefaultTableModel
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from JSMinerLogic import JSMinerLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

logger = get_logger("JSMiner")

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("JS Link & Secret Miner")

        self.logic = JSMinerLogic()
        self.findings = []

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        logger.info("JS Miner loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        self.column_names = ["Type", "Found At", "Details"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)

        self.panel.add(JLabel("JS Link & Secret Miner - Discovered Assets"), BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

    def getTabCaption(self):
        return "JS Miner"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        # We are only interested in JS files
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        if not (url.endswith(".js") or ".js?" in url):
            return

        response = messageInfo.getResponse()
        if not response:
            return

        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        findings = self.logic.analyze_js(url, body)

        for f in findings:
            FindingReporter.get().report(f)

            row = [f['name'], url, f['description'][:100] + "..."]
            if row not in self.findings:
                self.findings.append(row)
                def update_table(r=row):
                    self.table_model.addRow(r)
                SwingUtilities.invokeLater(update_table)
