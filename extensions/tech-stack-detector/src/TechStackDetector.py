from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, BorderLayout, SwingUtilities
from javax.swing.table import DefaultTableModel
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from TechStackLogic import TechStackLogic
from burp_utils import get_logger

logger = get_logger("TechStackDetector")

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Fingerprinting & Tech Stack Detector")

        self.logic = TechStackLogic()
        self.domain_stacks = {} # domain -> set of techs

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        logger.info("Tech Stack Detector loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        self.column_names = ["Domain", "Detected Technologies"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)

        self.panel.add(JLabel("Application Technology Fingerprints"), BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)

    def getTabCaption(self):
        return "Tech Detector"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl()
        domain = url.getHost()

        response = messageInfo.getResponse()
        if not response:
            return

        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        headers_list = response_info.getHeaders()
        headers = {}
        for h in headers_list:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        detected = self.logic.analyze_message(headers, body)

        if detected:
            if domain not in self.domain_stacks:
                self.domain_stacks[domain] = set()

            new_techs = False
            for tech in detected:
                if tech not in self.domain_stacks[domain]:
                    self.domain_stacks[domain].add(tech)
                    new_techs = True

            if new_techs:
                self.update_ui_table()

    def update_ui_table(self):
        def update():
            self.table_model.setRowCount(0)
            for domain, techs in self.domain_stacks.items():
                self.table_model.addRow([domain, ", ".join(sorted(list(techs)))])
        SwingUtilities.invokeLater(update)
