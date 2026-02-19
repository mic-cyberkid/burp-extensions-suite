from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, BorderLayout, SwingUtilities
from javax.swing.table import DefaultTableModel
import sys
import os

# Add the current directory and common directory to sys.path
# This allows us to import ScannerLogic and shared utilities
# In a real Burp environment, we might need to be careful with paths
# For now, we assume the file is loaded from its directory
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from ScannerLogic import ScannerLogic
from burp_utils import get_logger

logger = get_logger("PassiveScanner")

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Passive Vulnerability Scanner")

        self.logic = ScannerLogic()
        self.findings = []

        # Setup UI
        self.setup_ui()

        # Register as HTTP listener
        callbacks.registerHttpListener(self)

        # Add the custom tab to Burp
        callbacks.addSuiteTab(self)

        logger.info("Passive Vulnerability Scanner loaded successfully.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Table for findings
        self.column_names = ["Issue", "Severity", "Confidence", "URL", "Remediation"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)
        scroll_pane = JScrollPane(self.table)

        self.panel.add(JLabel("Passive Scan Findings"), BorderLayout.NORTH)
        self.panel.add(scroll_pane, BorderLayout.CENTER)

    # ITab implementation
    def getTabCaption(self):
        return "Passive Scanner"

    def getUiComponent(self):
        return self.panel

    # IHttpListener implementation
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses
        if messageIsRequest:
            return

        # Only process tools like Proxy (4) or others if desired
        # Burp Tool flags: Proxy = 4, Scanner = 16, etc.
        if toolFlag != 4:
            return

        response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
        headers_list = response_info.getHeaders()

        # Convert Java list of headers to Python dict
        headers = {}
        for h in headers_list:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())
        status_code = response_info.getStatusCode()

        findings = self.logic.analyze_response(url, status_code, headers)

        for finding in findings:
            # Avoid duplicate findings for the same URL and Issue
            finding_key = (url, finding['name'])
            if finding_key not in [ (f[3], f[0]) for f in self.findings]:
                row = [finding['name'], finding['severity'], finding['confidence'], url, finding['remediation']]
                self.findings.append(row)

                # Update UI in Event Dispatch Thread
                def add_to_table(row=row):
                    self.table_model.addRow(row)
                SwingUtilities.invokeLater(add_to_table)

                # Also log as an issue in Burp (optional, but good for visibility)
                # Note: Legacy API has different ways to report issues depending on how it's used
                # In passive scan, we might want to implement IScannerCheck instead,
                # but for simplicity and UI focus we use this custom tab.
                self._callbacks.issueAlert("Found: " + finding['name'] + " at " + url)
