from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from javax.swing import JPanel, JScrollPane, JTable, JLabel, BorderLayout, JButton, SwingUtilities
from javax.swing.table import DefaultTableModel
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from ResetOtpLogic import ResetOtpLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

logger = get_logger("ResetOtpAnalyzer")

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Reset/OTP Poisoning Analyzer")

        self.logic = ResetOtpLogic()
        self.findings = []

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        logger.info("Reset/OTP Analyzer loaded.")

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Table for findings
        self.column_names = ["Issue", "Severity", "URL", "Details"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)
        scroll_pane = JScrollPane(self.table)

        # Action Buttons
        button_panel = JPanel()
        probe_btn = JButton("Poison Host Probe (Repeater)", actionPerformed=lambda x: self.send_poison_probe())
        button_panel.add(probe_btn)

        self.panel.add(JLabel("Reset/OTP Vulnerability Findings"), BorderLayout.NORTH)
        self.panel.add(scroll_pane, BorderLayout.CENTER)
        self.panel.add(button_panel, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "Reset/OTP"

    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        if not self.logic.is_interesting_endpoint(url):
            return

        response = messageInfo.getResponse()
        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        headers_list = response_info.getHeaders()
        headers = {h.split(':', 1)[0].strip(): h.split(':', 1)[1].strip() for h in headers_list if ':' in h}

        # Run Analysis
        findings = self.logic.analyze_message(url, headers, body)

        # Host Poisoning Check
        request_headers = request_info.getHeaders()
        host = ""
        for h in request_headers:
            if h.lower().startswith("host:"):
                host = h[5:].strip()
                break

        if self.logic.check_host_poisoning(host, body):
             findings.append({
                'name': 'Potential Password Reset Poisoning',
                'severity': 'High',
                'confidence': 'Firm',
                'url': url,
                'description': 'The Host header value ({}) was found reflected in the response body of a reset/OTP endpoint. This often indicates that password reset links are generated using the Host header, which can be poisoned by an attacker.'.format(host),
                'remediation': 'Use a fixed, trusted domain name for generating absolute URLs in emails.'
            })

        for f in findings:
            # Report to shared reporter
            FindingReporter.get().report(f)

            # Update UI
            row = [f['name'], f['severity'], url, f['description'][:100] + "..."]
            if row not in self.findings:
                self.findings.append(row)
                def update_table(r=row):
                    self.table_model.addRow(r)
                SwingUtilities.invokeLater(update_table)

    def send_poison_probe(self):
        # In a real Burp environment, this would take the selected message and send to Repeater with mutated Host
        # Here we just alert the user to the concept.
        self._callbacks.issueAlert("Feature: Send to Repeater with 'Host: attacker.com' and check for reflection in response body.")
