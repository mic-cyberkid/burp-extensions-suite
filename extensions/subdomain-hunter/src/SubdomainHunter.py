from burp import IBurpExtender
from burp import IHttpListener
import sys
import os

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Resolve paths without relying on __file__
        extension_file = callbacks.getExtensionFilename()
        base_dir = os.path.dirname(extension_file)
        common_dir = os.path.join(base_dir, "../../../common/python")

        if base_dir not in sys.path: sys.path.append(base_dir)
        if common_dir not in sys.path: sys.path.append(common_dir)

        # Deferred imports to ensure sys.path is ready
        from TakeoverLogic import TakeoverLogic
        from burp_utils import get_logger
        from burp_shared import FindingReporter

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Subdomain Takeover & CNAME Hunter")

        self._logger = get_logger("SubdomainHunter")
        self._reporter = FindingReporter.get()
        self.logic = TakeoverLogic()

        # Register listeners
        callbacks.registerHttpListener(self)

        self._logger.info("Subdomain Hunter loaded.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        response = messageInfo.getResponse()
        if not response: return

        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        findings = self.logic.analyze_response(url, body)

        for f in findings:
            self._reporter.report(f)
            self._callbacks.issueAlert("Subdomain Takeover Detected: " + f['name'] + " at " + url)
