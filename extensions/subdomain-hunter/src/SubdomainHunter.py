from burp import IBurpExtender
from burp import IHttpListener
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from TakeoverLogic import TakeoverLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

logger = get_logger("SubdomainHunter")

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Subdomain Takeover & CNAME Hunter")

        self.logic = TakeoverLogic()

        # Register listeners
        callbacks.registerHttpListener(self)

        logger.info("Subdomain Hunter loaded.")

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
            FindingReporter.get().report(f)
            self._callbacks.issueAlert("Subdomain Takeover Detected: " + f['name'] + " at " + url)
