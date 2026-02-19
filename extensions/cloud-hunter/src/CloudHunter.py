from burp import IBurpExtender
from burp import IHttpListener
import sys
import os

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../common/python"))

from CloudHunterLogic import CloudHunterLogic
from burp_utils import get_logger
from burp_shared import FindingReporter

logger = get_logger("CloudHunter")

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Cloud Metadata & Bucket Hunter")

        self.logic = CloudHunterLogic()

        # Register listeners
        callbacks.registerHttpListener(self)

        logger.info("Cloud Hunter loaded.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url = str(request_info.getUrl())

        response = messageInfo.getResponse()
        if not response:
            return

        response_info = self._helpers.analyzeResponse(response)
        body_offset = response_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        findings = self.logic.analyze_content(url, body)

        for f in findings:
            FindingReporter.get().report(f)
            self._callbacks.issueAlert("Cloud Leak Detected: " + f['name'] + " at " + url)
