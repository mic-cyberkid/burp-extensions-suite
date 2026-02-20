import json
import ssl
import sys
import base64
import re
import os
import time

try:
    import urllib2
except ImportError:
    # Python 3 compatibility for unit tests
    import urllib.request as urllib2

class JulesAILogic:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = self.load_config()
        self.system_prompt = (
            "You are Jules AI, a ruthless and highly skilled web application penetration tester. "
            "You have access to Burp Suite tools via a special JSON format. "
            "To use a tool, output a JSON block like this: "
            "{\"tool\": \"http_request\", \"parameters\": {\"url\": \"...\", \"method\": \"GET\", \"headers\": [], \"body\": \"\"}} "
            "Available tools: "
            "1. http_request: Makes an HTTP request. Parameters: url, method, headers (list of strings), body. "
            "2. base64_decode: Decodes a base64 string. Parameter: data. "
            "3. report_finding: Logs a finding to the tracker. Parameters: name, severity, confidence, url, description, remediation. "
            "Always aim for high ROI bugs: IDOR, Logic Flaws, State Machine bypasses."
        )

    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "api_key": "",
            "endpoint": "https://jules.googleapis.com/v1alpha",
            "source_id": "",
            "session_id": ""
        }

    def save_config(self):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except:
            pass

    def format_analysis_prompt(self, url, request, response):
        prompt = "Investigative Task: Perform a ruthless security analysis of the following interaction.\n"
        prompt += "URL: {}\n\n".format(url)
        prompt += "REQUEST:\n{}\n\n".format(request[:2000])
        if response:
            prompt += "RESPONSE:\n{}\n\n".format(response[:3000])

        prompt += (
            "Identify potential IDORs, logic flaws, or misconfigurations. "
            "Use tools if necessary to probe further."
        )
        return prompt

    def parse_tool_call(self, ai_text):
        tool_calls = []
        i = 0
        while i < len(ai_text):
            if ai_text[i] == '{':
                stack = 0
                for j in range(i, len(ai_text)):
                    if ai_text[j] == '{':
                        stack += 1
                    elif ai_text[j] == '}':
                        stack -= 1

                    if stack == 0:
                        candidate = ai_text[i:j+1]
                        if '"tool"' in candidate:
                            try:
                                tool_calls.append(json.loads(candidate))
                                i = j
                            except:
                                pass
                        break
            i += 1
        return tool_calls

    def _make_request(self, url, method="GET", data=None, headers=None):
        if headers is None: headers = {}
        if self.config["api_key"]:
            headers["X-Goog-Api-Key"] = self.config["api_key"]
        headers["Content-Type"] = "application/json"

        json_data = json.dumps(data) if data else None
        req = urllib2.Request(url, json_data, headers)
        req.get_method = lambda: method

        try:
            ctx = ssl.create_default_context()
        except AttributeError:
            ctx = None

        if ctx:
            response = urllib2.urlopen(req, timeout=60, context=ctx)
        else:
            response = urllib2.urlopen(req, timeout=60)

        return json.loads(response.read())

    def create_session(self, initial_prompt):
        url = "{}/sessions".format(self.config["endpoint"])
        payload = {
            "prompt": self.system_prompt + "\n\n" + initial_prompt,
            "sourceContext": {
                "source": self.config["source_id"]
            },
            "title": "Burp Suite Analysis Session"
        }
        result = self._make_request(url, "POST", payload)
        self.config["session_id"] = result["id"]
        self.save_config()
        return result["id"]

    def send_message(self, session_id, prompt):
        url = "{}/sessions/{}:sendMessage".format(self.config["endpoint"], session_id)
        payload = {"prompt": prompt}
        return self._make_request(url, "POST", payload)

    def poll_for_response(self, session_id):
        url = "{}/sessions/{}/activities".format(self.config["endpoint"], session_id)
        # We need the latest activity from the 'agent'
        # Simple polling logic
        for _ in range(30): # 30 attempts, 2s each = 60s timeout
            activities = self._make_request(url, "GET")
            if "activities" in activities:
                # Iterate backwards to find latest agent message
                for act in reversed(activities["activities"]):
                    if act.get("originator") == "agent":
                        # Check if it contains a message or progress
                        if "message" in act:
                            return act["message"]["text"]
                        elif "progressUpdated" in act:
                            # Sometimes agent updates progress before full message
                            # But we usually want the message
                            pass
                        elif "planGenerated" in act:
                            # Handle initial plan generation if necessary
                            steps = act["planGenerated"]["plan"]["steps"]
                            return "Plan generated: " + ", ".join([s["title"] for s in steps])
            time.sleep(2)
        return "Timeout waiting for Jules AI response."

    def call_jules(self, prompt):
        """
        Unified call that handles session creation or message sending.
        """
        if not self.config["api_key"]:
            return "SIMULATION: No Google API Key provided. Please set it in the Jules AI tab."

        try:
            sid = self.config.get("session_id")
            if not sid:
                sid = self.create_session(prompt)
            else:
                try:
                    self.send_message(sid, prompt)
                except:
                    # Session might have expired, try creating a new one
                    sid = self.create_session(prompt)

            return self.poll_for_response(sid)
        except Exception as e:
            return "Error calling Jules API: " + str(e)
