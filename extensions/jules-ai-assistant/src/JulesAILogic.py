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
                    cfg = json.load(f)
                    # Migrating old config or setting defaults
                    if "backend_type" not in cfg: cfg["backend_type"] = "openai"
                    return cfg
            except:
                pass
        return {
            "api_key": "",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "source_id": "",
            "session_id": "",
            "backend_type": "openai",
            "model": "gpt-4o"
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

    def call_openai(self, convo):
        """
        Direct LLM call for OpenAI-compatible backends.
        """
        headers = {'Authorization': 'Bearer ' + self.config["api_key"]}
        url = self.config["endpoint"]
        payload = {
            "model": self.config.get("model", "gpt-4o"),
            "messages": convo,
            "temperature": 0.7
        }
        result = self._make_request(url, "POST", payload, headers)
        if 'choices' in result:
            return result['choices'][0]['message']['content']
        return str(result)

    def call_google_jules(self, prompt, is_initial=False):
        """
        Call for Google Jules API (Session-based).
        """
        if not self.config["source_id"]:
            return "Error: Source ID is required for Google Jules backend. If you are testing a web app without source code, use the 'OpenAI/Standard' backend."

        endpoint = self.config["endpoint"]
        headers = {"X-Goog-Api-Key": self.config["api_key"]}

        sid = self.config.get("session_id")

        if is_initial or not sid:
            # Create Session
            url = "{}/sessions".format(endpoint)
            payload = {
                "prompt": self.system_prompt + "\n\n" + prompt,
                "sourceContext": {"source": self.config["source_id"]},
                "title": "Burp Investigative Session"
            }
            result = self._make_request(url, "POST", payload, headers)
            sid = result["id"]
            self.config["session_id"] = sid
            self.save_config()
        else:
            # Send Message
            url = "{}/sessions/{}:sendMessage".format(endpoint, sid)
            payload = {"prompt": prompt}
            try:
                self._make_request(url, "POST", payload, headers)
            except:
                # Retry with new session if message failed
                return self.call_google_jules(prompt, is_initial=True)

        return self.poll_for_google_jules_response(sid)

    def poll_for_google_jules_response(self, session_id):
        url = "{}/sessions/{}/activities".format(self.config["endpoint"], session_id)
        headers = {"X-Goog-Api-Key": self.config["api_key"]}

        for _ in range(30):
            activities = self._make_request(url, "GET", headers=headers)
            if "activities" in activities:
                for act in reversed(activities["activities"]):
                    if act.get("originator") == "agent":
                        if "message" in act:
                            return act["message"]["text"]
            time.sleep(2)
        return "Timeout waiting for Google Jules response."

    def call_agent(self, convo, iteration=0):
        """
        Unified agent call that selects the appropriate backend.
        """
        if not self.config["api_key"]:
            return "SIMULATION: No API Key provided."

        try:
            if self.config["backend_type"] == "google_jules":
                # Jules API takes the last user message as prompt
                # Note: Jules API manages its own history in the session
                return self.call_google_jules(convo[-1]["content"], is_initial=(iteration==0))
            else:
                # OpenAI/Standard backend requires sending the full convo
                return self.call_openai(convo)
        except Exception as e:
            return "Error: " + str(e)
