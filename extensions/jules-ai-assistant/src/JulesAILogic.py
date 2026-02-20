import json
import ssl
import sys
import base64
import re

try:
    import urllib2
except ImportError:
    # Python 3 compatibility for unit tests
    import urllib.request as urllib2

class JulesAILogic:
    def __init__(self):
        self.system_prompt = (
            "You are Jules AI, a ruthless and highly skilled web application penetration tester. "
            "You have access to Burp Suite tools via a special JSON format. "
            "To use a tool, output a JSON block like this: "
            "{\"tool\": \"http_request\", \"parameters\": {\"url\": \"...\", \"method\": \"GET\", \"headers\": [], \"body\": \"\"}} "
            "Available tools: "
            "1. http_request: Makes an HTTP request. Parameters: url, method, headers (list of strings), body. "
            "2. base64_decode: Decodes a base64 string. Parameter: data. "
            "3. report_finding: Logs a finding to the tracker. Parameters: name, severity, confidence, url, description, remediation. "
            "After using a tool, you will receive the result and should continue your analysis. "
            "Always aim for high ROI bugs: IDOR, Logic Flaws, State Machine bypasses."
        )

    def format_analysis_prompt(self, url, request, response):
        prompt = "Initial Target URL: {}\n\n".format(url)
        prompt += "ORIGINAL REQUEST:\n{}\n\n".format(request[:2000])
        if response:
            prompt += "ORIGINAL RESPONSE:\n{}\n\n".format(response[:3000])

        prompt += (
            "Deeply analyze this interaction. You can use tools to probe further or decode data. "
            "If you find a bug, use 'report_finding'. If you need more info, use 'http_request'. "
            "Start by identifying interesting parameters or headers."
        )
        return prompt

    def parse_tool_call(self, ai_text):
        """
        Attempts to find balanced JSON blocks containing a "tool" key.
        """
        tool_calls = []
        i = 0
        while i < len(ai_text):
            if ai_text[i] == '{':
                # Start of a potential JSON block
                stack = 0
                for j in range(i, len(ai_text)):
                    if ai_text[j] == '{':
                        stack += 1
                    elif ai_text[j] == '}':
                        stack -= 1

                    if stack == 0:
                        # Balanced block found
                        candidate = ai_text[i:j+1]
                        if '"tool"' in candidate:
                            try:
                                tool_calls.append(json.loads(candidate))
                                i = j # Move pointer to end of this block
                            except:
                                pass
                        break
            i += 1
        return tool_calls

    def call_llm(self, api_key, endpoint, messages, model="gpt-4o"):
        """
        Raw call to the LLM.
        """
        if not api_key:
             # Simulation fallback for testing
             last_msg = messages[-1]['content']
             if "tool" in last_msg.lower(): return "I have used a tool."
             return "SIMULATION: No API key provided."

        try:
            data = json.dumps({
                "model": model,
                "messages": messages,
                "temperature": 0.7
            })

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + api_key
            }

            req = urllib2.Request(endpoint, data, headers)

            try:
                ctx = ssl.create_default_context()
            except AttributeError:
                ctx = None

            if ctx:
                response = urllib2.urlopen(req, timeout=60, context=ctx)
            else:
                response = urllib2.urlopen(req, timeout=60)

            body = response.read()
            result = json.loads(body)

            if 'choices' in result and len(result['choices']) > 0:
                return result['choices'][0]['message']['content']
            elif 'error' in result:
                return "API Error: " + str(result['error'])
            else:
                return "Unexpected API response format: " + body
        except Exception as e:
            return "Error calling Jules AI API: " + str(e)
