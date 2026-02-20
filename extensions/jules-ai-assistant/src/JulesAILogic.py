import json
import ssl
import sys

try:
    import urllib2
except ImportError:
    # Python 3 compatibility for unit tests
    import urllib.request as urllib2

class JulesAILogic:
    def __init__(self):
        self.system_prompt = (
            "You are Jules AI, a ruthless and highly skilled web application penetration tester. "
            "Your goal is to analyze HTTP traffic and findings to identify critical vulnerabilities, "
            "especially business logic flaws, complex authorization bypasses, and chained exploits. "
            "Provide clear analysis, potential impacts, and precise payload suggestions."
        )

    def format_analysis_prompt(self, url, request, response):
        prompt = "URL: {}\n\n".format(url)
        prompt += "REQUEST:\n{}\n\n".format(request[:2000]) # Truncate for token limits
        if response:
            prompt += "RESPONSE:\n{}\n\n".format(response[:3000])

        prompt += (
            "Please perform a deep security analysis of this interaction. "
            "Identify potential IDORs, logic flaws, race conditions, or misconfigurations. "
            "Suggest 3 ruthless exploit payloads to verify these vulnerabilities."
        )
        return prompt

    def simulate_ai_response(self, prompt):
        """
        Simulated AI response for testing or when no API key is provided.
        """
        if "login" in prompt.lower():
            return (
                "JULES AI ANALYSIS (Simulation Mode):\n"
                "- The login flow appears to use a standard POST request. Check for SQL Injection in the 'username' field.\n"
                "- Verify if the session token generated has high entropy.\n"
                "- PAYLOADS:\n"
                "  1. admin'--\n"
                "  2. \"><script>alert('JulesAI')</script>\n"
                "  3. Try brute-forcing with the Multi-Session Matrix."
            )
        return "JULES AI ANALYSIS (Simulation Mode):\nAnalyzing traffic... No immediate critical logic flaws detected. Perform manual exploration of identified parameters."

    def call_api(self, api_key, endpoint, prompt, model="gpt-4o", system_prompt=None):
        """
        Real API call to an OpenAI-compatible LLM provider.
        Uses urllib2 for Jython 2.7 compatibility.
        """
        if system_prompt is None:
            system_prompt = self.system_prompt
        if not api_key:
            return self.simulate_ai_response(prompt)

        try:
            # Prepare request body (OpenAI Chat Completion format)
            data = json.dumps({
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.7
            })

            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + api_key
            }

            # Create request
            req = urllib2.Request(endpoint, data, headers)

            # SSL Context to handle modern TLS if necessary in older Jython
            # Note: Modern Burp versions bundle a capable Jython environment
            try:
                ctx = ssl.create_default_context()
            except AttributeError:
                # Fallback for very old environments
                ctx = None

            # Execute request
            if ctx:
                response = urllib2.urlopen(req, timeout=60, context=ctx)
            else:
                response = urllib2.urlopen(req, timeout=60)

            body = response.read()
            result = json.loads(body)

            # Parse result
            if 'choices' in result and len(result['choices']) > 0:
                ai_msg = result['choices'][0]['message']['content']
                return ai_msg
            elif 'error' in result:
                return "API Error: " + str(result['error'])
            else:
                return "Unexpected API response format: " + body

        except urllib2.HTTPError as e:
            error_content = e.read()
            try:
                error_json = json.loads(error_content)
                if 'error' in error_json:
                    return "HTTP Error {}: {}".format(e.code, error_json['error']['message'])
            except:
                pass
            return "HTTP Error {}: {}".format(e.code, error_content)

        except Exception as e:
            return "Error calling Jules AI API: " + str(e)
