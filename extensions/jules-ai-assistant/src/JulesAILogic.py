import json

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
                "JULES AI ANALYSIS:\n"
                "- The login flow appears to use a standard POST request. Check for SQL Injection in the 'username' field.\n"
                "- Verify if the session token generated has high entropy.\n"
                "- PAYLOADS:\n"
                "  1. admin'--\n"
                "  2. \"><script>alert('JulesAI')</script>\n"
                "  3. Try brute-forcing with the Multi-Session Matrix."
            )
        return "JULES AI ANALYSIS:\nAnalyzing traffic... No immediate critical logic flaws detected. Perform manual exploration of identified parameters."

    def call_api(self, api_key, endpoint, prompt):
        """
        Placeholder for real API call (e.g., to OpenAI or Anthropic).
        Uses urllib2 for Jython 2.7 compatibility.
        """
        if not api_key:
            return self.simulate_ai_response(prompt)

        # In a real implementation, we would use urllib2 to POST to the endpoint
        # Example structure:
        # import urllib2
        # data = json.dumps({"model": "gpt-4", "messages": [{"role": "system", "content": self.system_prompt}, {"role": "user", "content": prompt}]})
        # req = urllib2.Request(endpoint, data, {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + api_key})
        # response = urllib2.urlopen(req)
        # return json.loads(response.read())['choices'][0]['message']['content']

        return "API Key detected. (Real API call logic would go here). \n\n" + self.simulate_ai_response(prompt)
