import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from JulesAILogic import JulesAILogic

class TestJulesAILogic(unittest.TestCase):
    def setUp(self):
        self.logic = JulesAILogic()

    def test_format_prompt(self):
        url = "http://test.com/login"
        request = "POST /login HTTP/1.1\nHost: test.com"
        response = "HTTP/1.1 200 OK"
        prompt = self.logic.format_analysis_prompt(url, request, response)
        self.assertIn(url, prompt)
        self.assertIn("REQUEST:", prompt)
        self.assertIn("RESPONSE:", prompt)

    def test_simulate_response(self):
        prompt = "test login message"
        response = self.logic.simulate_ai_response(prompt)
        self.assertIn("JULES AI ANALYSIS", response)
        self.assertIn("login", response.lower())

    def test_call_api_simulation(self):
        # Without API key, it should fall back to simulation
        response = self.logic.call_api("", "http://api.com", "test")
        self.assertIn("Simulation Mode", response)

if __name__ == '__main__':
    unittest.main()
