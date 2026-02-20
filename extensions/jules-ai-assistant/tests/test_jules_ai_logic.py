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
        self.assertIn("ORIGINAL REQUEST:", prompt)

    def test_parse_tool_call(self):
        ai_text = 'Check this: {"tool": "http_request", "parameters": {"url": "http://test.com"}}'
        calls = self.logic.parse_tool_call(ai_text)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['tool'], 'http_request')

    def test_call_llm_simulation(self):
        # Without API key, it should return simulation text
        response = self.logic.call_llm("", "http://api.com", [{"role": "user", "content": "test"}])
        self.assertIn("SIMULATION", response)

if __name__ == '__main__':
    unittest.main()
