import unittest
import sys
import os
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from JulesAILogic import JulesAILogic

class TestJulesAILogic(unittest.TestCase):
    def setUp(self):
        self.config_path = "test_jules_config.json"
        if os.path.exists(self.config_path): os.remove(self.config_path)
        self.logic = JulesAILogic(self.config_path)

    def tearDown(self):
        if os.path.exists(self.config_path): os.remove(self.config_path)

    def test_config_persistence(self):
        self.logic.config["api_key"] = "test-key"
        self.logic.save_config()

        new_logic = JulesAILogic(self.config_path)
        self.assertEqual(new_logic.config["api_key"], "test-key")

    def test_format_prompt(self):
        url = "http://test.com/login"
        prompt = self.logic.format_analysis_prompt(url, "REQ", "RESP")
        self.assertIn(url, prompt)

    def test_parse_tool_call(self):
        ai_text = 'Use this tool: {"tool": "http_request", "parameters": {"url": "http://x.com"}}'
        calls = self.logic.parse_tool_call(ai_text)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool"], "http_request")

if __name__ == '__main__':
    unittest.main()
