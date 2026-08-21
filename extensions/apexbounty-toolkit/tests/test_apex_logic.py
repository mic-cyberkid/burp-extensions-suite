import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ApexToolkitLogic import (
    LogicBreakerEngine,
    LLMFuzzerEngine,
    RaceOrchestratorEngine,
    PrivilegeMatrixEngine
)

class TestLogicBreakerEngine(unittest.TestCase):
    def test_permutations_generation(self):
        sequence = [
            {'id': 1, 'name': 'Cart Item'},
            {'id': 2, 'name': 'Apply Coupon'},
            {'id': 3, 'name': 'Checkout'}
        ]
        perms = LogicBreakerEngine.generate_permutations(sequence)
        self.assertTrue(len(perms) > 0)
        names = [p['name'] for p in perms]
        self.assertIn('Baseline (Full Sequence)', names)
        self.assertIn('Drop Cart Item', names)
        self.assertIn('Duplicate Cart Item', names)
        self.assertIn('Reverse Sequence', names)
        self.assertIn('Jump to Final Step', names)

    def test_empty_sequence(self):
        perms = LogicBreakerEngine.generate_permutations([])
        self.assertEqual(perms, [])


class TestLLMFuzzerEngine(unittest.TestCase):
    def test_extract_parameters(self):
        raw_req = (
            "POST /api/user?debug=true HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"user_id": 123, "role": "user"}'
        )
        params = LLMFuzzerEngine.extract_parameters(raw_req)
        param_names = [p['name'] for p in params]
        self.assertIn('debug', param_names)
        self.assertIn('user_id', param_names)
        self.assertIn('role', param_names)

    def test_extract_parameters_array_and_null(self):
        raw_req = (
            "POST /api/batch HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n\r\n"
            '[{"id": 1, "active": null}]'
        )
        params = LLMFuzzerEngine.extract_parameters(raw_req)
        param_names = [p['name'] for p in params]
        self.assertIn('id', param_names)
        self.assertIn('active', param_names)
        active_p = next(p for p in params if p['name'] == 'active')
        self.assertEqual(active_p['value'], 'null')

    def test_build_prompt_redaction(self):
        snippet = (
            "POST /api/user HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer secret_token_123\r\n"
            "Cookie: session=secret_sess_abc\r\n"
            "X-API-Key: key_999\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"role": "user"}'
        )
        prompt = LLMFuzzerEngine.build_prompt('role', snippet)
        self.assertIn("role", prompt)
        self.assertIn("WAF bypass", prompt)
        self.assertNotIn("secret_token_123", prompt)
        self.assertNotIn("secret_sess_abc", prompt)
        self.assertNotIn("key_999", prompt)
        self.assertIn("Authorization: [REDACTED]", prompt)
        self.assertIn("Cookie: [REDACTED]", prompt)

    def test_parse_llm_payloads(self):
        json_resp = 'Here are payloads: ["\' OR 1=1--", "admin\'--", "<script>alert(1)</script>"]'
        payloads = LLMFuzzerEngine.parse_llm_payloads(json_resp)
        self.assertEqual(len(payloads), 3)
        self.assertEqual(payloads[0], "' OR 1=1--")

    def test_parse_llm_payloads_markdown_fence(self):
        fenced_resp = "```json\n[\"payload_a\", \"payload_b\"]\n```"
        payloads = LLMFuzzerEngine.parse_llm_payloads(fenced_resp)
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0], "payload_a")

    def test_inject_payload_json(self):
        raw_req = (
            "POST /api/user HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 16\r\n\r\n"
            '{"role": "user"}'
        )
        injected = LLMFuzzerEngine.inject_payload(raw_req, 'role', 'admin_bypass')
        self.assertIn('admin_bypass', injected)
        self.assertIn('Content-Length: 24', injected)

    def test_inject_payload_exact_key_matching(self):
        raw_req = (
            "POST /api/account HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n\r\n"
            "user_id=5&id=10"
        )
        injected = LLMFuzzerEngine.inject_payload(raw_req, 'id', 'PAYLOAD_MARKER')
        self.assertIn("user_id=5", injected, "user_id should NOT be modified when targeting id")
        self.assertIn("id=PAYLOAD_MARKER", injected, "id should be injected with payload")

    def test_inject_payload_percent_encoding_and_delimiter(self):
        raw_req = (
            "GET /api/search?q=test&category=all HTTP/1.1\r\n"
            "Host: example.com\r\n\r\n"
        )
        injected = LLMFuzzerEngine.inject_payload(raw_req, 'q', "' OR '1'='1")
        self.assertIn("q=%27%20OR%20%271%27%3D%271", injected)
        self.assertTrue(injected.endswith("\r\n\r\n"), "Request must retain header trailing delimiter")


class TestRaceOrchestratorEngine(unittest.TestCase):
    def test_classify_race_response(self):
        is_anomaly, note = RaceOrchestratorEngine.classify_race_response(500, 100, [50, 60])
        self.assertTrue(is_anomaly)
        self.assertIn("500", note)

        is_anomaly2, note2 = RaceOrchestratorEngine.classify_race_response(200, 50, [50, 50])
        self.assertFalse(is_anomaly2)
        self.assertIn("Normal", note2)

        # Deviating content length
        is_anomaly3, note3 = RaceOrchestratorEngine.classify_race_response(200, 120, [50, 60])
        self.assertTrue(is_anomaly3)
        self.assertIn("Deviating Content Length (120)", note3)


class TestPrivilegeMatrixEngine(unittest.TestCase):
    def test_apply_role_headers(self):
        raw_req = (
            "GET /api/admin/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer original_token\r\n"
            "Cookie: session=12345\r\n\r\n"
        )
        new_headers = "Authorization: Bearer attacker_token\r\nX-Custom-Role: user"
        modified_req = PrivilegeMatrixEngine.apply_role_headers(raw_req, new_headers)

        self.assertNotIn("original_token", modified_req)
        self.assertNotIn("session=12345", modified_req)
        self.assertIn("Authorization: Bearer attacker_token", modified_req)
        self.assertIn("X-Custom-Role: user", modified_req)

    def test_classify_status_code(self):
        c200 = PrivilegeMatrixEngine.classify_status_code(200)
        self.assertEqual(c200['status'], 'SUCCESS')
        self.assertEqual(c200['color'], 'GREEN')

        c403 = PrivilegeMatrixEngine.classify_status_code(403)
        self.assertEqual(c403['status'], 'DENIED')
        self.assertEqual(c403['color'], 'RED')


if __name__ == '__main__':
    unittest.main()
