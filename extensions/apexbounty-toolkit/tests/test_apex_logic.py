import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ApexToolkitLogic import (
    NoiseFilter,
    CorrelationEngine,
    LogicBreakerEngine,
    LLMFuzzerEngine,
    RaceOrchestratorEngine,
    PrivilegeMatrixEngine
)


class TestNoiseFilter(unittest.TestCase):
    def test_should_filter_static_extensions(self):
        self.assertTrue(NoiseFilter.should_filter("https://example.com/app.js"))
        self.assertTrue(NoiseFilter.should_filter("/styles/main.css"))
        self.assertTrue(NoiseFilter.should_filter("/assets/logo.svg"))
        self.assertFalse(NoiseFilter.should_filter("https://example.com/api/v1/checkout"))

    def test_should_filter_mime_type(self):
        self.assertTrue(NoiseFilter.should_filter("/api/data", mime_type="application/javascript"))
        self.assertTrue(NoiseFilter.should_filter("/api/data", mime_type="text/css"))
        self.assertFalse(NoiseFilter.should_filter("/api/data", mime_type="application/json"))

    def test_should_filter_default_noise_patterns(self):
        self.assertTrue(NoiseFilter.should_filter("https://example.com/api/metrics"))
        self.assertTrue(NoiseFilter.should_filter("https://example.com/ping"))
        self.assertTrue(NoiseFilter.should_filter("https://example.com/analytics"))

    def test_should_filter_custom_regex(self):
        self.assertTrue(NoiseFilter.should_filter("/v1/ignore_me", custom_regex_pattern=r'/ignore_me'))
        self.assertFalse(NoiseFilter.should_filter("/v1/keep_me", custom_regex_pattern=r'/ignore_me'))


class TestCorrelationEngine(unittest.TestCase):
    def test_extract_tokens(self):
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session_id=xyz123; Path=/\r\n"
            "X-CSRF-Token: csrf_secret_abc\r\n"
        )
        body = '{"user_id": 456, "token": "jwt_token_val", "uuid": "123e4567-e89b-12d3-a456-426614174000"}'

        tokens = CorrelationEngine.extract_tokens(headers, body)

        self.assertEqual(tokens.get('session_id'), 'xyz123')
        self.assertEqual(tokens.get('X-CSRF-Token'), 'csrf_secret_abc')
        self.assertEqual(tokens.get('user_id'), '456')
        self.assertEqual(tokens.get('token'), 'jwt_token_val')
        self.assertEqual(tokens.get('uuid'), '123e4567-e89b-12d3-a456-426614174000')

    def test_apply_tokens(self):
        raw_req = (
            "POST /api/action?user_id=1 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer old_token\r\n"
            "Cookie: session_id=old_session\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"token": "old_token", "user_id": "1"}'
        )
        token_map = {
            'user_id': '999',
            'token': 'new_jwt_value',
            'authorization': 'Bearer new_jwt_value',
            'Cookie:session_id': 'new_session'
        }

        updated_req = CorrelationEngine.apply_tokens(raw_req, token_map)

        self.assertIn('user_id=999', updated_req)
        self.assertIn('Cookie: session_id=new_session', updated_req)
        self.assertIn('"token": "new_jwt_value"', updated_req)
        self.assertIn('Authorization: Bearer new_jwt_value', updated_req)

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

    def test_build_prompt(self):
        prompt = LLMFuzzerEngine.build_prompt('role', 'POST /api/user HTTP/1.1')
        self.assertIn("role", prompt)
        self.assertIn("WAF bypass", prompt)

    def test_parse_llm_payloads(self):
        json_resp = 'Here are payloads: ["\' OR 1=1--", "admin\'--", "<script>alert(1)</script>"]'
        payloads = LLMFuzzerEngine.parse_llm_payloads(json_resp)
        self.assertEqual(len(payloads), 3)
        self.assertEqual(payloads[0], "' OR 1=1--")

    def test_inject_payload(self):
        raw_req = (
            "POST /api/user HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"role": "user"}'
        )
        injected = LLMFuzzerEngine.inject_payload(raw_req, 'role', 'admin_bypass')
        self.assertIn('admin_bypass', injected)


class TestRaceOrchestratorEngine(unittest.TestCase):
    def test_classify_race_response(self):
        is_anomaly, note = RaceOrchestratorEngine.classify_race_response(500, 100, [50, 60])
        self.assertTrue(is_anomaly)
        self.assertIn("500", note)

        is_anomaly2, note2 = RaceOrchestratorEngine.classify_race_response(200, 50, [50, 50])
        self.assertFalse(is_anomaly2)
        self.assertIn("Normal", note2)


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
