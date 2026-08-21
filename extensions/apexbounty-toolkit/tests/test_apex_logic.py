import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ApexToolkitLogic import (
    LogicBreakerEngine,
    LLMFuzzerEngine,
    RaceOrchestratorEngine,
    PrivilegeMatrixEngine,
    JunkFilter,
    TokenExtractor,
    RequestMutator
)
from LogicBreakerTab import req_to_b64, b64_to_req, generate_curl

class TestJunkFilter(unittest.TestCase):
    def test_default_junk_filter(self):
        jf = JunkFilter()

        # Static JS
        is_junk, reason = jf.is_junk('GET', '/assets/app.js', 'application/javascript')
        self.assertTrue(is_junk)
        self.assertIn("Filtered extension", reason)

        # Static CSS Content Type
        is_junk, reason = jf.is_junk('GET', '/style', 'text/css')
        self.assertTrue(is_junk)
        self.assertIn("Filtered content-type", reason)

        # Static Pattern
        is_junk, reason = jf.is_junk('GET', '/static/logo.png', 'image/png')
        self.assertTrue(is_junk)

        # Valid API Endpoint
        is_junk, reason = jf.is_junk('POST', '/api/checkout', 'application/json')
        self.assertFalse(is_junk)

    def test_interesting_only_mode(self):
        jf = JunkFilter({'interesting_only': True})

        # GET to non-API HTML -> Junk in interesting-only mode
        is_junk, _ = jf.is_junk('GET', '/about', 'text/html')
        self.assertTrue(is_junk)

        # POST to /checkout -> Keep
        is_junk, _ = jf.is_junk('POST', '/checkout', 'text/html')
        self.assertFalse(is_junk)

        # GET to /api/v1/user -> Keep
        is_junk, _ = jf.is_junk('GET', '/api/v1/user', 'application/json')
        self.assertFalse(is_junk)


class TestTokenExtractor(unittest.TestCase):
    def test_extract_tokens(self):
        raw_resp = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: sessionid=xyz123; Path=/\r\n"
            "X-CSRF-Token: token_abc\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"status": "ok", "order_id": 9988, "user_id": "u_42"}'
        )
        tokens = TokenExtractor.extract_tokens(raw_resp)
        self.assertEqual(tokens['cookies'].get('sessionid'), 'xyz123')
        self.assertEqual(tokens['headers'].get('X-CSRF-Token'), 'token_abc')
        self.assertEqual(tokens['body_tokens'].get('order_id'), '9988')
        self.assertEqual(tokens['body_tokens'].get('user_id'), 'u_42')


class TestLogicBreakerTabHelpers(unittest.TestCase):
    def test_b64_serialization(self):
        raw = b"POST /api/login HTTP/1.1\r\nHost: test.com\r\n\r\nuser=1"
        encoded = req_to_b64(raw)
        decoded = b64_to_req(encoded)
        self.assertEqual(bytes(decoded), raw)

    def test_generate_curl(self):
        raw = "POST /api/test HTTP/1.1\r\nHost: test.com\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
        curl = generate_curl("test.com", 443, True, raw)
        self.assertIn("curl -i -s -k -X POST \"https://test.com/api/test\"", curl)
        self.assertIn("-H \"Host: test.com\"", curl)
        self.assertIn("--data-raw \"{\\\"a\\\":1}\"", curl)


class TestRequestMutator(unittest.TestCase):
    def test_apply_state(self):
        raw_req = (
            "POST /api/checkout HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Cookie: sessionid=old_session\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"order_id": "0", "items": [1]}'
        )
        state = {
            'cookies': {'sessionid': 'new_session'},
            'headers': {'X-CSRF-Token': 'new_csrf'},
            'body_tokens': {'order_id': '9988'}
        }
        mutated = RequestMutator.apply_state(raw_req, state)
        self.assertIn("sessionid=new_session", mutated)
        self.assertIn("X-CSRF-Token: new_csrf", mutated)
        self.assertIn('"order_id": "9988"', mutated)


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

    def test_analyze_differential_results(self):
        is_anomaly, notes = LogicBreakerEngine.analyze_differential_results(
            baseline_status=200,
            baseline_len=500,
            final_status=200,
            final_len=1200,
            final_resp_body="Order approved and created successfully"
        )
        self.assertIn("Length diff", notes)
        self.assertIn("Success keywords", notes)

        is_anomaly2, notes2 = LogicBreakerEngine.analyze_differential_results(
            baseline_status=200,
            baseline_len=500,
            final_status=403,
            final_len=100,
            final_resp_body="Unauthorized access"
        )
        self.assertTrue(is_anomaly2)
        self.assertIn("Status diff", notes2)


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
