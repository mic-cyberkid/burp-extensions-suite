import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ApexToolkitLogic import (
    ScopeEngine,
    LogicBreakerEngine,
    LLMFuzzerEngine,
    RaceOrchestratorEngine,
    PrivilegeMatrixEngine,
    CorrelationEngine
)


class MockCallbacks(object):
    def __init__(self, in_scope_hosts):
        self.in_scope_hosts = set(in_scope_hosts)

    def isInScope(self, target):
        target_str = str(target)
        for host in self.in_scope_hosts:
            if host in target_str:
                return True
        return False


class MockHttpService(object):
    def __init__(self, host, protocol='https', port=443):
        self._host = host
        self._protocol = protocol
        self._port = port

    def getHost(self):
        return self._host

    def getProtocol(self):
        return self._protocol

    def getPort(self):
        return self._port


class TestScopeEngine(unittest.TestCase):
    def test_callbacks_none(self):
        self.assertTrue(ScopeEngine.is_in_scope(None, "https://example.com"))

    def test_empty_target(self):
        callbacks = MockCallbacks(["example.com"])
        self.assertTrue(ScopeEngine.is_in_scope(callbacks, None))
        self.assertTrue(ScopeEngine.is_in_scope(callbacks, ""))

    def test_string_target_in_and_out_of_scope(self):
        callbacks = MockCallbacks(["example.com"])
        self.assertTrue(ScopeEngine.is_in_scope(callbacks, "https://example.com/api"))
        self.assertTrue(ScopeEngine.is_in_scope(callbacks, "example.com"))
        self.assertFalse(ScopeEngine.is_in_scope(callbacks, "https://out-of-scope.com/api"))

    def test_http_service_target(self):
        callbacks = MockCallbacks(["target.com"])
        svc_in = MockHttpService("target.com")
        svc_out = MockHttpService("other.com")

        self.assertTrue(ScopeEngine.is_in_scope(callbacks, svc_in))
        self.assertFalse(ScopeEngine.is_in_scope(callbacks, svc_out))

    def test_callbacks_exception_fallback(self):
        class FaultyCallbacks(object):
            def isInScope(self, url):
                raise RuntimeError("Scope check internal failure")

        self.assertTrue(ScopeEngine.is_in_scope(FaultyCallbacks(), "https://example.com"))

class TestLogicBreakerEngine(unittest.TestCase):
    def test_permutations_generation(self):
        sequence = [
            {'id': 1, 'name': 'Cart Item', 'included': True},
            {'id': 2, 'name': 'Apply Coupon', 'included': True},
            {'id': 3, 'name': 'Checkout', 'included': True}
        ]
        perms = LogicBreakerEngine.generate_permutations(sequence)
        self.assertTrue(len(perms) > 0)
        names = [p['name'] for p in perms]
        self.assertIn('Baseline (Full Sequence)', names)
        self.assertIn('Drop Cart Item', names)
        self.assertIn('Duplicate Cart Item', names)
        self.assertIn('Reverse Sequence', names)
        self.assertIn('Jump to Final Step', names)

    def test_permutations_with_pruned_steps(self):
        sequence = [
            {'id': 1, 'name': 'Step 1', 'included': True},
            {'id': 2, 'name': 'Step 2 (Pruned)', 'included': False},
            {'id': 3, 'name': 'Step 3', 'included': True}
        ]
        perms = LogicBreakerEngine.generate_permutations(sequence)
        # Should only generate permutations for active (Step 1 and Step 3) steps
        self.assertEqual(len(perms[0]['sequence']), 2)

    def test_empty_sequence(self):
        perms = LogicBreakerEngine.generate_permutations([])
        self.assertEqual(perms, [])


class TestLLMFuzzerEngine(unittest.TestCase):
    def test_extract_parameters(self):
        raw_req = (
            "POST /api/user?debug=true HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"user_id": 123, "meta": {"role": "user"}}'
        )
        params = LLMFuzzerEngine.extract_parameters(raw_req)
        param_names = [p['name'] for p in params]
        self.assertIn('debug', param_names)
        self.assertIn('user_id', param_names)
        self.assertIn('meta.role', param_names)

    def test_redact_sensitive_headers(self):
        req_snippet = (
            "GET /api/data HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer secret_token_123\r\n"
            "Cookie: session=xyz789\r\n"
            "User-Agent: Burp\r\n"
        )
        redacted = LLMFuzzerEngine.redact_sensitive_headers(req_snippet)
        self.assertNotIn("secret_token_123", redacted)
        self.assertNotIn("session=xyz789", redacted)
        self.assertIn("Authorization: [REDACTED]", redacted)
        self.assertIn("Cookie: [REDACTED]", redacted)
        self.assertIn("User-Agent: Burp", redacted)

    def test_build_prompt_redacts_auth(self):
        raw_req = "POST /api HTTP/1.1\r\nAuthorization: Bearer secret_key_abc\r\n\r\n"
        prompt = LLMFuzzerEngine.build_prompt('role', raw_req)
        self.assertNotIn("secret_key_abc", prompt)
        self.assertIn("[REDACTED]", prompt)

    def test_parse_llm_payloads(self):
        json_resp = '```json\n["\' OR 1=1--", "admin\'--", "<script>alert(1)</script>"]\n```'
        payloads = LLMFuzzerEngine.parse_llm_payloads(json_resp)
        self.assertEqual(len(payloads), 3)
        self.assertEqual(payloads[0], "' OR 1=1--")

    def test_inject_payload_exact_key_matching(self):
        # Test bug fix where injecting 'id' was corrupting 'user_id'
        raw_req = (
            "POST /api/account HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n\r\n"
            "user_id=5&id=10"
        )
        injected = LLMFuzzerEngine.inject_payload(raw_req, 'id', "PAYLOAD_MARKER&test=1")
        # Ensure user_id was NOT modified
        self.assertIn("user_id=5", injected)
        # Ensure id WAS modified and percent-encoded
        self.assertIn("id=PAYLOAD_MARKER%26test%3D1", injected)
        # Ensure Content-Length was correctly updated
        self.assertIn("Content-Length: 38", injected)

    def test_inject_payload_query_string(self):
        raw_req = "GET /api/data?user_id=5&id=10 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        injected = LLMFuzzerEngine.inject_payload(raw_req, 'id', '99')
        self.assertIn("user_id=5", injected)
        self.assertIn("id=99", injected)


class TestRaceOrchestratorEngine(unittest.TestCase):
    def test_classify_race_response(self):
        is_anomaly, note = RaceOrchestratorEngine.classify_race_response(500, 100, [50, 60])
        self.assertTrue(is_anomaly)
        self.assertIn("500", note)

        is_anomaly2, note2 = RaceOrchestratorEngine.classify_race_response(200, 50, [50, 50])
        self.assertFalse(is_anomaly2)
        self.assertIn("Normal", note2)

        # Test baseline length deviation
        is_anomaly3, note3 = RaceOrchestratorEngine.classify_race_response(200, 120, [50, 60])
        self.assertTrue(is_anomaly3)
        self.assertIn("Deviating Content Length", note3)


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


class TestCorrelationEngine(unittest.TestCase):
    def test_extract_and_apply_tokens(self):
        resp_str = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: csrf_token=cookie_csrf_123; Path=/\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"access_token": "bearer_jwt_456", "user_id": 12}'
        )
        tokens = CorrelationEngine.extract_tokens(resp_str)
        self.assertIn("csrf_token", tokens)
        self.assertEqual(tokens["csrf_token"], "cookie_csrf_123")
        self.assertIn("access_token", tokens)
        self.assertEqual(tokens["access_token"], "bearer_jwt_456")

        req_str = (
            "POST /api/action HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "X-CSRF-Token: old_csrf\r\n"
            "Authorization: Bearer old_token\r\n\r\n"
            "csrf_token=old_csrf&data=test"
        )
        updated = CorrelationEngine.apply_token_updates(req_str, tokens)
        self.assertIn("X-CSRF-Token: cookie_csrf_123", updated)
        self.assertIn("Authorization: Bearer bearer_jwt_456", updated)
        self.assertIn("csrf_token=cookie_csrf_123", updated)


if __name__ == '__main__':
    unittest.main()
