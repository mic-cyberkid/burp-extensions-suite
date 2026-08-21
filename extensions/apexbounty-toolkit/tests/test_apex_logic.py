import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ApexToolkitLogic import (
    LogicBreakerEngine,
    LLMFuzzerEngine,
    RaceOrchestratorEngine,
    PrivilegeMatrixEngine,
    log_info,
    log_error,
    save_setting,
    load_setting
)


class MockCallbacks(object):
    def __init__(self):
        self.output = []
        self.errors = []
        self.settings = {}

    def printOutput(self, msg):
        self.output.append(msg)

    def printError(self, msg):
        self.errors.append(msg)

    def saveExtensionSetting(self, key, value):
        self.settings[key] = value

    def loadExtensionSetting(self, key):
        return self.settings.get(key, None)


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

    def test_is_static_asset(self):
        self.assertTrue(LogicBreakerEngine.is_static_asset("/static/style.css"))
        self.assertTrue(LogicBreakerEngine.is_static_asset("/assets/script.js?v=1.0"))
        self.assertTrue(LogicBreakerEngine.is_static_asset("/images/logo.png"))
        self.assertFalse(LogicBreakerEngine.is_static_asset("/api/v1/user/login"))
        self.assertFalse(LogicBreakerEngine.is_static_asset("/checkout"))

    def test_export_import_sequence_json(self):
        sequence = [
            {
                'method': 'POST',
                'host': 'example.com',
                'port': 443,
                'use_https': True,
                'path': '/api/login',
                'name': 'POST /api/login',
                'request_str': 'POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\n',
                'include': True
            }
        ]
        json_str = LogicBreakerEngine.export_sequence_to_json(sequence)
        self.assertIn('/api/login', json_str)
        self.assertIn('example.com', json_str)

        imported = LogicBreakerEngine.import_sequence_from_json(json_str)
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0]['method'], 'POST')
        self.assertEqual(imported[0]['host'], 'example.com')
        self.assertEqual(imported[0]['port'], 443)
        self.assertTrue(imported[0]['use_https'])

    def test_extract_and_substitute_dynamic_tokens(self):
        resp_str = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: sessionid=xyz123secret; Path=/\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"access_token": "token_abc_999", "csrf_token": "csrf_val_111", "status": "success"}'
        )
        tokens = LogicBreakerEngine.extract_dynamic_tokens(resp_str)
        self.assertIn('access_token', tokens)
        self.assertEqual(tokens['access_token'], 'token_abc_999')
        self.assertEqual(tokens['__bearer_token__'], 'token_abc_999')
        self.assertIn('sessionid', tokens)

        req_str = (
            "POST /api/checkout HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer old_stale_token\r\n"
            "Cookie: sessionid=old_sess\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"csrf_token": "old_token", "amount": 100}'
        )
        substituted = LogicBreakerEngine.substitute_tokens(req_str, tokens)
        self.assertIn('Authorization: Bearer token_abc_999', substituted)
        self.assertIn('sessionid=xyz123secret', substituted)
        self.assertIn('"csrf_token": "csrf_val_111"', substituted)


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

    def test_extract_nested_parameters(self):
        raw_req = (
            "POST /api/settings HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"user": {"profile": {"name": "Alice"}}, "roles": ["admin", "editor"]}'
        )
        params = LLMFuzzerEngine.extract_parameters(raw_req)
        param_names = [p['name'] for p in params]
        self.assertIn('user.profile.name', param_names)

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

    def test_export_race_results_csv(self):
        results = [
            ("Request A", "A-1", "200", "150", "No", "Normal (200)"),
            ("Request B", "B-1", "500", "50", "Yes", "Internal Server Error (500)")
        ]
        csv_out = RaceOrchestratorEngine.export_race_results_csv(results)
        self.assertIn('Target,Thread ID,Status', csv_out)
        self.assertIn('"Request A","A-1","200"', csv_out)
        self.assertIn('"Request B","B-1","500"', csv_out)


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


class TestUtilities(unittest.TestCase):
    def test_logging_and_settings(self):
        callbacks = MockCallbacks()
        log_info(callbacks, "Info test")
        self.assertEqual(len(callbacks.output), 1)
        self.assertIn("Info test", callbacks.output[0])

        log_error(callbacks, "Error test", Exception("boom"))
        self.assertEqual(len(callbacks.errors), 1)
        self.assertIn("Error test", callbacks.errors[0])

        save_setting(callbacks, "my_key", "my_value")
        val = load_setting(callbacks, "my_key")
        self.assertEqual(val, "my_value")


if __name__ == '__main__':
    unittest.main()
