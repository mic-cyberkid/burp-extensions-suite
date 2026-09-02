import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../src'))

from ApexToolkitLogic import (
    LogicBreakerEngine,
    LLMFuzzerEngine,
    RaceOrchestratorEngine,
    PrivilegeMatrixEngine,
    NoiseScorer,
    FlowStep,
    FlowSession,
    FlowCorrelator,
    FlowCaptureManager,
    MarkdownRenderer,
    TargetNotesManager
)


class TestMarkdownRendererAndNotesManager(unittest.TestCase):
    def test_markdown_rendering(self):
        raw_md = "# Header 1\n\n- Item A\n- Item B\n\n```\ncode_block()\n```"
        html = MarkdownRenderer.render_to_html(raw_md)
        self.assertIn("<h1", html)
        self.assertIn("Header 1</h1>", html)
        self.assertIn("<li>Item A</li>", html)
        self.assertIn("<code>", html)

    def test_target_notes_manager_per_domain(self):
        mgr = TargetNotesManager()
        mgr.save_notes("example.com", "# Notes for Example")
        mgr.save_notes("api.target.org", "# Notes for API Target")

        self.assertEqual(mgr.get_notes("example.com"), "# Notes for Example")
        self.assertEqual(mgr.get_notes("api.target.org"), "# Notes for API Target")
        self.assertIn("example.com", mgr.list_domains())
        self.assertIn("api.target.org", mgr.list_domains())

        rendered = mgr.get_rendered_notes("example.com")
        self.assertIn("Notes for Example", rendered)


class TestNoiseScorer(unittest.TestCase):
    def test_static_asset_scoring(self):
        score_js = NoiseScorer.score("GET", "/static/app.js", mime_type="application/javascript")
        score_png = NoiseScorer.score("GET", "/images/logo.png", mime_type="image/png")
        self.assertGreaterEqual(score_js, 0.70)
        self.assertGreaterEqual(score_png, 0.70)
        self.assertEqual(NoiseScorer.classify(score_js), "LIKELY_NOISE")

    def test_api_post_scoring(self):
        score_api = NoiseScorer.score(
            "POST",
            "/api/v1/invite/accept",
            headers="Content-Type: application/json",
            body='{"token": "xyz123"}',
            mime_type="application/json"
        )
        self.assertLess(score_api, 0.40)
        self.assertEqual(NoiseScorer.classify(score_api), "RELEVANT")

    def test_ambiguous_endpoint_scoring(self):
        score = NoiseScorer.score("GET", "/user/dashboard", headers="Host: example.com")
        self.assertTrue(0.0 <= score <= 1.0)


class TestFlowSessionAndStep(unittest.TestCase):
    def test_session_lifecycle_and_pruning(self):
        session = FlowSession(name="Invite Flow", scope_hosts=["example.com"])
        self.assertEqual(session.status, 'IDLE')

        step1 = FlowStep("s1", 1, "GET", "example.com", "/invite", noise_score=0.1, classification="RELEVANT")
        step2 = FlowStep("s2", 2, "GET", "example.com", "/static/style.css", noise_score=0.9, classification="LIKELY_NOISE")
        step3 = FlowStep("s3", 3, "POST", "example.com", "/api/invite/accept", noise_score=0.05, classification="RELEVANT")

        session.add_step(step1)
        session.add_step(step2)
        session.add_step(step3)

        self.assertEqual(len(session.steps), 3)
        self.assertEqual(len(session.get_active_steps()), 3)

        # Prune step 2 (soft delete)
        session.prune_step("s2")
        self.assertTrue(step2.is_pruned)
        self.assertEqual(len(session.get_active_steps(include_pruned=False)), 2)

        # Summary calculations
        summary = session.get_summary()
        self.assertEqual(summary['total_steps'], 3)
        self.assertEqual(summary['active_steps'], 2)
        self.assertEqual(summary['pruned_steps'], 1)
        self.assertEqual(summary['relevant_count'], 2)

        # Restore step 2
        session.restore_step("s2")
        self.assertFalse(step2.is_pruned)
        self.assertEqual(len(session.get_active_steps(include_pruned=False)), 3)

    def test_reorder_steps(self):
        session = FlowSession(name="Reorder Test")
        step1 = FlowStep("s1", 1, "GET", "example.com", "/step1")
        step2 = FlowStep("s2", 2, "POST", "example.com", "/step2")
        session.add_step(step1)
        session.add_step(step2)

        session.reorder_step(0, 1)
        self.assertEqual(session.steps[0].step_id, "s2")
        self.assertEqual(session.steps[0].sequence_index, 1)
        self.assertEqual(session.steps[1].step_id, "s1")
        self.assertEqual(session.steps[1].sequence_index, 2)


class TestFlowCorrelator(unittest.TestCase):
    def test_token_and_json_correlation(self):
        step1 = FlowStep(
            "s1", 1, "POST", "example.com", "/api/invite/create",
            response_body='{"invite_id": "inv_9988", "token": "secret_abc"}'
        )
        step2 = FlowStep(
            "s2", 2, "POST", "example.com", "/api/invite/inv_9988/accept",
            body='{"token": "secret_abc"}'
        )

        deps = FlowCorrelator.correlate_steps([step1, step2])
        self.assertGreaterEqual(len(deps), 1)
        dep_keys = [d['key'] for d in deps]
        self.assertIn("invite_id", dep_keys)


class TestFlowCaptureManager(unittest.TestCase):
    def test_capture_lifecycle_and_scope(self):
        mgr = FlowCaptureManager()
        session = mgr.start_capture(name="Test Capture", scope_hosts=["api.example.com"])
        self.assertEqual(session.status, 'CAPTURING')

        # Ingest in-scope step
        s1 = mgr.ingest_candidate("POST", "api.example.com", "/api/auth", mime_type="application/json")
        self.assertIsNotNone(s1)
        self.assertEqual(len(session.steps), 1)

        # Ingest out-of-scope step (should be ignored)
        s2 = mgr.ingest_candidate("GET", "tracker.otherdomain.com", "/ping")
        self.assertIsNone(s2)
        self.assertEqual(len(session.steps), 1)

        mgr.pause_capture()
        self.assertEqual(session.status, 'PAUSED')

        mgr.resume_capture()
        self.assertEqual(session.status, 'CAPTURING')

        mgr.stop_capture()
        self.assertEqual(session.status, 'BASELINE_READY')


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
