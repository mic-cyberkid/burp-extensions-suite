import unittest
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from authdiff import AuthDiff

class TestAuthDiff(unittest.TestCase):
    def setUp(self):
        # Create AuthDiff instance with a mock configuration path
        self.engine = AuthDiff(config_path="extensions/authdiff/config.yaml")

    def test_normalization(self):
        text = "Order 12345: uuid 123e4567-e89b-12d3-a456-426614174000 created at 2023-10-27T12:00:00Z with key a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        normalized = self.engine.normalize_text(text)

        # Verify UUID mask
        self.assertIn("[UUID_MASK]", normalized)
        self.assertNotIn("123e4567-e89b-12d3-a456-426614174000", normalized)

        # Verify Date mask
        self.assertIn("[DATETIME_MASK]", normalized)
        self.assertNotIn("2023-10-27T12:00:00Z", normalized)

        # Verify long hex string (32 chars)
        self.assertIn("[HEX_MASK]", normalized)

        # Verify number mask
        self.assertIn("[NUM_MASK]", normalized)

    def test_json_structure_extraction(self):
        data = {
            "user": {
                "id": 1,
                "name": "Alice",
                "roles": ["admin", "user"]
            },
            "status": "active"
        }
        paths = self.engine.extract_json_structure(data)

        expected = {"user", "user.id", "user.name", "user.roles", "status"}
        self.assertEqual(paths, expected)

    def test_similarity_calculation_identical_json(self):
        res_a = {
            "status_code": 200,
            "body": '{"id": 100, "name": "Admin"}'
        }
        res_b = {
            "status_code": 200,
            "body": '{"id": 200, "name": "User"}'
        }

        score = self.engine.calculate_similarity(res_a, res_b)

        # Structural similarity should be exactly 1.0 (since they have the exact same JSON key paths)
        self.assertEqual(score["struct_sim"], 1.0)
        # Composite score should be very high due to number normalization and structural match
        self.assertGreater(score["composite_score"], 0.85)

    def test_severity_classification(self):
        orig = {"status_code": 200, "body": '{"user_id": 1}'}

        # 1. Critical Case: replayed succeeds, similarity > 85%
        replayed_critical = {"status_code": 200, "body": '{"user_id": 2}'}
        score_crit = self.engine.calculate_similarity(orig, replayed_critical)
        sev_crit = self.engine.classify_severity(orig, replayed_critical, score_crit)
        self.assertEqual(sev_crit, "CRITICAL")

        # 2. Enforced Case: replayed receives 403
        replayed_enforced = {"status_code": 403, "body": "Forbidden"}
        score_enf = self.engine.calculate_similarity(orig, replayed_enforced)
        sev_enf = self.engine.classify_severity(orig, replayed_enforced, score_enf)
        self.assertEqual(sev_enf, "INFO / ENFORCED")

        # 3. Uncertain Case: replayed succeeds but structure is entirely different (< 50%)
        replayed_uncertain = {"status_code": 200, "body": '{"error_msg": "Access Denied due to completely different page style"}'}
        score_unc = self.engine.calculate_similarity(orig, replayed_uncertain)
        sev_unc = self.engine.classify_severity(orig, replayed_uncertain, score_unc)
        self.assertEqual(sev_unc, "UNCERTAIN")

if __name__ == '__main__':
    unittest.main()
