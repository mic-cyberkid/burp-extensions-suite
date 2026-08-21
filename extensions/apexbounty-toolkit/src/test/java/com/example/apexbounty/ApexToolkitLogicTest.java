package com.example.apexbounty;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class ApexToolkitLogicTest {

    @Test
    public void testLogicBreakerPermutations() {
        ApexToolkitLogic.LogicBreakerEngine.Step step1 = new ApexToolkitLogic.LogicBreakerEngine.Step("Step 1", null);
        ApexToolkitLogic.LogicBreakerEngine.Step step2 = new ApexToolkitLogic.LogicBreakerEngine.Step("Step 2", null);
        ApexToolkitLogic.LogicBreakerEngine.Step step3 = new ApexToolkitLogic.LogicBreakerEngine.Step("Step 3", null);

        List<ApexToolkitLogic.LogicBreakerEngine.Step> seq = Arrays.asList(step1, step2, step3);
        List<ApexToolkitLogic.LogicBreakerEngine.Permutation> perms = ApexToolkitLogic.LogicBreakerEngine.generatePermutations(seq);

        assertFalse(perms.isEmpty());

        List<String> names = new ArrayList<>();
        for (ApexToolkitLogic.LogicBreakerEngine.Permutation p : perms) {
            names.add(p.getName());
        }

        assertTrue(names.contains("Baseline (Full Sequence)"));
        assertTrue(names.contains("Drop Step 1"));
        assertTrue(names.contains("Duplicate Step 1"));
        assertTrue(names.contains("Reverse Sequence"));
        assertTrue(names.contains("Jump to Final Step"));
    }

    @Test
    public void testLogicBreakerEmptySequence() {
        List<ApexToolkitLogic.LogicBreakerEngine.Permutation> perms =
                ApexToolkitLogic.LogicBreakerEngine.generatePermutations(Collections.emptyList());
        assertTrue(perms.isEmpty());
    }

    @Test
    public void testLlmRedactSensitiveHeaders() {
        String snippet = "POST /api/test HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Authorization: Bearer secret_123\r\n" +
                "Cookie: session=abc_456\r\n" +
                "X-API-Key: key_789\r\n" +
                "Content-Type: application/json\r\n\r\n" +
                "{\"user\": 1}";

        String redacted = ApexToolkitLogic.LLMFuzzerEngine.redactSensitiveHeaders(snippet);

        assertFalse(redacted.contains("secret_123"));
        assertFalse(redacted.contains("abc_456"));
        assertFalse(redacted.contains("key_789"));
        assertTrue(redacted.contains("Authorization: [REDACTED]"));
        assertTrue(redacted.contains("Cookie: [REDACTED]"));
        assertTrue(redacted.contains("X-API-Key: [REDACTED]"));
    }

    @Test
    public void testLlmBuildPrompt() {
        String prompt = ApexToolkitLogic.LLMFuzzerEngine.buildPrompt("role", "POST /api/user HTTP/1.1\r\nAuthorization: Bearer secret\r\n");

        assertTrue(prompt.contains("role"));
        assertTrue(prompt.contains("WAF bypass"));
        assertFalse(prompt.contains("secret"));
        assertTrue(prompt.contains("Authorization: [REDACTED]"));
    }

    @Test
    public void testLlmParsePayloads() {
        String responseText = "Here are payloads:\n[\"' OR 1=1--\", \"admin'--\", \"<script>alert(1)</script>\"]";
        List<String> payloads = ApexToolkitLogic.LLMFuzzerEngine.parseLlmPayloads(responseText);

        assertEquals(3, payloads.size());
        assertEquals("' OR 1=1--", payloads.get(0));
    }

    @Test
    public void testLlmParsePayloadsMarkdownFence() {
        String fenced = "```json\n[\"payload_1\", \"payload_2\"]\n```";
        List<String> payloads = ApexToolkitLogic.LLMFuzzerEngine.parseLlmPayloads(fenced);

        assertEquals(2, payloads.size());
        assertEquals("payload_1", payloads.get(0));
    }

    @Test
    public void testRaceOrchestratorClassifyResponse() {
        Set<Integer> baselines = new HashSet<>(Arrays.asList(50, 60));

        ApexToolkitLogic.RaceOrchestratorEngine.ClassificationResult res500 =
                ApexToolkitLogic.RaceOrchestratorEngine.classifyRaceResponse(500, 100, baselines);
        assertTrue(res500.isAnomaly());
        assertTrue(res500.getNote().contains("500"));

        ApexToolkitLogic.RaceOrchestratorEngine.ClassificationResult resNormal =
                ApexToolkitLogic.RaceOrchestratorEngine.classifyRaceResponse(200, 50, baselines);
        assertFalse(resNormal.isAnomaly());

        ApexToolkitLogic.RaceOrchestratorEngine.ClassificationResult resDeviating =
                ApexToolkitLogic.RaceOrchestratorEngine.classifyRaceResponse(200, 120, baselines);
        assertTrue(resDeviating.isAnomaly());
        assertTrue(resDeviating.getNote().contains("Deviating Content Length (120)"));
    }

    @Test
    public void testPrivilegeMatrixClassifyStatusCode() {
        assertEquals("SUCCESS", ApexToolkitLogic.PrivilegeMatrixEngine.classifyStatusCode(200));
        assertEquals("DENIED", ApexToolkitLogic.PrivilegeMatrixEngine.classifyStatusCode(403));
        assertEquals("REDIRECT", ApexToolkitLogic.PrivilegeMatrixEngine.classifyStatusCode(302));
        assertEquals("ERROR", ApexToolkitLogic.PrivilegeMatrixEngine.classifyStatusCode(500));
    }
}
