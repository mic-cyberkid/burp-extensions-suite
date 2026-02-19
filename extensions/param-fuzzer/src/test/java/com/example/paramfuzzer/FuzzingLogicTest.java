package com.example.paramfuzzer;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class FuzzingLogicTest {
    private final FuzzingLogic logic = new FuzzingLogic();

    @Test
    public void testPayloadCount() {
        assertFalse(logic.getAllPayloads().isEmpty());
    }

    @Test
    public void testAnomalyDetectionStatus() {
        assertTrue(logic.isAnomaly(200, 1000, 500, 1000));
        assertFalse(logic.isAnomaly(200, 1000, 200, 1000));
    }

    @Test
    public void testAnomalyDetectionLength() {
        // 11% difference
        assertTrue(logic.isAnomaly(200, 1000, 200, 1110));
        // 5% difference
        assertFalse(logic.isAnomaly(200, 1000, 200, 1050));
    }
}
