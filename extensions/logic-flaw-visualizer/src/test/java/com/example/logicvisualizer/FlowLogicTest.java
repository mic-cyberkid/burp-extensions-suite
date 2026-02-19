package com.example.logicvisualizer;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class FlowLogicTest {
    @Test
    public void testFlowRecordCreation() {
        FlowRecord record = new FlowRecord("http://test.com/login", "POST", 200);
        assertEquals("http://test.com/login", record.getUrl());
        assertEquals("POST", record.getMethod());
        assertEquals(200, record.getStatusCode());
        assertNotNull(record.getTimestamp());
    }
}
