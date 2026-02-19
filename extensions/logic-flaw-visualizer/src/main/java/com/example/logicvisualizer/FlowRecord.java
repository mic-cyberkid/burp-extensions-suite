package com.example.logicvisualizer;

import java.time.LocalDateTime;

public class FlowRecord {
    private final String url;
    private final String method;
    private final int statusCode;
    private final LocalDateTime timestamp;

    public FlowRecord(String url, String method, int statusCode) {
        this.url = url;
        this.method = method;
        this.statusCode = statusCode;
        this.timestamp = LocalDateTime.now();
    }

    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public int getStatusCode() { return statusCode; }
    public LocalDateTime getTimestamp() { return timestamp; }

    @Override
    public String toString() {
        return String.format("[%d] %s %s", statusCode, method, url);
    }
}
