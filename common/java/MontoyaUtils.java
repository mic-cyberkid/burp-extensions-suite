package com.example.common;

import burp.api.montoya.MontoyaApi;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * Shared Java utilities for Burp Montoya API extensions.
 */
public class MontoyaUtils {

    /**
     * Reports a finding to a shared JSON file that the Report Generator can pick up.
     * Fallback to Burp alerts if file writing fails.
     */
    public static void reportFinding(MontoyaApi api, String name, String severity, String url, String description) {
        api.logging().logToOutput("Finding: " + name + " at " + url);

        // Simple JSON-like append to a shared file in the user's home directory
        String home = System.getProperty("user.home");
        String filePath = Paths.get(home, "burp_vuln_tracker_java.json").toString();

        try (FileWriter fw = new FileWriter(filePath, true)) {
            // Very basic manual JSON formatting for simplicity
            String finding = String.format("{\"name\": \"%s\", \"severity\": \"%s\", \"url\": \"%s\", \"description\": \"%s\", \"timestamp\": \"%s\"}\n",
                    name, severity, url, description, java.time.LocalDateTime.now().toString());
            fw.write(finding);
        } catch (IOException e) {
            api.logging().logToError("Failed to write to shared finding file: " + e.getMessage());
        }
    }
}
