package com.example.apexbounty;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApexToolkitLogic {

    // -------------------------------------------------------------------------
    // Logic Breaker Engine
    // -------------------------------------------------------------------------
    public static class LogicBreakerEngine {

        public static class Step {
            private final String name;
            private final HttpRequest request;

            public Step(String name, HttpRequest request) {
                this.name = name;
                this.request = request;
            }

            public String getName() {
                return name;
            }

            public HttpRequest getRequest() {
                return request;
            }
        }

        public static class Permutation {
            private final String name;
            private final String description;
            private final List<Step> sequence;

            public Permutation(String name, String description, List<Step> sequence) {
                this.name = name;
                this.description = description;
                this.sequence = sequence;
            }

            public String getName() {
                return name;
            }

            public String getDescription() {
                return description;
            }

            public List<Step> getSequence() {
                return sequence;
            }
        }

        public static List<Permutation> generatePermutations(List<Step> sequence) {
            List<Permutation> permutations = new ArrayList<>();
            if (sequence == null || sequence.isEmpty()) {
                return permutations;
            }

            int n = sequence.size();

            // 1. Baseline sequence
            permutations.add(new Permutation(
                    "Baseline (Full Sequence)",
                    "Executes full sequence as recorded (1..N)",
                    new ArrayList<>(sequence)
            ));

            // 2. Skip single steps (Drop step i)
            for (int i = 0; i < n; i++) {
                List<Step> copy = new ArrayList<>();
                for (int j = 0; j < n; j++) {
                    if (j != i) {
                        copy.add(sequence.get(j));
                    }
                }
                if (!copy.isEmpty()) {
                    String stepName = sequence.get(i).getName() != null ? sequence.get(i).getName() : "Step " + (i + 1);
                    permutations.add(new Permutation(
                            "Drop " + stepName,
                            "Drops step " + (i + 1) + " (" + stepName + ")",
                            copy
                    ));
                }
            }

            // 3. Duplicate steps (Repeat step i)
            for (int i = 0; i < n; i++) {
                List<Step> copy = new ArrayList<>(sequence.subList(0, i + 1));
                copy.add(sequence.get(i));
                copy.addAll(sequence.subList(i + 1, n));
                String stepName = sequence.get(i).getName() != null ? sequence.get(i).getName() : "Step " + (i + 1);
                permutations.add(new Permutation(
                        "Duplicate " + stepName,
                        "Executes step " + (i + 1) + " twice in succession",
                        copy
                ));
            }

            // 4. Reverse sequence
            if (n > 1) {
                List<Step> copy = new ArrayList<>(sequence);
                Collections.reverse(copy);
                permutations.add(new Permutation(
                        "Reverse Sequence",
                        "Executes sequence in reverse order (N..1)",
                        copy
                ));
            }

            // 5. Swap adjacent steps
            if (n > 1) {
                for (int i = 0; i < n - 1; i++) {
                    List<Step> copy = new ArrayList<>(sequence);
                    Collections.swap(copy, i, i + 1);
                    permutations.add(new Permutation(
                            "Swap Steps " + (i + 1) + " & " + (i + 2),
                            "Swaps execution order of step " + (i + 1) + " and step " + (i + 2),
                            copy
                    ));
                }
            }

            // 6. Direct step jump (Execute final step directly)
            if (n > 1) {
                permutations.add(new Permutation(
                        "Jump to Final Step",
                        "Executes only the final step without previous setup steps",
                        Collections.singletonList(sequence.get(n - 1))
                ));
            }

            return permutations;
        }
    }

    // -------------------------------------------------------------------------
    // LLM Fuzzer Engine
    // -------------------------------------------------------------------------
    public static class LLMFuzzerEngine {

        public static final List<String> SENSITIVE_HEADERS = Arrays.asList(
                "authorization", "cookie", "x-api-key", "api-key",
                "x-auth-token", "session", "token", "x-access-token", "bearer"
        );

        public static class ParamInfo {
            private final String name;
            private final String value;
            private final String type;

            public ParamInfo(String name, String value, String type) {
                this.name = name;
                this.value = value;
                this.type = type;
            }

            public String getName() {
                return name;
            }

            public String getValue() {
                return value;
            }

            public String getType() {
                return type;
            }
        }

        public static String redactSensitiveHeaders(String snippet) {
            if (snippet == null || snippet.isEmpty()) {
                return snippet;
            }
            String[] lines = snippet.split("\r?\n");
            StringBuilder sb = new StringBuilder();
            String delimiter = snippet.contains("\r\n") ? "\r\n" : "\n";

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (line.contains(":")) {
                    String key = line.split(":", 2)[0].trim().toLowerCase();
                    if (SENSITIVE_HEADERS.contains(key)) {
                        sb.append(line.split(":", 2)[0]).append(": [REDACTED]");
                        if (i < lines.length - 1) sb.append(delimiter);
                        continue;
                    }
                }
                sb.append(line);
                if (i < lines.length - 1) sb.append(delimiter);
            }
            return sb.toString();
        }

        public static List<ParamInfo> extractParameters(HttpRequest request) {
            List<ParamInfo> params = new ArrayList<>();
            if (request == null) {
                return params;
            }

            List<ParsedHttpParameter> parsedParams = request.parameters();
            if (parsedParams != null) {
                for (ParsedHttpParameter p : parsedParams) {
                    params.add(new ParamInfo(p.name(), p.value(), p.type().name()));
                }
            }

            return params;
        }

        public static String buildPrompt(String targetParam, String baseRequestSnippet) {
            String safeSnippet = redactSensitiveHeaders(baseRequestSnippet);
            if (safeSnippet != null && safeSnippet.length() > 300) {
                safeSnippet = safeSnippet.substring(0, 300);
            }
            return "You are an expert security researcher conducting authorized vulnerability testing.\n" +
                    "Generate 5 high-efficiency WAF bypass and security test payloads for parameter: '" + targetParam + "'.\n" +
                    "Request context snippet:\n" + safeSnippet + "\n\n" +
                    "Return ONLY a JSON array of string payloads, like:\n" +
                    "[\"payload1\", \"payload2\", \"payload3\", \"payload4\", \"payload5\"]";
        }

        public static List<String> parseLlmPayloads(String llmResponseText) {
            List<String> payloads = new ArrayList<>();
            if (llmResponseText == null || llmResponseText.trim().isEmpty()) {
                return payloads;
            }

            String text = llmResponseText.trim();
            if (text.startsWith("```")) {
                String[] lines = text.split("\r?\n");
                List<String> filtered = new ArrayList<>();
                for (int i = 0; i < lines.length; i++) {
                    if (i == 0 && lines[i].startsWith("```")) continue;
                    if (i == lines.length - 1 && lines[i].trim().equals("```")) continue;
                    filtered.add(lines[i]);
                }
                text = String.join("\n", filtered).trim();
            }

            // Simple JSON array extraction
            Pattern arrayPattern = Pattern.compile("\\[\\s*\"([^\"]*)\"(?:\\s*,\\s*\"([^\"]*)\")*\\s*\\]", Pattern.DOTALL);
            Matcher matcher = arrayPattern.matcher(text);
            if (matcher.find()) {
                Pattern itemPattern = Pattern.compile("\"([^\"]*)\"");
                Matcher itemMatcher = itemPattern.matcher(matcher.group(0));
                while (itemMatcher.find()) {
                    payloads.add(itemMatcher.group(1));
                }
                if (!payloads.isEmpty()) {
                    return payloads;
                }
            }

            // Fallback line-by-line parsing
            String[] lines = text.split("\r?\n");
            for (String line : lines) {
                String cleaned = line.trim();
                cleaned = cleaned.replaceAll("^\\d+[\\.\\)]\\s*", "");
                cleaned = cleaned.replaceAll("^[-\\*\u2022]\\s*", "");
                cleaned = cleaned.replaceAll("^[\"'`]|[\"'`]$", "").trim();
                if (!cleaned.isEmpty() && !cleaned.startsWith("{") && !cleaned.startsWith("[")) {
                    payloads.add(cleaned);
                }
            }

            if (payloads.size() > 10) {
                return payloads.subList(0, 10);
            }
            return payloads;
        }

        public static HttpRequest injectPayload(HttpRequest request, String paramName, String payload) {
            if (request == null || paramName == null) {
                return request;
            }

            // Use Montoya API parameter replacement for safe, object-level updates
            List<ParsedHttpParameter> params = request.parameters();
            if (params != null) {
                for (ParsedHttpParameter p : params) {
                    if (p.name().equals(paramName)) {
                        HttpParameter newParam = HttpParameter.parameter(paramName, payload, p.type());
                        return request.withUpdatedParameters(newParam);
                    }
                }
            }

            return request;
        }
    }

    // -------------------------------------------------------------------------
    // Race Orchestrator Engine
    // -------------------------------------------------------------------------
    public static class RaceOrchestratorEngine {

        public static class ClassificationResult {
            private final boolean anomaly;
            private final String note;

            public ClassificationResult(boolean anomaly, String note) {
                this.anomaly = anomaly;
                this.note = note;
            }

            public boolean isAnomaly() {
                return anomaly;
            }

            public String getNote() {
                return note;
            }
        }

        public static ClassificationResult classifyRaceResponse(int statusCode, int contentLength, Set<Integer> baselineLengths) {
            boolean isAnomaly = false;
            List<String> notes = new ArrayList<>();

            if (statusCode == 500) {
                isAnomaly = true;
                notes.add("Internal Server Error (500)");
            } else if (statusCode >= 500) {
                isAnomaly = true;
                notes.add("Server Error (" + statusCode + ")");
            }

            if (baselineLengths != null && !baselineLengths.isEmpty() && !baselineLengths.contains(contentLength)) {
                isAnomaly = true;
                notes.add("Deviating Content Length (" + contentLength + ")");
            }

            if (notes.isEmpty()) {
                notes.add("Normal (" + statusCode + ")");
            }

            return new ClassificationResult(isAnomaly, String.join("; ", notes));
        }
    }

    // -------------------------------------------------------------------------
    // Privilege Matrix Engine
    // -------------------------------------------------------------------------
    public static class PrivilegeMatrixEngine {

        public static final List<String> AUTH_HEADER_NAMES = Arrays.asList(
                "authorization", "cookie", "x-auth-token", "bearer",
                "api-key", "x-api-key", "session", "x-access-token"
        );

        public static HttpRequest applyRoleHeaders(HttpRequest request, String roleHeadersRaw) {
            if (request == null) {
                return null;
            }

            HttpRequest modified = request;

            // Remove existing auth headers using Montoya's native header manipulation
            List<HttpHeader> headers = request.headers();
            if (headers != null) {
                for (HttpHeader h : headers) {
                    if (AUTH_HEADER_NAMES.contains(h.name().toLowerCase())) {
                        modified = modified.withRemovedHeader(h.name());
                    }
                }
            }

            // Parse and add new role headers
            if (roleHeadersRaw != null && !roleHeadersRaw.trim().isEmpty()) {
                String[] lines = roleHeadersRaw.split("\r?\n");
                for (String line : lines) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty() && trimmed.contains(":") && !trimmed.startsWith("#")) {
                        String[] parts = trimmed.split(":", 2);
                        modified = modified.withAddedHeader(HttpHeader.httpHeader(parts[0].trim(), parts[1].trim()));
                    }
                }
            }

            return modified;
        }

        public static String classifyStatusCode(int statusCode) {
            if (statusCode >= 200 && statusCode < 300) {
                return "SUCCESS";
            } else if (statusCode == 401 || statusCode == 403) {
                return "DENIED";
            } else if (statusCode >= 300 && statusCode < 400) {
                return "REDIRECT";
            } else if (statusCode >= 500) {
                return "ERROR";
            } else {
                return "OTHER";
            }
        }
    }
}
