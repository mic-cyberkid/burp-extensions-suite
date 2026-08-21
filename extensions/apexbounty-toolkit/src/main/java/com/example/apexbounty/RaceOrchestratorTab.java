package com.example.apexbounty;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

public class RaceOrchestratorTab {

    private final MontoyaApi api;
    private final JPanel panel;
    private final JTextField txtThreads;
    private final JTextField txtDelay;
    private final JButton btnRunRace;
    private final DefaultTableModel resultsTableModel;

    private final HttpRequestEditor editorA;
    private final HttpRequestEditor editorB;
    private final HttpResponseEditor respEditor;

    private HttpRequest reqA;
    private HttpRequest reqB;

    private final List<RaceRecord> raceResults = new CopyOnWriteArrayList<>();

    private static class RaceRecord {
        final String target;
        final String threadId;
        final String status;
        final String length;
        final String anomalyFlag;
        final String note;
        final HttpResponse response;

        RaceRecord(String target, String threadId, String status, String length, String anomalyFlag, String note, HttpResponse response) {
            this.target = target;
            this.threadId = threadId;
            this.status = status;
            this.length = length;
            this.anomalyFlag = anomalyFlag;
            this.note = note;
            this.response = response;
        }
    }

    private static class AnomalyCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String statusVal = String.valueOf(table.getModel().getValueAt(row, 2));
            String flagVal = String.valueOf(table.getModel().getValueAt(row, 4));

            if (!isSelected) {
                if (statusVal.contains("500") || flagVal.contains("Server Error") || statusVal.contains("ERROR")) {
                    c.setBackground(new Color(255, 210, 210)); // Soft Red
                    c.setForeground(Color.BLACK);
                } else if ("Yes".equals(flagVal) || flagVal.contains("Deviating")) {
                    c.setBackground(new Color(255, 255, 200)); // Soft Yellow
                    c.setForeground(Color.BLACK);
                } else {
                    c.setBackground(Color.WHITE);
                    c.setForeground(Color.BLACK);
                }
            }
            return c;
        }
    }

    public RaceOrchestratorTab(MontoyaApi api) {
        this.api = api;
        this.panel = new JPanel(new BorderLayout());

        // Top Controls Bar
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JLabel lblTitle = new JLabel("Multi-Endpoint Race Orchestrator");
        Font font = lblTitle.getFont();
        if (font != null) {
            lblTitle.setFont(font.deriveFont(Font.BOLD, 14.0f));
        }

        controlPanel.add(lblTitle);
        controlPanel.add(new JSeparator(JSeparator.VERTICAL));

        controlPanel.add(new JLabel("Threads per Endpoint (max 100):"));
        txtThreads = new JTextField("10", 5);
        controlPanel.add(txtThreads);

        controlPanel.add(new JLabel("Delay (ms):"));
        txtDelay = new JTextField("0", 5);
        controlPanel.add(txtDelay);

        btnRunRace = new JButton("Run Race Attack");
        btnRunRace.addActionListener(e -> onRunRace());
        controlPanel.add(btnRunRace);

        // Requests Editors
        editorA = api.userInterface().createHttpRequestEditor();
        editorB = api.userInterface().createHttpRequestEditor();

        JPanel panelA = new JPanel(new BorderLayout());
        panelA.add(new JLabel(" Target Request A (Send via context menu)"), BorderLayout.NORTH);
        panelA.add(editorA.uiComponent(), BorderLayout.CENTER);

        JPanel panelB = new JPanel(new BorderLayout());
        panelB.add(new JLabel(" Target Request B (Send via context menu)"), BorderLayout.NORTH);
        panelB.add(editorB.uiComponent(), BorderLayout.CENTER);

        JSplitPane reqSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panelA, panelB);
        reqSplit.setResizeWeight(0.5);

        // Results Section
        resultsTableModel = new DefaultTableModel(
                new Object[]{"Target", "Thread ID", "Status", "Content Length", "Anomaly Flag", "Note"}, 0
        );
        JTable resultsTable = new JTable(resultsTableModel);
        AnomalyCellRenderer renderer = new AnomalyCellRenderer();
        for (int col = 0; col < 6; col++) {
            resultsTable.getColumnModel().getColumn(col).setCellRenderer(renderer);
        }

        respEditor = api.userInterface().createHttpResponseEditor();

        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = resultsTable.getSelectedRow();
            if (row >= 0 && row < raceResults.size()) {
                RaceRecord rec = raceResults.get(row);
                if (rec.response != null) {
                    respEditor.setResponse(rec.response);
                }
            }
        });

        JScrollPane resScroll = new JScrollPane(resultsTable);

        JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, resScroll, respEditor.uiComponent());
        bottomSplit.setResizeWeight(0.6);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqSplit, bottomSplit);
        mainSplit.setResizeWeight(0.4);

        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(mainSplit, BorderLayout.CENTER);
    }

    public Component getComponent() {
        return panel;
    }

    public void setRequestA(HttpRequest request) {
        this.reqA = request;
        editorA.setRequest(request);
    }

    public void setRequestB(HttpRequest request) {
        this.reqB = request;
        editorB.setRequest(request);
    }

    private void onRunRace() {
        if (reqA == null) {
            JOptionPane.showMessageDialog(panel, "Request A is not set. Please set Request A first.");
            return;
        }

        if (reqB == null) {
            reqB = reqA;
            editorB.setRequest(reqB);
        }

        int threadsPerEndpoint;
        int delayMs;
        try {
            threadsPerEndpoint = Integer.parseInt(txtThreads.getText().trim());
            threadsPerEndpoint = Math.min(Math.max(1, threadsPerEndpoint), 100);
            delayMs = Integer.parseInt(txtDelay.getText().trim());
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(panel, "Threads and Delay must be valid integers.");
            return;
        }

        btnRunRace.setEnabled(false);
        resultsTableModel.setRowCount(0);
        raceResults.clear();

        int finalThreads = threadsPerEndpoint;
        int finalDelay = delayMs;
        Thread t = new Thread(() -> raceOrchestratorThread(finalThreads, finalDelay));
        t.setDaemon(true);
        t.start();
    }

    private void raceOrchestratorThread(int threadsPerEndpoint, int delayMs) {
        try {
            int totalThreads = threadsPerEndpoint * 2;
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(totalThreads);

            Set<Integer> baselineLengths = new HashSet<>();

            // Pre-flight baseline request
            try {
                HttpRequestResponse baseRespA = api.http().sendRequest(reqA);
                if (baseRespA != null && baseRespA.response() != null) {
                    baselineLengths.add(baseRespA.response().body().length());
                }
                HttpRequestResponse baseRespB = api.http().sendRequest(reqB);
                if (baseRespB != null && baseRespB.response() != null) {
                    baselineLengths.add(baseRespB.response().body().length());
                }
            } catch (Exception ignored) {
            }

            Runnable workerTask = () -> {
                try {
                    startLatch.await();
                    if (delayMs > 0) {
                        Thread.sleep(delayMs);
                    }
                } catch (InterruptedException ignored) {
                }
            };

            for (int i = 0; i < threadsPerEndpoint; i++) {
                final int threadNum = i + 1;

                // Worker A
                new Thread(() -> {
                    workerTask.run();
                    executeRaceRequest("Request A", reqA, "A-" + threadNum, baselineLengths, doneLatch);
                }).start();

                // Worker B
                new Thread(() -> {
                    workerTask.run();
                    executeRaceRequest("Request B", reqB, "B-" + threadNum, baselineLengths, doneLatch);
                }).start();
            }

            // Release synchronized batch!
            startLatch.countDown();
            doneLatch.await();

        } catch (Exception ex) {
            api.logging().logToError("Race Orchestrator Error: " + ex.getMessage());
        } finally {
            SwingUtilities.invokeLater(() -> btnRunRace.setEnabled(true));
        }
    }

    private void executeRaceRequest(String targetName, HttpRequest req, String threadId, Set<Integer> baselineLengths, CountDownLatch doneLatch) {
        try {
            HttpRequestResponse reqResp = api.http().sendRequest(req);
            int statusCode = 0;
            int length = 0;

            HttpResponse resp = reqResp != null ? reqResp.response() : null;
            if (resp != null) {
                statusCode = resp.statusCode();
                length = resp.body().length();
            }

            ApexToolkitLogic.RaceOrchestratorEngine.ClassificationResult res =
                    ApexToolkitLogic.RaceOrchestratorEngine.classifyRaceResponse(statusCode, length, baselineLengths);

            String flagStr = res.isAnomaly() ? "Yes" : "No";
            RaceRecord rec = new RaceRecord(targetName, threadId, String.valueOf(statusCode), String.valueOf(length), flagStr, res.getNote(), resp);
            raceResults.add(rec);

            String sStatus = String.valueOf(statusCode);
            String sLen = String.valueOf(length);
            SwingUtilities.invokeLater(() -> resultsTableModel.addRow(new Object[]{targetName, threadId, sStatus, sLen, flagStr, res.getNote()}));
        } catch (Exception ex) {
            String errStatus = "ERROR";
            String note = "Error: " + ex.getMessage();
            RaceRecord rec = new RaceRecord(targetName, threadId, errStatus, "0", "Yes", note, null);
            raceResults.add(rec);

            SwingUtilities.invokeLater(() -> resultsTableModel.addRow(new Object[]{targetName, threadId, errStatus, "0", "Yes", note}));
        } finally {
            doneLatch.countDown();
        }
    }
}
