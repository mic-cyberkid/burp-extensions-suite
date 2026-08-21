package com.example.apexbounty;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class LogicBreakerTab {

    private final MontoyaApi api;
    private final JPanel panel;
    private final JButton btnAttack;
    private final JButton btnStop;
    private final JButton btnClear;
    private final JLabel lblStatus;
    private final DefaultTableModel seqTableModel;
    private final DefaultTableModel resultsTableModel;

    private final List<ApexToolkitLogic.LogicBreakerEngine.Step> recordedSteps = new CopyOnWriteArrayList<>();
    private volatile boolean isAttacking = false;

    public LogicBreakerTab(MontoyaApi api) {
        this.api = api;
        this.panel = new JPanel(new BorderLayout());

        // Top Control Panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JLabel lblTitle = new JLabel("State-Aware Logic Breaker");
        Font font = lblTitle.getFont();
        if (font != null) {
            lblTitle.setFont(font.deriveFont(Font.BOLD, 14.0f));
        }

        btnAttack = new JButton("Run Permutation Attack");
        btnAttack.addActionListener(e -> onRunAttack());

        btnStop = new JButton("Stop Attack");
        btnStop.setEnabled(False());
        btnStop.addActionListener(e -> onStopAttack());

        btnClear = new JButton("Clear Sequence");
        btnClear.addActionListener(e -> onClearSequence());

        lblStatus = new JLabel("Sequence Count: 0");

        controlPanel.add(lblTitle);
        controlPanel.add(new JSeparator(JSeparator.VERTICAL));
        controlPanel.add(btnAttack);
        controlPanel.add(btnStop);
        controlPanel.add(btnClear);
        controlPanel.add(lblStatus);

        // Sequence Table
        seqTableModel = new DefaultTableModel(new Object[]{"Step #", "Method", "Host", "Path"}, 0);
        JTable seqTable = new JTable(seqTableModel);
        JScrollPane seqScroll = new JScrollPane(seqTable);

        JPanel seqPanel = new JPanel(new BorderLayout());
        seqPanel.add(new JLabel("  Recorded Sequence Steps (Send from Proxy / Repeater context menu)"), BorderLayout.NORTH);
        seqPanel.add(seqScroll, BorderLayout.CENTER);

        // Results Table
        resultsTableModel = new DefaultTableModel(new Object[]{"Permutation", "Description", "Steps Executed", "Final Status", "Final Length"}, 0);
        JTable resultsTable = new JTable(resultsTableModel);
        JScrollPane resScroll = new JScrollPane(resultsTable);

        JPanel resPanel = new JPanel(new BorderLayout());
        resPanel.add(new JLabel("  Permutation Attack Results"), BorderLayout.NORTH);
        resPanel.add(resScroll, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, seqPanel, resPanel);
        splitPane.setResizeWeight(0.4);

        panel.add(controlPanel, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);
    }

    private boolean False() { return false; }

    public Component getComponent() {
        return panel;
    }

    public void addRequest(HttpRequest request) {
        if (request == null) return;

        String method = request.method();
        String host = request.httpService() != null ? request.httpService().host() : "N/A";
        String path = request.path() != null ? request.path() : "/";
        String stepName = method + " " + path;

        ApexToolkitLogic.LogicBreakerEngine.Step step = new ApexToolkitLogic.LogicBreakerEngine.Step(stepName, request);
        recordedSteps.add(step);

        int stepNum = recordedSteps.size();
        SwingUtilities.invokeLater(() -> {
            seqTableModel.addRow(new Object[]{String.valueOf(stepNum), method, host, path});
            lblStatus.setText("Sequence Count: " + stepNum);
        });
    }

    private void onClearSequence() {
        recordedSteps.clear();
        seqTableModel.setRowCount(0);
        resultsTableModel.setRowCount(0);
        lblStatus.setText("Sequence Count: 0");
    }

    private void onStopAttack() {
        isAttacking = false;
        btnStop.setEnabled(false);
    }

    private void onRunAttack() {
        if (recordedSteps.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Please send at least one request to the Logic Breaker sequence first.");
            return;
        }

        if (isAttacking) return;

        // Scope Safety Check
        long outOfScopeCount = recordedSteps.stream()
                .filter(step -> step.getRequest().url() != null && !api.scope().isInScope(step.getRequest().url()))
                .count();

        if (outOfScopeCount > 0) {
            int confirm = JOptionPane.showConfirmDialog(
                    panel,
                    "Warning: " + outOfScopeCount + " target request(s) are OUT OF SCOPE.\nDo you want to proceed anyway?",
                    "Scope Safety Warning",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );
            if (confirm != JOptionPane.YES_OPTION) {
                return;
            }
        }

        isAttacking = true;
        btnAttack.setEnabled(false);
        btnStop.setEnabled(true);
        resultsTableModel.setRowCount(0);

        Thread t = new Thread(this::executeAttackThread);
        t.setDaemon(true);
        t.start();
    }

    private void executeAttackThread() {
        try {
            List<ApexToolkitLogic.LogicBreakerEngine.Permutation> permutations =
                    ApexToolkitLogic.LogicBreakerEngine.generatePermutations(recordedSteps);

            for (ApexToolkitLogic.LogicBreakerEngine.Permutation perm : permutations) {
                if (!isAttacking) break;

                String name = perm.getName();
                String desc = perm.getDescription();
                List<ApexToolkitLogic.LogicBreakerEngine.Step> seq = perm.getSequence();
                String stepsStr = seq.size() + " steps";

                String finalStatus = "N/A";
                String finalLength = "N/A";

                for (ApexToolkitLogic.LogicBreakerEngine.Step step : seq) {
                    if (!isAttacking) break;

                    try {
                        HttpRequestResponse reqResp = api.http().sendRequest(step.getRequest());
                        if (reqResp != null && reqResp.response() != null) {
                            HttpResponse resp = reqResp.response();
                            finalStatus = String.valueOf(resp.statusCode());
                            finalLength = String.valueOf(resp.body().length());
                        }
                    } catch (Exception ex) {
                        finalStatus = "Error: " + ex.getMessage();
                    }
                }

                String sStatus = finalStatus;
                String sLength = finalLength;
                SwingUtilities.invokeLater(() -> resultsTableModel.addRow(new Object[]{name, desc, stepsStr, sStatus, sLength}));
            }
        } finally {
            isAttacking = false;
            SwingUtilities.invokeLater(() -> {
                btnAttack.setEnabled(true);
                btnStop.setEnabled(false);
            });
        }
    }
}
