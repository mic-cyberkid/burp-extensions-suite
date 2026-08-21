package com.example.apexbounty;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

public class PrivilegeMatrixTab {

    private final MontoyaApi api;
    private final JPanel panel;
    private final JCheckBox chkEnable;
    private final JCheckBox chkStateChanging;
    private final JButton btnClear;

    private final JTextArea txtAdmin;
    private final JTextArea txtUserA;
    private final JTextArea txtUserB;
    private final JTextArea txtUnauth;

    private final DefaultTableModel matrixTableModel;
    private final JTabbedPane detailTabbedPane;
    private final Map<String, HttpResponseEditor> roleViewers = new HashMap<>();

    private final List<MatrixRecord> matrixRecords = new CopyOnWriteArrayList<>();
    private volatile boolean isEnabled = false;

    private static class MatrixRecord {
        final String method;
        final String path;
        final Map<String, String> statuses;
        final Map<String, HttpResponse> responses;

        MatrixRecord(String method, String path, Map<String, String> statuses, Map<String, HttpResponse> responses) {
            this.method = method;
            this.path = path;
            this.statuses = statuses;
            this.responses = responses;
        }
    }

    private static class StatusColorCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String valStr = value != null ? String.valueOf(value) : "";

            if (!isSelected && column >= 2) {
                if (valStr.contains("200") || valStr.contains("201") || valStr.contains("204")) {
                    cell.setBackground(new Color(200, 245, 200)); // Soft Green
                    cell.setForeground(Color.BLACK);
                } else if (valStr.contains("401") || valStr.contains("403")) {
                    cell.setBackground(new Color(255, 210, 210)); // Soft Red
                    cell.setForeground(Color.BLACK);
                } else if (valStr.contains("301") || valStr.contains("302")) {
                    cell.setBackground(new Color(255, 255, 200)); // Soft Yellow
                    cell.setForeground(Color.BLACK);
                } else if (valStr.contains("500") || valStr.contains("502") || valStr.contains("Error")) {
                    cell.setBackground(new Color(255, 220, 180)); // Soft Orange
                    cell.setForeground(Color.BLACK);
                } else {
                    cell.setBackground(Color.WHITE);
                    cell.setForeground(Color.BLACK);
                }
            }
            return cell;
        }
    }

    public PrivilegeMatrixTab(MontoyaApi api) {
        this.api = api;
        this.panel = new JPanel(new BorderLayout());

        // Initialize table model first
        matrixTableModel = new DefaultTableModel(
                new Object[]{"Method", "Path / Endpoint", "Admin Status", "User A Status", "User B Status", "Unauth Status"}, 0
        );

        JPanel topContainer = new JPanel(new BorderLayout());

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        JLabel lblTitle = new JLabel("Dynamic Privilege Matrix (BOLA / IDOR)");
        Font font = lblTitle.getFont();
        if (font != null) {
            lblTitle.setFont(font.deriveFont(Font.BOLD, 14.0f));
        }

        chkEnable = new JCheckBox("Enable Background Matrix Replay", false);
        chkEnable.addActionListener(e -> isEnabled = chkEnable.isSelected());

        chkStateChanging = new JCheckBox("Replay State-Changing Methods (POST/PUT/DELETE)", false);

        btnClear = new JButton("Clear Matrix Log");
        btnClear.addActionListener(e -> {
            matrixTableModel.setRowCount(0);
            matrixRecords.clear();
        });

        controlPanel.add(lblTitle);
        controlPanel.add(new JSeparator(JSeparator.VERTICAL));
        controlPanel.add(chkEnable);
        controlPanel.add(chkStateChanging);
        controlPanel.add(btnClear);

        // Role Config Grid
        JPanel gridPanel = new JPanel(new GridLayout(1, 4, 5, 5));
        gridPanel.setBorder(BorderFactory.createTitledBorder(" Role Auth Headers Configuration "));

        txtAdmin = new JTextArea("Authorization: Bearer ADMIN_TOKEN_HERE\nCookie: session=admin_sess", 3, 20);
        txtUserA = new JTextArea("Authorization: Bearer USER_A_TOKEN_HERE\nCookie: session=user_a_sess", 3, 20);
        txtUserB = new JTextArea("Authorization: Bearer USER_B_TOKEN_HERE\nCookie: session=user_b_sess", 3, 20);
        txtUnauth = new JTextArea("# Unauth: Strips all auth headers", 3, 20);

        gridPanel.add(createRoleBox("Role 1: Admin", txtAdmin));
        gridPanel.add(createRoleBox("Role 2: User A", txtUserA));
        gridPanel.add(createRoleBox("Role 3: User B", txtUserB));
        gridPanel.add(createRoleBox("Role 4: Unauth", txtUnauth));

        topContainer.add(controlPanel, BorderLayout.NORTH);
        topContainer.add(gridPanel, BorderLayout.SOUTH);

        // Results Table
        JTable matrixTable = new JTable(matrixTableModel);
        StatusColorCellRenderer renderer = new StatusColorCellRenderer();
        for (int c = 0; c < 6; c++) {
            matrixTable.getColumnModel().getColumn(c).setCellRenderer(renderer);
        }

        matrixTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int row = matrixTable.getSelectedRow();
            if (row >= 0 && row < matrixRecords.size()) {
                MatrixRecord rec = matrixRecords.get(row);
                for (Map.Entry<String, HttpResponseEditor> entry : roleViewers.entrySet()) {
                    String roleName = entry.getKey();
                    HttpResponseEditor editor = entry.getValue();
                    HttpResponse resp = rec.responses.get(roleName);
                    if (resp != null) {
                        editor.setResponse(resp);
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(matrixTable);

        detailTabbedPane = new JTabbedPane();
        String[] roles = new String[]{"Admin", "User A", "User B", "Unauth"};
        for (String role : roles) {
            HttpResponseEditor editor = api.userInterface().createHttpResponseEditor();
            roleViewers.put(role, editor);
            detailTabbedPane.addTab(role + " Response", editor.uiComponent());
        }

        JSplitPane centerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabbedPane);
        centerSplit.setResizeWeight(0.5);

        panel.add(topContainer, BorderLayout.NORTH);
        panel.add(centerSplit, BorderLayout.CENTER);
    }

    private JPanel createRoleBox(String title, JTextArea textArea) {
        JPanel box = new JPanel(new BorderLayout());
        box.setBorder(BorderFactory.createTitledBorder(title));
        box.add(new JScrollPane(textArea), BorderLayout.CENTER);
        return box;
    }

    public Component getComponent() {
        return panel;
    }

    public void handleProxyRequest(InterceptedRequest interceptedRequest) {
        if (!isEnabled || interceptedRequest == null) return;

        HttpRequest request = interceptedRequest;
        if (request.url() == null) return;

        // Target scope check
        if (!api.scope().isInScope(request.url())) {
            return;
        }

        String method = request.method() != null ? request.method().toUpperCase() : "";
        if (isStateChanging(method) && !chkStateChanging.isSelected()) {
            return;
        }

        String path = request.path() != null ? request.path() : "/";
        if (isStaticAsset(path)) {
            return;
        }

        Thread t = new Thread(() -> replayMatrixThread(request, method, path));
        t.setDaemon(true);
        t.start();
    }

    private boolean isStateChanging(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method) || "PATCH".equals(method);
    }

    private boolean isStaticAsset(String path) {
        String lower = path.toLowerCase();
        return lower.endsWith(".js") || lower.endsWith(".css") || lower.endsWith(".png") ||
                lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".gif") ||
                lower.endsWith(".svg") || lower.endsWith(".ico") || lower.endsWith(".woff") || lower.endsWith(".woff2");
    }

    private void replayMatrixThread(HttpRequest baseRequest, String method, String path) {
        String[][] rolesConfig = new String[][]{
                {"Admin", txtAdmin.getText()},
                {"User A", txtUserA.getText()},
                {"User B", txtUserB.getText()},
                {"Unauth", txtUnauth.getText()}
        };

        Map<String, String> roleStatuses = new HashMap<>();
        Map<String, HttpResponse> roleResponses = new HashMap<>();

        for (String[] roleConfig : rolesConfig) {
            String roleName = roleConfig[0];
            String roleHeaders = roleConfig[1];

            HttpRequest modifiedReq = ApexToolkitLogic.PrivilegeMatrixEngine.applyRoleHeaders(baseRequest, roleHeaders);

            try {
                HttpRequestResponse reqResp = api.http().sendRequest(modifiedReq);
                HttpResponse resp = reqResp != null ? reqResp.response() : null;
                if (resp != null) {
                    roleStatuses.put(roleName, String.valueOf(resp.statusCode()));
                    roleResponses.put(roleName, resp);
                } else {
                    roleStatuses.put(roleName, "Error");
                    roleResponses.put(roleName, null);
                }
            } catch (Exception ex) {
                roleStatuses.put(roleName, "Error: " + ex.getMessage());
                roleResponses.put(roleName, null);
            }
        }

        MatrixRecord record = new MatrixRecord(method, path, roleStatuses, roleResponses);
        matrixRecords.add(record);

        SwingUtilities.invokeLater(() -> matrixTableModel.addRow(new Object[]{
                method,
                path,
                roleStatuses.getOrDefault("Admin", "N/A"),
                roleStatuses.getOrDefault("User A", "N/A"),
                roleStatuses.getOrDefault("User B", "N/A"),
                roleStatuses.getOrDefault("Unauth", "N/A")
        }));
    }
}
