package com.example.logicvisualizer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class LogicFlawVisualizer implements BurpExtension {
    private MontoyaApi api;
    private final List<FlowRecord> flowRecords = new ArrayList<>();
    private DefaultTreeModel treeModel;
    private DefaultMutableTreeNode rootNode;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Logic Flaw Visualizer");

        // UI Setup
        setupUI();

        // Register HTTP Handler to capture flows
        api.http().registerHttpHandler(new FlowCaptureHandler());

        api.logging().logToOutput("Logic Flaw Visualizer loaded.");
    }

    private void setupUI() {
        rootNode = new DefaultMutableTreeNode("Recorded Logic Flows");
        treeModel = new DefaultTreeModel(rootNode);
        JTree tree = new JTree(treeModel);

        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(tree), BorderLayout.CENTER);

        JButton clearBtn = new JButton("Clear Flows");
        clearBtn.addActionListener(e -> {
            flowRecords.clear();
            rootNode.removeAllChildren();
            treeModel.reload();
        });
        panel.add(clearBtn, BorderLayout.SOUTH);

        api.userInterface().registerSuiteTab("Logic Visualizer", panel);
    }

    private class FlowCaptureHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            String url = responseReceived.initiatingRequest().url();

            // Filter for interesting auth/logic endpoints
            if (url.contains("login") || url.contains("reset") || url.contains("otp") || url.contains("verify") || url.contains("password")) {
                FlowRecord record = new FlowRecord(
                        url,
                        responseReceived.initiatingRequest().method(),
                        responseReceived.statusCode()
                );

                synchronized (flowRecords) {
                    flowRecords.add(record);
                    SwingUtilities.invokeLater(() -> {
                        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(record.toString());
                        rootNode.add(newNode);
                        treeModel.reload();
                    });
                }

                // Basic Anomaly: Check if a high-privilege action follows a suspicious status or missing step
                // (Very simplified detection logic for PoC)
                if (responseReceived.statusCode() == 200 && url.contains("password") && flowRecords.size() < 2) {
                    api.logging().logToOutput("Anomaly Detected: Password change without preceding reset/auth steps!");
                }
            }

            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}
