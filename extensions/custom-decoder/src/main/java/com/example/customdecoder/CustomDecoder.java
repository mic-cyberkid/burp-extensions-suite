package com.example.customdecoder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.core.ByteArray;

import javax.swing.*;
import java.awt.*;

public class CustomDecoder implements BurpExtension {
    private MontoyaApi api;
    private DecoderLogic logic;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logic = new DecoderLogic();

        api.extension().setName("Custom Decoder/Encoder");

        // Register a request editor provider to add a custom tab
        api.userInterface().registerHttpRequestEditorProvider(new DecoderTabProvider());

        api.logging().logToOutput("Custom Decoder/Encoder loaded.");
    }

    private class DecoderTabProvider implements HttpRequestEditorProvider {
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
            return new DecoderTab();
        }
    }

    private class DecoderTab implements ExtensionProvidedHttpRequestEditor {
        private final JPanel panel;
        private final JTextArea displayArea;
        private HttpRequestResponse requestResponse;

        public DecoderTab() {
            panel = new JPanel(new BorderLayout());
            displayArea = new JTextArea();
            displayArea.setEditable(false);

            JButton autoDetectBtn = new JButton("Auto-Detect & Decode");
            autoDetectBtn.addActionListener(e -> {
                if (requestResponse != null && requestResponse.request() != null) {
                    String body = requestResponse.request().bodyToString();
                    displayArea.setText(logic.autoDetectAndDecode(body));
                }
            });

            JPanel controls = new JPanel();
            controls.add(autoDetectBtn);

            panel.add(controls, BorderLayout.NORTH);
            panel.add(new JScrollPane(displayArea), BorderLayout.CENTER);
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            displayArea.setText("Select 'Auto-Detect' to analyze body.");
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return requestResponse != null && requestResponse.request() != null && requestResponse.request().body().length() > 0;
        }

        @Override
        public String caption() {
            return "Custom Decoder";
        }

        @Override
        public Component uiComponent() {
            return panel;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public HttpRequest getRequest() {
            return requestResponse == null ? null : requestResponse.request();
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }
}
