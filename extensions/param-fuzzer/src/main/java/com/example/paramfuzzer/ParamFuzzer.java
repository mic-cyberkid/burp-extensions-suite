package com.example.paramfuzzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.intruder.*;
import burp.api.montoya.core.ByteArray;

public class ParamFuzzer implements BurpExtension {
    private MontoyaApi api;
    private FuzzingLogic logic;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logic = new FuzzingLogic();

        api.extension().setName("Automated Parameter Fuzzer");

        // Register a payload generator for Intruder
        api.intruder().registerPayloadGeneratorProvider(new FuzzerPayloadGeneratorProvider());

        // Register a payload processor
        api.intruder().registerPayloadProcessor(new FuzzerPayloadProcessor());

        api.logging().logToOutput("Automated Parameter Fuzzer loaded.");
    }

    private class FuzzerPayloadGeneratorProvider implements PayloadGeneratorProvider {
        @Override
        public String displayName() {
            return "Smart Fuzzer Payloads";
        }

        @Override
        public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration) {
            return new FuzzerPayloadGenerator();
        }
    }

    private class FuzzerPayloadGenerator implements PayloadGenerator {
        private int index = 0;
        private final java.util.List<String> payloads = logic.getAllPayloads();

        @Override
        public GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint) {
            if (index < payloads.size()) {
                return GeneratedPayload.payload(payloads.get(index++));
            }
            return GeneratedPayload.end();
        }
    }

    private class FuzzerPayloadProcessor implements PayloadProcessor {
        @Override
        public String displayName() {
            return "Fuzzer Processor";
        }

        @Override
        public PayloadProcessingResult processPayload(PayloadData payloadData) {
            // Can perform transformations here if needed
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }
    }
}
