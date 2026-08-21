package com.example.apexbounty;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ApexBountyToolkit implements BurpExtension, ProxyRequestHandler, ContextMenuItemsProvider {

    private MontoyaApi api;
    private JTabbedPane mainTabbedPane;
    private LogicBreakerTab logicBreakerTab;
    private LLMFuzzerTab llmFuzzerTab;
    private RaceOrchestratorTab raceOrchestratorTab;
    private PrivilegeMatrixTab privilegeMatrixTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("ApexBountyToolkit");

        this.logicBreakerTab = new LogicBreakerTab(api);
        this.llmFuzzerTab = new LLMFuzzerTab(api);
        this.raceOrchestratorTab = new RaceOrchestratorTab(api);
        this.privilegeMatrixTab = new PrivilegeMatrixTab(api);

        this.mainTabbedPane = new JTabbedPane();
        this.mainTabbedPane.addTab("Logic Breaker", logicBreakerTab.getComponent());
        this.mainTabbedPane.addTab("LLM Context Fuzzer", llmFuzzerTab.getComponent());
        this.mainTabbedPane.addTab("Race Orchestrator", raceOrchestratorTab.getComponent());
        this.mainTabbedPane.addTab("Privilege Matrix", privilegeMatrixTab.getComponent());

        api.userInterface().registerSuiteTab("Apex Toolkit", mainTabbedPane);
        api.proxy().registerRequestHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);

        api.logging().logToOutput("[+] ApexBountyToolkit (Montoya API Java Edition) successfully initialized!");
    }

    // -------------------------------------------------------------------------
    // ProxyRequestHandler Implementation
    // -------------------------------------------------------------------------
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        privilegeMatrixTab.handleProxyRequest(interceptedRequest);
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    // -------------------------------------------------------------------------
    // ContextMenuItemsProvider Implementation
    // -------------------------------------------------------------------------
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuList = new ArrayList<>();
        List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
        if (selectedMessages == null || selectedMessages.isEmpty()) {
            return menuList;
        }

        HttpRequestResponse firstMessage = selectedMessages.get(0);

        // 1. Send to Logic Breaker
        JMenuItem itemLogicBreaker = new JMenuItem("Send to Logic Breaker");
        itemLogicBreaker.addActionListener(e -> {
            logicBreakerTab.addRequest(firstMessage.request());
            mainTabbedPane.setSelectedComponent(logicBreakerTab.getComponent());
        });
        menuList.add(itemLogicBreaker);

        // 2. Send to LLM Fuzzer
        JMenuItem itemLlmFuzzer = new JMenuItem("Send to LLM Fuzzer");
        itemLlmFuzzer.addActionListener(e -> {
            llmFuzzerTab.setTargetRequest(firstMessage.request());
            mainTabbedPane.setSelectedComponent(llmFuzzerTab.getComponent());
        });
        menuList.add(itemLlmFuzzer);

        // 3. Send to Race Orchestrator A
        JMenuItem itemRaceA = new JMenuItem("Send to Race Orchestrator (Request A)");
        itemRaceA.addActionListener(e -> {
            raceOrchestratorTab.setRequestA(firstMessage.request());
            mainTabbedPane.setSelectedComponent(raceOrchestratorTab.getComponent());
        });
        menuList.add(itemRaceA);

        // 4. Send to Race Orchestrator B
        JMenuItem itemRaceB = new JMenuItem("Send to Race Orchestrator (Request B)");
        itemRaceB.addActionListener(e -> {
            raceOrchestratorTab.setRequestB(firstMessage.request());
            mainTabbedPane.setSelectedComponent(raceOrchestratorTab.getComponent());
        });
        menuList.add(itemRaceB);

        return menuList;
    }
}
