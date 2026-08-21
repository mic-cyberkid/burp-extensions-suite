# -*- coding: utf-8 -*-
"""
ApexBountyToolkit.py - Main Entry Point for ApexBountyToolkit Burp Extension.

This module implements the core Burp Suite extension interfaces:
- IBurpExtender: Main initialization and registration with Burp Suite.
- ITab: Registers a custom top-level tab ("Apex Toolkit") in Burp Suite's UI.
- IHttpListener: Listens to HTTP traffic passing through Burp Proxy for automated privilege matrix replays.
- IContextMenuFactory: Registers right-click context menu options in Proxy, Repeater, and Target tabs.

Jython 2.7 Compatible.
"""

import sys
import os

# Safely resolve module paths for Jython in Burp Suite
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.append(current_dir)
except Exception:
    pass

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import JTabbedPane, JMenuItem, SwingUtilities
from java.util import ArrayList

from LogicBreakerTab import LogicBreakerTab
from LLMFuzzerTab import LLMFuzzerTab
from RaceOrchestratorTab import RaceOrchestratorTab
from PrivilegeMatrixTab import PrivilegeMatrixTab


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    """
    Main extension class instantiated by Burp Suite upon loading.
    Configures and orchestrates all four ApexBountyToolkit sub-tools.
    """

    def registerExtenderCallbacks(self, callbacks):
        """
        Entry point called by Burp Suite when the extension is loaded.
        Registers extension callbacks, helpers, context menus, HTTP listeners, and UI components.
        """
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Set extension name displayed in Burp's Extensions tab
        callbacks.setExtensionName("ApexBountyToolkit")

        # Initialize the 4 modular tool tab logic and UI managers
        self.logic_breaker_tab = LogicBreakerTab(callbacks, self.helpers)
        self.llm_fuzzer_tab = LLMFuzzerTab(callbacks, self.helpers)
        self.race_orchestrator_tab = RaceOrchestratorTab(callbacks, self.helpers)
        self.privilege_matrix_tab = PrivilegeMatrixTab(callbacks, self.helpers)

        # Build main tab UI on Swing EDT (Event Dispatch Thread)
        self.main_tabbed_pane = JTabbedPane()
        self.main_tabbed_pane.addTab("Logic Breaker", self.logic_breaker_tab.get_component())
        self.main_tabbed_pane.addTab("LLM Context Fuzzer", self.llm_fuzzer_tab.get_component())
        self.main_tabbed_pane.addTab("Race Orchestrator", self.race_orchestrator_tab.get_component())
        self.main_tabbed_pane.addTab("Privilege Matrix", self.privilege_matrix_tab.get_component())

        # Register top-level tab with Burp Suite UI
        callbacks.addSuiteTab(self)

        # Register HTTP listener to capture in-scope proxy requests for Privilege Matrix
        callbacks.registerHttpListener(self)

        # Register right-click Context Menu factory for sending requests to tools
        callbacks.registerContextMenuFactory(self)

        print("[+] ApexBountyToolkit successfully loaded and initialized!")

    # --------------------------------------------------------------------------
    # ITab Implementation
    # --------------------------------------------------------------------------
    def getTabCaption(self):
        """
        Returns the title displayed on the main custom tab in Burp Suite.
        """
        return "Apex Toolkit"

    def getUiComponent(self):
        """
        Returns the root Swing component to render inside Burp's main window.
        """
        return self.main_tabbed_pane

    # --------------------------------------------------------------------------
    # IHttpListener Implementation
    # --------------------------------------------------------------------------
    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        """
        Listens to HTTP traffic in Burp. Re-routes request messages from Proxy
        to the Dynamic Privilege Matrix for background privilege matrix replay.
        """
        # Listen only to request messages coming through Burp Proxy (toolFlag == 4 / TOOL_PROXY)
        if isRequest and toolFlag == self.callbacks.TOOL_PROXY:
            self.privilege_matrix_tab.handle_proxy_request(messageInfo)

    # --------------------------------------------------------------------------
    # IContextMenuFactory Implementation
    # --------------------------------------------------------------------------
    def createMenuItems(self, invocation):
        """
        Generates custom right-click context menu options when a user right-clicks
        on HTTP messages across Proxy, Repeater, Target, and Logger tabs.
        """
        menu_list = ArrayList()

        # Selected HTTP messages from invocation context
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            return menu_list

        first_message = selected_messages[0]

        # 1. Action: Send to Logic Breaker
        item_logic_breaker = JMenuItem("Send to Logic Breaker")

        def send_to_logic_breaker(e):
            self.logic_breaker_tab.add_request(
                first_message.getHttpService(),
                first_message.getRequest()
            )
            # Switch focus to Apex Toolkit -> Logic Breaker tab
            self.main_tabbed_pane.setSelectedComponent(self.logic_breaker_tab.get_component())

        item_logic_breaker.addActionListener(send_to_logic_breaker)
        menu_list.add(item_logic_breaker)

        # 1b. Action: Start Logic Breaker Flow from here
        item_start_flow = JMenuItem("Start Logic Breaker Flow from here")

        def start_flow_from_here(e):
            self.logic_breaker_tab.start_flow_from_request(
                first_message.getHttpService(),
                first_message.getRequest()
            )
            self.main_tabbed_pane.setSelectedComponent(self.logic_breaker_tab.get_component())

        item_start_flow.addActionListener(start_flow_from_here)
        menu_list.add(item_start_flow)

        # 1c. Action: Add to current Logic Breaker sequence
        item_add_seq = JMenuItem("Add to current Logic Breaker sequence")

        def add_to_seq(e):
            for msg in selected_messages:
                self.logic_breaker_tab.add_request(
                    msg.getHttpService(),
                    msg.getRequest()
                )

        item_add_seq.addActionListener(add_to_seq)
        menu_list.add(item_add_seq)

        # 2. Action: Send to LLM Context Fuzzer
        item_llm_fuzzer = JMenuItem("Send to LLM Fuzzer")

        def send_to_llm_fuzzer(e):
            self.llm_fuzzer_tab.set_target_request(
                first_message.getHttpService(),
                first_message.getRequest()
            )
            self.main_tabbed_pane.setSelectedComponent(self.llm_fuzzer_tab.get_component())

        item_llm_fuzzer.addActionListener(send_to_llm_fuzzer)
        menu_list.add(item_llm_fuzzer)

        # 3. Action: Send to Race Orchestrator A
        item_race_a = JMenuItem("Send to Race Orchestrator (Request A)")

        def send_to_race_a(e):
            self.race_orchestrator_tab.set_request_a(
                first_message.getHttpService(),
                first_message.getRequest()
            )
            self.main_tabbed_pane.setSelectedComponent(self.race_orchestrator_tab.get_component())

        item_race_a.addActionListener(send_to_race_a)
        menu_list.add(item_race_a)

        # 4. Action: Send to Race Orchestrator B
        item_race_b = JMenuItem("Send to Race Orchestrator (Request B)")

        def send_to_race_b(e):
            self.race_orchestrator_tab.set_request_b(
                first_message.getHttpService(),
                first_message.getRequest()
            )
            self.main_tabbed_pane.setSelectedComponent(self.race_orchestrator_tab.get_component())

        item_race_b.addActionListener(send_to_race_b)
        menu_list.add(item_race_b)

        return menu_list
