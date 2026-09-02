# -*- coding: utf-8 -*-
"""
Fieldbook.py - Main Burp Suite Extender entry point for Fieldbook.
Implements IBurpExtender, ITab, IContextMenuFactory, and IExtensionStateListener.
"""

import sys
import os
import base64

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

from FieldbookLogic import FieldbookEntry, FieldbookStore
from FieldbookUI import (
    FieldbookTab,
    QuickCaptureDialog,
    to_b64,
    from_b64,
    HAS_GUI
)

# Burp Extender API interface imports
try:
    from burp import IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener, IMenuItemHandler
    from javax.swing import JMenuItem, SwingUtilities
    from java.util import ArrayList
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False


class SendToFieldbookActionListener(object):
    def __init__(self, ext_instance, messages):
        self.ext = ext_instance
        self.messages = messages

    def actionPerformed(self, event):
        linked_reqs = []
        for idx, msg in enumerate(self.messages):
            svc = msg.getHttpService()
            host = svc.getHost() if svc else ""
            port = svc.getPort() if svc else 80
            protocol = svc.getProtocol() if svc else "http"

            req_bytes = msg.getRequest()
            resp_bytes = msg.getResponse()

            method = "HTTP"
            path = "/"
            url = ""

            if req_bytes and self.ext._helpers:
                try:
                    req_info = self.ext._helpers.analyzeRequest(svc, req_bytes)
                    method = req_info.getMethod()
                    url_obj = req_info.getUrl()
                    if url_obj:
                        url = str(url_obj)
                        path = url_obj.getPath()
                        if url_obj.getQuery():
                            path += "?" + url_obj.getQuery()
                except Exception:
                    pass

            if not url and host:
                url = protocol + "://" + host + ((":" + str(port)) if port not in (80, 443) else "") + path

            linked_reqs.append({
                "id": idx + 1,
                "method": method,
                "host": host,
                "path": path,
                "url": url,
                "request_bytes_b64": to_b64(req_bytes),
                "response_bytes_b64": to_b64(resp_bytes),
                "http_service": {
                    "host": host,
                    "port": port,
                    "protocol": protocol
                }
            })

        ext_ref = self.ext
        def open_capture():
            dlg = QuickCaptureDialog(
                parent_frame=None,
                store=ext_ref._store,
                callbacks=ext_ref._callbacks,
                pre_linked_requests=linked_reqs,
                on_save_callback=ext_ref._tab._on_new_note_saved if hasattr(ext_ref, '_tab') else None
            )
            dlg.setVisible(True)

        SwingUtilities.invokeLater(open_capture)


class BurpExtender(object):
    """
    Main Fieldbook Burp Extension Class
    """
    if BURP_AVAILABLE:
        __implements__ = [IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener, IMenuItemHandler]

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Fieldbook - Research Notebook")

        # Initialize thread-safe data store and UI
        self._store = FieldbookStore()

        if HAS_GUI:
            self._tab = FieldbookTab(self._store, self._callbacks)
            callbacks.addSuiteTab(self)
            callbacks.registerContextMenuFactory(self)
            callbacks.registerMenuItem("New Fieldbook Note", self)
            callbacks.registerExtensionStateListener(self)

        print("[+] Fieldbook extension loaded successfully.")

    # ITab Implementation
    def getTabCaption(self):
        return "Fieldbook"

    def getUiComponent(self):
        return self._tab if HAS_GUI else None

    # IMenuItemHandler Implementation (Extensions / Tools menu item "New Fieldbook Note")
    def menuItemClicked(self, menuItemCaption, messageInfo):
        if HAS_GUI:
            ext_ref = self
            def show_quick_capture():
                dlg = QuickCaptureDialog(
                    parent_frame=None,
                    store=ext_ref._store,
                    callbacks=ext_ref._callbacks,
                    pre_linked_requests=[],
                    on_save_callback=ext_ref._tab._on_new_note_saved if hasattr(ext_ref, '_tab') else None
                )
                dlg.setVisible(True)
            SwingUtilities.invokeLater(show_quick_capture)

    # IContextMenuFactory Implementation ("Send to Fieldbook")
    def createMenuItems(self, invocation):
        if not HAS_GUI:
            return None

        menu_list = ArrayList()
        selected_messages = invocation.getSelectedMessages()

        if selected_messages and len(selected_messages) > 0:
            menu_item = JMenuItem("Send to Fieldbook")
            listener = SendToFieldbookActionListener(self, selected_messages)
            menu_item.addActionListener(listener)
            menu_list.add(menu_item)

        return menu_list

    # IExtensionStateListener Implementation
    def extensionUnloaded(self):
        try:
            if hasattr(self, '_store'):
                self._store.save_immediate()
            print("[+] Fieldbook state saved on extension unload.")
        except Exception as e:
            print("[-] Error saving Fieldbook state on unload: " + str(e))
