"""
Context Menu Integration for Fieldbook ("Send to Fieldbook").
Captures request/response snapshots from Proxy history, Repeater, Site Map, and Logger.
"""

import logging
import threading
from datetime import datetime

try:
    from javax.swing import JMenuItem, SwingUtilities
    from java.awt.event import ActionListener
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

from fieldbook.src.ui.capture_dialog import QuickCaptureDialog

logger = logging.getLogger("Fieldbook.ContextMenu")

try:
    from datetime import timezone
    def current_iso_timestamp():
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
except ImportError:
    def current_iso_timestamp():
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def extract_request_snapshot(helpers, message_item):
    """
    Extracts a self-contained snapshot dict from an IHttpRequestResponse object.
    """
    if not message_item:
        return None

    try:
        http_service = message_item.getHttpService()
        req_bytes = message_item.getRequest()
        resp_bytes = message_item.getResponse()

        host = ""
        port = 80
        protocol = "http"
        if http_service:
            host = http_service.getHost()
            port = http_service.getPort()
            protocol = http_service.getProtocol()

        req_info = None
        method = "GET"
        url_str = ""
        if req_bytes and helpers:
            try:
                if http_service:
                    req_info = helpers.analyzeRequest(http_service, req_bytes)
                else:
                    req_info = helpers.analyzeRequest(req_bytes)
                if req_info:
                    method = req_info.getMethod()
                    try:
                        url_obj = req_info.getUrl()
                        if url_obj:
                            url_str = url_obj.toString()
                    except Exception:
                        pass
            except Exception as e:
                logger.debug("Error analyzing request info: %s", e)

        if not url_str and host:
            url_str = "%s://%s:%d" % (protocol, host, port)

        raw_req_str = ""
        if req_bytes and helpers:
            try:
                raw_req_str = helpers.bytesToString(req_bytes)
            except Exception:
                raw_req_str = str(req_bytes)

        raw_resp_str = ""
        status_code = None
        if resp_bytes and helpers:
            try:
                raw_resp_str = helpers.bytesToString(resp_bytes)
                resp_info = helpers.analyzeResponse(resp_bytes)
                if resp_info:
                    status_code = resp_info.getStatusCode()
            except Exception as ex:
                logger.debug("Error analyzing response info: %s", ex)

        # Build clean label
        path_str = url_str
        if url_str and "://" in url_str:
            path_str = url_str.split("://", 1)[1]
            if "/" in path_str:
                path_str = "/" + path_str.split("/", 1)[1]
        label = "%s %s%s" % (method, host or "target", path_str)

        return {
            "label": label,
            "method": method,
            "url": url_str,
            "host": host,
            "raw_request": raw_req_str,
            "raw_response_status": status_code,
            "raw_response_headers_and_body_or_reference": raw_resp_str,
            "captured_at": current_iso_timestamp()
        }
    except Exception as err:
        logger.error("Failed to extract request snapshot: %s", err)
        return None


class FieldbookContextMenuFactory(object):
    """
    Implements Burp's IContextMenuFactory interface for Fieldbook.
    """
    def __init__(self, callbacks, helpers, store, main_frame_getter=None, on_save_callback=None):
        self.callbacks = callbacks
        self.helpers = helpers
        self.store = store
        self.main_frame_getter = main_frame_getter
        self.on_save_callback = on_save_callback

    def createMenuItems(self, invocation):
        if not GUI_AVAILABLE or not invocation:
            return None

        selected_messages = invocation.getSelectedMessages()
        if not selected_messages or len(selected_messages) == 0:
            return None

        count = len(selected_messages)
        if count == 1:
            menu_title = "Send to Fieldbook"
        else:
            menu_title = "Send %d requests to Fieldbook" % count

        menu_item = JMenuItem(menu_title)

        class MenuActionListener(ActionListener):
            def __init__(m_self):
                pass
            def actionPerformed(m_self, event):
                def process_snapshots():
                    snapshots = []
                    default_target = ""
                    for msg in selected_messages:
                        snap = extract_request_snapshot(self.helpers, msg)
                        if snap:
                            snapshots.append(snap)
                            if not default_target and snap.get("host"):
                                default_target = snap.get("host")

                    def show_dialog():
                        parent_frame = self.main_frame_getter() if self.main_frame_getter else None
                        dlg = QuickCaptureDialog(
                            parent_frame=parent_frame,
                            store=self.store,
                            linked_requests=snapshots,
                            default_target=default_target,
                            on_save_callback=self.on_save_callback
                        )
                        dlg.setVisible(True)

                    SwingUtilities.invokeLater(show_dialog)

                t = threading.Thread(target=process_snapshots)
                t.daemon = True
                t.start()

        menu_item.addActionListener(MenuActionListener())

        menu_list = []
        menu_list.append(menu_item)
        return menu_list
