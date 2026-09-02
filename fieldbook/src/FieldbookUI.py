# -*- coding: utf-8 -*-
"""
FieldbookUI.py - Swing UI components for Fieldbook:
- Main tab two-pane UI (FieldbookTab)
- Quick Capture popup dialog (QuickCaptureDialog)
- Request viewer dialog (RequestViewerDialog)
- Custom card renderers and helpers
"""

import sys
import os
import time
import base64
import threading

from FieldbookLogic import (
    FieldbookEntry,
    FieldbookStore,
    MarkdownParser,
    FieldbookExporter,
    ENTRY_TYPES,
    ENTRY_TYPE_COLORS
)

# Safe Swing/AWT imports for Python 3 CLI test environment
HAS_GUI = False
try:
    from javax.swing import (
        JPanel, JLabel, JTextField, JTextArea, JComboBox, JButton, JCheckBox,
        JList, JScrollPane, JSplitPane, JDialog, JEditorPane, JFileChooser,
        JOptionPane, ListCellRenderer, DefaultListModel, SwingUtilities,
        BorderFactory, JTabbedPane, JMenuItem, KeyStroke, AbstractAction,
        JComponent, ActionMap, InputMap
    )
    from java.awt import (
        BorderLayout, FlowLayout, GridLayout, GridBagLayout, GridBagConstraints,
        Color, Font, Dimension, Cursor, KeyboardFocusManager, KeyEventDispatcher,
        Toolkit
    )
    from java.awt.event import (
        ActionListener, KeyAdapter, KeyEvent, MouseAdapter, MouseEvent,
        WindowAdapter, WindowEvent
    )
    from javax.swing.event import DocumentListener, HyperlinkListener, HyperlinkEvent
    HAS_GUI = True
except ImportError:
    HAS_GUI = False


def to_b64(raw_bytes):
    if not raw_bytes:
        return ""
    try:
        if hasattr(raw_bytes, 'tostring'):
            b_str = raw_bytes.tostring()
        elif isinstance(raw_bytes, (bytes, bytearray)):
            b_str = bytes(raw_bytes)
        else:
            b_str = "".join([chr(b & 0xFF) if isinstance(b, int) else chr(ord(b) & 0xFF) for b in raw_bytes])
        return base64.b64encode(b_str).decode('ascii')
    except Exception:
        return ""

def from_b64(b64_str):
    if not b64_str:
        return b""
    try:
        return base64.b64decode(b64_str)
    except Exception:
        return b""

def format_relative_time(timestamp):
    if not timestamp:
        return ""
    diff = time.time() - timestamp
    if diff < 60:
        return "Just now"
    elif diff < 3600:
        mins = int(diff / 60)
        return str(mins) + "m ago"
    elif diff < 86400:
        hours = int(diff / 3600)
        return str(hours) + "h ago"
    else:
        return time.strftime("%b %d", time.localtime(timestamp))


if HAS_GUI:

    class SimpleDocumentListener(DocumentListener):
        def __init__(self, callback):
            self.callback = callback
        def insertUpdate(self, e):
            self.callback()
        def removeUpdate(self, e):
            self.callback()
        def changedUpdate(self, e):
            self.callback()


    class CustomMessageEditorController(object):
        def __init__(self, http_service, req_bytes, resp_bytes):
            self._http_service = http_service
            self._req_bytes = req_bytes
            self._resp_bytes = resp_bytes

        def getHttpService(self):
            return self._http_service

        def getRequest(self):
            return self._req_bytes

        def getResponse(self):
            return self._resp_bytes


    class RequestViewerDialog(JDialog):
        """
        Dialog displaying raw HTTP request and response in Burp message editor.
        """
        def __init__(self, parent_frame, callbacks, req_info):
            JDialog.__init__(self, parent_frame, "Linked Request Details", True)
            self.setSize(850, 600)
            self.setLocationRelativeTo(parent_frame)

            method = req_info.get("method", "HTTP")
            host = req_info.get("host", "")
            path = req_info.get("path", "")
            title = method + " " + host + path
            self.setTitle("Fieldbook Linked Request: " + title)

            req_bytes = from_b64(req_info.get("request_bytes_b64", ""))
            resp_bytes = from_b64(req_info.get("response_bytes_b64", ""))

            svc_info = req_info.get("http_service", {})
            http_service = None
            if callbacks and svc_info.get("host"):
                try:
                    http_service = callbacks.getHelpers().buildHttpService(
                        svc_info.get("host"),
                        svc_info.get("port", 80),
                        svc_info.get("protocol", "http") == "https"
                    )
                except Exception:
                    http_service = None

            panel = JPanel(BorderLayout(10, 10))
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

            # Header info
            info_label = JLabel("URL: " + req_info.get("url", title))
            info_label.setFont(Font("SansSerif", Font.BOLD, 12))
            panel.add(info_label, BorderLayout.NORTH)

            # Editor view
            if callbacks:
                controller = CustomMessageEditorController(http_service, req_bytes, resp_bytes)
                tabs = JTabbedPane()

                req_editor = callbacks.createMessageEditor(controller, False)
                req_editor.setMessage(req_bytes, True)
                tabs.addTab("Request", req_editor.getComponent())

                resp_editor = callbacks.createMessageEditor(controller, False)
                resp_editor.setMessage(resp_bytes, False)
                tabs.addTab("Response", resp_editor.getComponent())

                panel.add(tabs, BorderLayout.CENTER)
            else:
                # Fallback text area viewer
                text_area = JTextArea()
                text_area.setEditable(False)
                try:
                    req_str = req_bytes.decode('utf-8', errors='replace')
                    resp_str = resp_bytes.decode('utf-8', errors='replace')
                except Exception:
                    req_str = str(req_bytes)
                    resp_str = str(resp_bytes)
                text_area.setText("=== REQUEST ===\n" + req_str + "\n\n=== RESPONSE ===\n" + resp_str)
                panel.add(JScrollPane(text_area), BorderLayout.CENTER)

            close_btn = JButton("Close")
            class CloseListener(ActionListener):
                def __init__(self, dlg):
                    self.dlg = dlg
                def actionPerformed(self, e):
                    self.dlg.dispose()
            close_btn.addActionListener(CloseListener(self))

            btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
            btn_panel.add(close_btn)
            panel.add(btn_panel, BorderLayout.SOUTH)

            self.setContentPane(panel)


    class QuickCaptureDialog(JDialog):
        """
        Always-on-top lightweight popup for rapid note capture.
        Supports pre-populated linked requests, Ctrl+Enter save, Esc cancel.
        """
        def __init__(self, parent_frame, store, callbacks, pre_linked_requests=None, on_save_callback=None):
            JDialog.__init__(self, parent_frame, "Quick Capture to Fieldbook", True)
            self.setAlwaysOnTop(True)
            self.setSize(520, 380)
            self.setLocationRelativeTo(parent_frame)

            self.store = store
            self.callbacks = callbacks
            self.linked_requests = list(pre_linked_requests) if pre_linked_requests else []
            self.on_save_callback = on_save_callback

            self._init_ui()

        def _init_ui(self):
            panel = JPanel(BorderLayout(8, 8))
            panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

            # Top controls: Entry Type & Target
            top_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))

            top_panel.add(JLabel("Type:"))
            self.type_combo = JComboBox(ENTRY_TYPES)
            self.type_combo.setSelectedItem("NOTE")
            top_panel.add(self.type_combo)

            top_panel.add(JLabel("Target:"))
            self.target_field = JTextField(14)
            top_panel.add(self.target_field)

            top_panel.add(JLabel("Tags:"))
            self.tags_field = JTextField(12)
            self.tags_field.setToolTipText("Comma-separated tags")
            top_panel.add(self.tags_field)

            panel.add(top_panel, BorderLayout.NORTH)

            # Center: Linked request chips + Content Text Area
            center_panel = JPanel(BorderLayout(6, 6))

            if self.linked_requests:
                req_chips_panel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
                req_chips_panel.setBorder(BorderFactory.createTitledBorder("Linked Requests"))
                for req in self.linked_requests:
                    req_id = req.get("id", "1")
                    method = req.get("method", "GET")
                    host = req.get("host", "")
                    path = req.get("path", "")
                    chip_str = "[" + method + " " + host + path + "]"
                    chip_lbl = JLabel(chip_str)
                    chip_lbl.setFont(Font("Monospaced", Font.BOLD, 11))
                    chip_lbl.setForeground(Color(0x00, 0x55, 0xAA))
                    req_chips_panel.add(chip_lbl)
                center_panel.add(req_chips_panel, BorderLayout.NORTH)

            self.content_area = JTextArea()
            self.content_area.setLineWrap(True)
            self.content_area.setWrapStyleWord(True)
            self.content_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            scroll_pane = JScrollPane(self.content_area)
            scroll_pane.setBorder(BorderFactory.createTitledBorder("Note Content (Markdown supported, Ctrl+Enter to Save)"))

            center_panel.add(scroll_pane, BorderLayout.CENTER)
            panel.add(center_panel, BorderLayout.CENTER)

            # Bottom: Save and Cancel buttons
            bottom_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 4))
            save_btn = JButton("Save Note (Ctrl+Enter)")
            save_btn.setFont(Font("SansSerif", Font.BOLD, 12))
            save_btn.setBackground(Color(0x21, 0x96, 0xF3))

            cancel_btn = JButton("Cancel (Esc)")

            class SaveActionListener(ActionListener):
                def __init__(self, dlg):
                    self.dlg = dlg
                def actionPerformed(self, e):
                    self.dlg.commit_and_close()

            class CancelActionListener(ActionListener):
                def __init__(self, dlg):
                    self.dlg = dlg
                def actionPerformed(self, e):
                    self.dlg.dispose()

            save_btn.addActionListener(SaveActionListener(self))
            cancel_btn.addActionListener(CancelActionListener(self))

            bottom_panel.add(cancel_btn)
            bottom_panel.add(save_btn)
            panel.add(bottom_panel, BorderLayout.SOUTH)

            # Key Bindings: Ctrl+Enter to Save, Esc to Cancel
            root_pane = self.getRootPane()
            input_map = root_pane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
            action_map = root_pane.getActionMap()

            ctrl_enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, Toolkit.getDefaultToolkit().getMenuShortcutKeyMask())
            esc_key = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0)

            dlg_ref = self
            class SaveAction(AbstractAction):
                def actionPerformed(self, e):
                    dlg_ref.commit_and_close()

            class CancelAction(AbstractAction):
                def actionPerformed(self, e):
                    dlg_ref.dispose()

            input_map.put(ctrl_enter, "saveNote")
            action_map.put("saveNote", SaveAction())

            input_map.put(esc_key, "cancelNote")
            action_map.put("cancelNote", CancelAction())

            self.setContentPane(panel)

            # Request focus in text area when visible
            class WindowFocusAdapter(WindowAdapter):
                def __init__(self, text_comp):
                    self.text_comp = text_comp
                def windowOpened(self, e):
                    self.text_comp.requestFocusInWindow()

            self.addWindowListener(WindowFocusAdapter(self.content_area))

        def commit_and_close(self):
            content = self.content_area.getText().strip()
            if not content and not self.linked_requests:
                self.dispose()
                return

            entry_type = str(self.type_combo.getSelectedItem())
            target = self.target_field.getText().strip()
            tags_raw = self.tags_field.getText().strip()
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

            entry = FieldbookEntry(
                entry_type=entry_type,
                content=content,
                target=target,
                tags=tags,
                linked_requests=self.linked_requests
            )

            # Non-blocking save to store
            self.store.add_entry(entry, immediate=True)

            if self.on_save_callback:
                try:
                    self.on_save_callback(entry)
                except Exception:
                    pass

            self.dispose()


    class EntryCardCellRenderer(ListCellRenderer):
        """
        Custom renderer for list entry cards showing type badge, text preview,
        target, relative timestamp, and request badge.
        """
        def __init__(self):
            self.panel = JPanel(BorderLayout(6, 4))
            self.panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color(0xE0, 0xE0, 0xE0)),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
            ))

            self.top_line = JPanel(BorderLayout())
            self.top_line.setOpaque(False)

            self.type_badge = JLabel(" NOTE ")
            self.type_badge.setOpaque(True)
            self.type_badge.setFont(Font("SansSerif", Font.BOLD, 10))
            self.type_badge.setForeground(Color.WHITE)

            self.target_label = JLabel("")
            self.target_label.setFont(Font("SansSerif", Font.BOLD, 11))
            self.target_label.setForeground(Color(0x33, 0x33, 0x33))

            self.time_label = JLabel("")
            self.time_label.setFont(Font("SansSerif", Font.PLAIN, 10))
            self.time_label.setForeground(Color(0x88, 0x88, 0x88))

            top_left = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
            top_left.setOpaque(False)
            top_left.add(self.type_badge)
            top_left.add(self.target_label)

            self.top_line.add(top_left, BorderLayout.WEST)
            self.top_line.add(self.time_label, BorderLayout.EAST)

            self.preview_label = JLabel("")
            self.preview_label.setFont(Font("SansSerif", Font.PLAIN, 12))

            self.bottom_line = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
            self.bottom_line.setOpaque(False)
            self.req_badge = JLabel("")
            self.req_badge.setFont(Font("SansSerif", Font.PLAIN, 10))
            self.req_badge.setForeground(Color(0x00, 0x66, 0xCC))
            self.tags_label = JLabel("")
            self.tags_label.setFont(Font("SansSerif", Font.ITALIC, 10))
            self.tags_label.setForeground(Color(0x66, 0x66, 0x66))

            self.bottom_line.add(self.req_badge)
            self.bottom_line.add(self.tags_label)

            self.panel.add(self.top_line, BorderLayout.NORTH)
            self.panel.add(self.preview_label, BorderLayout.CENTER)
            self.panel.add(self.bottom_line, BorderLayout.SOUTH)

        def getListCellRendererComponent(self, list_obj, value, index, isSelected, cellHasFocus):
            if isinstance(value, FieldbookEntry):
                entry = value
                # Type badge
                self.type_badge.setText(" " + entry.type + " ")
                color_hex = ENTRY_TYPE_COLORS.get(entry.type, "#2196F3")
                try:
                    c = Color.decode(color_hex)
                    self.type_badge.setBackground(c)
                except Exception:
                    self.type_badge.setBackground(Color.BLUE)

                # Target & Time
                self.target_label.setText(entry.target if entry.target else "Unassigned")
                self.time_label.setText(format_relative_time(entry.updated_at))

                # Text Preview
                first_line = entry.content.strip().splitlines()[0] if entry.content.strip() else "(Empty note)"
                if len(first_line) > 70:
                    first_line = first_line[:67] + "..."
                self.preview_label.setText(first_line)

                # Badges
                req_count = len(entry.linked_requests)
                if req_count > 0:
                    self.req_badge.setText("[" + str(req_count) + (" req" if req_count == 1 else " reqs") + "] ")
                else:
                    self.req_badge.setText("")

                if entry.tags:
                    self.tags_label.setText("#" + " #".join(entry.tags))
                else:
                    self.tags_label.setText("")

            if isSelected:
                self.panel.setBackground(Color(0xE3, 0xF2, 0xFD))
            else:
                self.panel.setBackground(Color.WHITE)

            return self.panel


    class FieldbookTab(JPanel):
        """
        Main Tab UI for Fieldbook containing:
        - Left Pane: live search, filter chips/dropdowns, entry cards list, + New Note button
        - Right Pane: entry detail editor, Markdown edit/preview toggle, tag editor, linked requests list
        """
        def __init__(self, store, callbacks):
            JPanel.__init__(self, BorderLayout())
            self.store = store
            self.callbacks = callbacks
            self.current_entry = None

            self._init_ui()
            self.refresh_entries_list()

        def _init_ui(self):
            split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            split_pane.setDividerLocation(340)

            left_pane = self._build_left_pane()
            right_pane = self._build_right_pane()

            split_pane.setLeftComponent(left_pane)
            split_pane.setRightComponent(right_pane)

            self.add(split_pane, BorderLayout.CENTER)

        def _build_left_pane(self):
            panel = JPanel(BorderLayout(4, 4))
            panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

            # Top controls: New Note button & Search bar
            top_box = JPanel(BorderLayout(4, 4))

            new_btn = JButton("+ New Note (Ctrl+N)")
            new_btn.setFont(Font("SansSerif", Font.BOLD, 12))
            new_btn.setBackground(Color(0x4C, 0xAF, 0x50))
            new_btn.setForeground(Color.WHITE)

            class NewNoteListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    self.tab.create_new_note()
            new_btn.addActionListener(NewNoteListener(self))

            top_box.add(new_btn, BorderLayout.NORTH)

            # Search field
            self.search_field = JTextField()
            self.search_field.setToolTipText("Search notes...")
            search_panel = JPanel(BorderLayout(4, 0))
            search_panel.add(JLabel("Search: "), BorderLayout.WEST)
            search_panel.add(self.search_field, BorderLayout.CENTER)

            class SearchDocListener(SimpleDocumentListener):
                def __init__(self, tab):
                    SimpleDocumentListener.__init__(self, self.on_change)
                    self.tab = tab
                def on_change(self):
                    self.tab.refresh_entries_list()
            self.search_field.getDocument().addDocumentListener(SearchDocListener(self))

            top_box.add(search_panel, BorderLayout.SOUTH)
            panel.add(top_box, BorderLayout.NORTH)

            # Filter chips/dropdowns
            filters_panel = JPanel(GridLayout(3, 1, 2, 2))

            # Type Filter
            type_p = JPanel(BorderLayout(4, 0))
            type_p.add(JLabel("Type: "), BorderLayout.WEST)
            self.filter_type_combo = JComboBox(["ALL"] + ENTRY_TYPES)
            type_p.add(self.filter_type_combo, BorderLayout.CENTER)

            # Target Filter
            target_p = JPanel(BorderLayout(4, 0))
            target_p.add(JLabel("Target: "), BorderLayout.WEST)
            self.filter_target_combo = JComboBox(["ALL"])
            target_p.add(self.filter_target_combo, BorderLayout.CENTER)

            # Tag Filter
            tag_p = JPanel(BorderLayout(4, 0))
            tag_p.add(JLabel("Tag: "), BorderLayout.WEST)
            self.filter_tag_combo = JComboBox(["ALL"])
            tag_p.add(self.filter_tag_combo, BorderLayout.CENTER)

            class FilterComboListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    self.tab.refresh_entries_list()

            combo_listener = FilterComboListener(self)
            self.filter_type_combo.addActionListener(combo_listener)
            self.filter_target_combo.addActionListener(combo_listener)
            self.filter_tag_combo.addActionListener(combo_listener)

            filters_panel.add(type_p)
            filters_panel.add(target_p)
            filters_panel.add(tag_p)

            # Wrap filters in collapsible / titled container
            filter_container = JPanel(BorderLayout())
            filter_container.setBorder(BorderFactory.createTitledBorder("Filters"))
            filter_container.add(filters_panel, BorderLayout.CENTER)

            # Center: List of Entry Cards
            self.list_model = DefaultListModel()
            self.entry_list = JList(self.list_model)
            self.entry_list.setCellRenderer(EntryCardCellRenderer())

            class EntrySelectionListener(MouseAdapter):
                def __init__(self, tab):
                    self.tab = tab
                def mouseClicked(self, e):
                    self.tab.on_entry_selected()

            class ListKeyListener(KeyAdapter):
                def __init__(self, tab):
                    self.tab = tab
                def keyReleased(self, e):
                    if e.getKeyCode() in (KeyEvent.VK_UP, KeyEvent.VK_DOWN):
                        self.tab.on_entry_selected()

            self.entry_list.addMouseListener(EntrySelectionListener(self))
            self.entry_list.addKeyListener(ListKeyListener(self))

            scroll_list = JScrollPane(self.entry_list)

            center_box = JPanel(BorderLayout(4, 4))
            center_box.add(filter_container, BorderLayout.NORTH)
            center_box.add(scroll_list, BorderLayout.CENTER)

            panel.add(center_box, BorderLayout.CENTER)
            return panel

        def _build_right_pane(self):
            panel = JPanel(BorderLayout(6, 6))
            panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

            # Header bar: Type, Target, Tags, Delete
            header_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.weightx = 0.0
            gbc.gridy = 0

            # Type
            gbc.gridx = 0
            header_panel.add(JLabel("Type: "), gbc)
            gbc.gridx = 1
            self.detail_type_combo = JComboBox(ENTRY_TYPES)
            header_panel.add(self.detail_type_combo, gbc)

            # Target
            gbc.gridx = 2
            header_panel.add(JLabel("  Target: "), gbc)
            gbc.gridx = 3
            gbc.weightx = 0.5
            self.detail_target_field = JTextField()
            header_panel.add(self.detail_target_field, gbc)

            # Tags
            gbc.gridx = 4
            gbc.weightx = 0.0
            header_panel.add(JLabel("  Tags: "), gbc)
            gbc.gridx = 5
            gbc.weightx = 0.5
            self.detail_tags_field = JTextField()
            self.detail_tags_field.setToolTipText("Comma-separated tags")
            header_panel.add(self.detail_tags_field, gbc)

            # Delete Note button
            gbc.gridx = 6
            gbc.weightx = 0.0
            del_btn = JButton("Delete Note")
            del_btn.setForeground(Color.RED)
            class DeleteNoteListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    self.tab.delete_current_entry()
            del_btn.addActionListener(DeleteNoteListener(self))
            header_panel.add(del_btn, gbc)

            panel.add(header_panel, BorderLayout.NORTH)

            # Linked requests chips container
            self.req_chips_container = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
            self.req_chips_container.setBorder(BorderFactory.createTitledBorder("Linked Requests (click to view, [x] to remove)"))

            # Editor view: Tabbed Edit vs Preview
            self.tabbed_editor = JTabbedPane()

            # Edit view
            self.edit_text_area = JTextArea()
            self.edit_text_area.setLineWrap(True)
            self.edit_text_area.setWrapStyleWord(True)
            self.edit_text_area.setFont(Font("Monospaced", Font.PLAIN, 12))

            class EditDocListener(SimpleDocumentListener):
                def __init__(self, tab):
                    SimpleDocumentListener.__init__(self, self.on_change)
                    self.tab = tab
                def on_change(self):
                    self.tab.on_content_changed()

            self.edit_text_area.getDocument().addDocumentListener(EditDocListener(self))
            self.tabbed_editor.addTab("Edit (Markdown)", JScrollPane(self.edit_text_area))

            # Preview view
            self.preview_pane = JEditorPane("text/html", "")
            self.preview_pane.setEditable(False)

            class PreviewHyperlinkListener(HyperlinkListener):
                def __init__(self, tab):
                    self.tab = tab
                def hyperlinkUpdate(self, e):
                    if e.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
                        href = e.getDescription()
                        if href and href.startswith("req:"):
                            req_num_str = href[4:]
                            self.tab.open_linked_request_by_num(req_num_str)

            self.preview_pane.addHyperlinkListener(PreviewHyperlinkListener(self))
            self.tabbed_editor.addTab("Preview (HTML)", JScrollPane(self.preview_pane))

            class EditorTabChangeListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    pass

            # Update preview on tab select
            def on_tab_change(e):
                if self.tabbed_editor.getSelectedIndex() == 1:
                    self.update_markdown_preview()

            self.tabbed_editor.addChangeListener(on_tab_change)

            center_container = JPanel(BorderLayout(4, 4))
            center_container.add(self.req_chips_container, BorderLayout.NORTH)
            center_container.add(self.tabbed_editor, BorderLayout.CENTER)

            panel.add(center_container, BorderLayout.CENTER)

            # Bottom Bar: Autosave status & Export buttons
            bottom_bar = JPanel(BorderLayout(4, 4))
            self.status_label = JLabel("Ready")
            self.status_label.setFont(Font("SansSerif", Font.ITALIC, 11))

            actions_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 2))

            export_btn = JButton("Export Report...")
            class ExportListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    self.tab.show_export_dialog()
            export_btn.addActionListener(ExportListener(self))

            path_btn = JButton("Notebook Path...")
            class PathListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    self.tab.show_path_dialog()
            path_btn.addActionListener(PathListener(self))

            actions_panel.add(path_btn)
            actions_panel.add(export_btn)

            bottom_bar.add(self.status_label, BorderLayout.WEST)
            bottom_bar.add(actions_panel, BorderLayout.EAST)

            panel.add(bottom_bar, BorderLayout.SOUTH)

            # Detail field listeners for auto-save
            class DetailFieldDocListener(SimpleDocumentListener):
                def __init__(self, tab):
                    SimpleDocumentListener.__init__(self, self.on_change)
                    self.tab = tab
                def on_change(self):
                    self.tab.save_current_entry_fields()

            class ComboChangeListener(ActionListener):
                def __init__(self, tab):
                    self.tab = tab
                def actionPerformed(self, e):
                    self.tab.save_current_entry_fields()

            self.detail_type_combo.addActionListener(ComboChangeListener(self))
            self.detail_target_field.getDocument().addDocumentListener(DetailFieldDocListener(self))
            self.detail_tags_field.getDocument().addDocumentListener(DetailFieldDocListener(self))

            return panel

        def refresh_filter_combos(self):
            # Target combo
            current_target = self.filter_target_combo.getSelectedItem()
            self.filter_target_combo.removeAllItems()
            self.filter_target_combo.addItem("ALL")
            for t in self.store.get_targets():
                self.filter_target_combo.addItem(t)
            if current_target and current_target in [self.filter_target_combo.getItemAt(i) for i in range(self.filter_target_combo.getItemCount())]:
                self.filter_target_combo.setSelectedItem(current_target)

            # Tag combo
            current_tag = self.filter_tag_combo.getSelectedItem()
            self.filter_tag_combo.removeAllItems()
            self.filter_tag_combo.addItem("ALL")
            for tag in self.store.get_tags():
                self.filter_tag_combo.addItem(tag)
            if current_tag and current_tag in [self.filter_tag_combo.getItemAt(i) for i in range(self.filter_tag_combo.getItemCount())]:
                self.filter_tag_combo.setSelectedItem(current_tag)

        def refresh_entries_list(self):
            query = self.search_field.getText()
            ftype = str(self.filter_type_combo.getSelectedItem())
            ftarget = str(self.filter_target_combo.getSelectedItem()) if self.filter_target_combo.getSelectedItem() else "ALL"
            ftag = str(self.filter_tag_combo.getSelectedItem()) if self.filter_tag_combo.getSelectedItem() else "ALL"

            entries = self.store.search_entries(query=query, entry_type=ftype, target=ftarget, tag=ftag)

            self.list_model.clear()
            for entry in entries:
                self.list_model.addElement(entry)

            # Re-select current entry if present
            if self.current_entry:
                for i in range(self.list_model.getSize()):
                    if self.list_model.getElementAt(i).id == self.current_entry.id:
                        self.entry_list.setSelectedIndex(i)
                        break

        def on_entry_selected(self):
            selected = self.entry_list.getSelectedValue()
            if isinstance(selected, FieldbookEntry):
                self.current_entry = selected
                self.populate_detail_pane(selected)

        def populate_detail_pane(self, entry):
            self.detail_type_combo.setSelectedItem(entry.type)
            self.detail_target_field.setText(entry.target)
            self.detail_tags_field.setText(", ".join(entry.tags))
            self.edit_text_area.setText(entry.content)

            self.render_linked_request_chips(entry)
            self.update_markdown_preview()
            self.status_label.setText("Loaded note: " + entry.id)

        def render_linked_request_chips(self, entry):
            self.req_chips_container.removeAll()
            if not entry or not entry.linked_requests:
                no_req_lbl = JLabel("No linked requests")
                no_req_lbl.setFont(Font("SansSerif", Font.ITALIC, 11))
                self.req_chips_container.add(no_req_lbl)
            else:
                for idx, req in enumerate(entry.linked_requests):
                    req_num = req.get("id", str(idx + 1))
                    method = req.get("method", "GET")
                    host = req.get("host", "")
                    path = req.get("path", "")

                    chip_panel = JPanel(FlowLayout(FlowLayout.LEFT, 2, 0))
                    chip_panel.setBackground(Color(0xE3, 0xF2, 0xFD))
                    chip_panel.setBorder(BorderFactory.createLineBorder(Color(0x90, 0xCA, 0xF9)))

                    btn_lbl = JLabel(" #" + str(req_num) + ": " + method + " " + host + path + " ")
                    btn_lbl.setFont(Font("Monospaced", Font.BOLD, 11))
                    btn_lbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

                    class ViewReqListener(MouseAdapter):
                        def __init__(self, tab, req_data):
                            self.tab = tab
                            self.req_data = req_data
                        def mouseClicked(self, e):
                            self.tab.open_linked_request_dialog(self.req_data)

                    btn_lbl.addMouseListener(ViewReqListener(self, req))

                    remove_btn = JLabel(" [x] ")
                    remove_btn.setFont(Font("SansSerif", Font.BOLD, 10))
                    remove_btn.setForeground(Color.RED)
                    remove_btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))

                    class RemoveReqListener(MouseAdapter):
                        def __init__(self, tab, req_idx):
                            self.tab = tab
                            self.req_idx = req_idx
                        def mouseClicked(self, e):
                            self.tab.remove_linked_request(self.req_idx)

                    remove_btn.addMouseListener(RemoveReqListener(self, idx))

                    chip_panel.add(btn_lbl)
                    chip_panel.add(remove_btn)
                    self.req_chips_container.add(chip_panel)

            self.req_chips_container.revalidate()
            self.req_chips_container.repaint()

        def update_markdown_preview(self):
            content = self.edit_text_area.getText()
            html = MarkdownParser.to_html(content)
            self.preview_pane.setText(html)

        def on_content_changed(self):
            self.save_current_entry_fields()

        def save_current_entry_fields(self):
            if not self.current_entry:
                return

            content = self.edit_text_area.getText()
            entry_type = str(self.detail_type_combo.getSelectedItem())
            target = self.detail_target_field.getText().strip()
            tags_raw = self.detail_tags_field.getText().strip()
            tags = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

            updated = self.store.update_entry(
                self.current_entry.id,
                content=content,
                entry_type=entry_type,
                target=target,
                tags=tags
            )
            if updated:
                self.current_entry = updated
                self.status_label.setText("Autosaved at " + time.strftime("%H:%M:%S"))

                # Refresh list cell rendering
                self.entry_list.repaint()
                self.refresh_filter_combos()

        def create_new_note(self, pre_linked_requests=None):
            dlg = QuickCaptureDialog(
                parent_frame=None,
                store=self.store,
                callbacks=self.callbacks,
                pre_linked_requests=pre_linked_requests,
                on_save_callback=self._on_new_note_saved
            )
            dlg.setVisible(True)

        def _on_new_note_saved(self, new_entry):
            def gui_update():
                self.refresh_filter_combos()
                self.refresh_entries_list()
                # Select newly added note
                for i in range(self.list_model.getSize()):
                    if self.list_model.getElementAt(i).id == new_entry.id:
                        self.entry_list.setSelectedIndex(i)
                        self.on_entry_selected()
                        break
            SwingUtilities.invokeLater(gui_update)

        def delete_current_entry(self):
            if not self.current_entry:
                return
            res = JOptionPane.showConfirmDialog(
                self,
                "Are you sure you want to delete this note?",
                "Delete Fieldbook Note",
                JOptionPane.YES_NO_OPTION
            )
            if res == JOptionPane.YES_OPTION:
                self.store.delete_entry(self.current_entry.id, immediate=True)
                self.current_entry = None
                self.edit_text_area.setText("")
                self.detail_target_field.setText("")
                self.detail_tags_field.setText("")
                self.req_chips_container.removeAll()
                self.refresh_entries_list()
                self.status_label.setText("Note deleted")

        def remove_linked_request(self, req_idx):
            if not self.current_entry or req_idx >= len(self.current_entry.linked_requests):
                return
            reqs = list(self.current_entry.linked_requests)
            del reqs[req_idx]
            self.store.update_entry(self.current_entry.id, linked_requests=reqs, immediate=True)
            self.render_linked_request_chips(self.current_entry)

        def open_linked_request_dialog(self, req_data):
            dlg = RequestViewerDialog(None, self.callbacks, req_data)
            dlg.setVisible(True)

        def open_linked_request_by_num(self, req_num_str):
            if not self.current_entry or not self.current_entry.linked_requests:
                return
            for req in self.current_entry.linked_requests:
                if str(req.get("id")) == str(req_num_str):
                    self.open_linked_request_dialog(req)
                    return

        def show_export_dialog(self):
            entries = self.store.get_all_entries()
            if not entries:
                JOptionPane.showMessageDialog(self, "No notes available to export.")
                return

            md_export = FieldbookExporter.export_markdown(entries)
            json_export = FieldbookExporter.export_json(entries)

            options = ["Export Markdown", "Export JSON", "Cancel"]
            choice = JOptionPane.showOptionDialog(
                self,
                "Select export format for " + str(len(entries)) + " Fieldbook notes:",
                "Export Fieldbook Notes",
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                None,
                options,
                options[0]
            )

            if choice == 0:
                self._save_export_to_file("fieldbook_report.md", md_export)
            elif choice == 1:
                self._save_export_to_file("fieldbook_backup.json", json_export)

        def _save_export_to_file(self, default_name, content):
            chooser = JFileChooser()
            chooser.setSelectedFile(java_file(default_name) if 'java_file' in globals() else os.path.join(os.path.expanduser("~"), default_name))
            ret = chooser.showSaveDialog(self)
            if ret == JFileChooser.APPROVE_OPTION:
                selected_path = str(chooser.getSelectedFile().getAbsolutePath())
                try:
                    with open(selected_path, "w") as f:
                        f.write(content)
                    JOptionPane.showMessageDialog(self, "Export saved successfully to:\n" + selected_path)
                except Exception as e:
                    JOptionPane.showMessageDialog(self, "Failed to export: " + str(e))

        def show_path_dialog(self):
            current_path = self.store.filepath
            new_path = JOptionPane.showInputDialog(
                self,
                "Current notebook persistence file path:",
                current_path
            )
            if new_path and new_path.strip():
                self.store.set_filepath(new_path.strip())
                self.store.save_immediate()
                JOptionPane.showMessageDialog(self, "Notebook path updated to:\n" + new_path.strip())
