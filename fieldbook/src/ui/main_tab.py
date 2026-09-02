"""
Main Notebook Tab UI for Fieldbook (Split-pane view with off-EDT search filtering).
"""

import logging
import threading

from fieldbook.src.model.notebook import ENTRY_TYPES, DEFAULT_ENTRY_TYPE, NotebookEntry
from fieldbook.src.util.markdown_util import markdown_to_html
from fieldbook.src.util.export_util import export_to_markdown, export_to_json
from fieldbook.src.ui.components import ENTRY_TYPE_COLORS, hex_to_color

logger = logging.getLogger("Fieldbook.MainTab")

try:
    from javax.swing import (
        JPanel, JLabel, JTextField, JTextArea, JComboBox, JButton, JCheckBox,
        JSplitPane, JList, DefaultListModel, ListCellRenderer, JScrollPane,
        JEditorPane, SwingUtilities, BorderFactory, JOptionPane, JFileChooser,
        SwingConstants
    )
    from javax.swing.event import DocumentListener, HyperlinkEvent, HyperlinkListener
    from java.awt import (
        BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets,
        Dimension, Font, Color, CardLayout
    )
    from java.awt.event import KeyAdapter, KeyEvent, ActionListener
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


if GUI_AVAILABLE:
    class EntryListCellRenderer(JPanel, ListCellRenderer):
        """
        Cell renderer for the left-side entry list.
        Shows color-coded entry_type badge, target, text snippet, pin icon, and request count.
        """
        def __init__(self):
            JPanel.__init__(self, BorderLayout(6, 2))
            self.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8))

            self.top_panel = JPanel(BorderLayout())
            self.top_panel.setOpaque(False)

            self.title_lbl = JLabel()
            self.title_lbl.setFont(Font("SansSerif", Font.BOLD, 12))
            self.top_panel.add(self.title_lbl, BorderLayout.CENTER)

            self.pin_lbl = JLabel("")
            self.pin_lbl.setFont(Font("SansSerif", Font.PLAIN, 11))
            self.top_panel.add(self.pin_lbl, BorderLayout.EAST)

            self.add(self.top_panel, BorderLayout.NORTH)

            self.snippet_lbl = JLabel()
            self.snippet_lbl.setFont(Font("SansSerif", Font.PLAIN, 11))
            self.snippet_lbl.setForeground(Color(71, 85, 105))
            self.add(self.snippet_lbl, BorderLayout.CENTER)

            self.bottom_panel = JPanel(BorderLayout())
            self.bottom_panel.setOpaque(False)
            self.meta_lbl = JLabel()
            self.meta_lbl.setFont(Font("SansSerif", Font.ITALIC, 10))
            self.meta_lbl.setForeground(Color.GRAY)
            self.bottom_panel.add(self.meta_lbl, BorderLayout.WEST)

            self.req_count_lbl = JLabel()
            self.req_count_lbl.setFont(Font("SansSerif", Font.BOLD, 10))
            self.req_count_lbl.setForeground(Color(3, 105, 161))
            self.bottom_panel.add(self.req_count_lbl, BorderLayout.EAST)

            self.add(self.bottom_panel, BorderLayout.SOUTH)

        def getListCellRendererComponent(self, list_obj, value, index, isSelected, cellHasFocus):
            if isSelected:
                self.setBackground(Color(224, 242, 254))
                self.setOpaque(True)
            else:
                self.setBackground(Color.WHITE)
                self.setOpaque(True)

            if isinstance(value, NotebookEntry):
                e_type = value.entry_type
                target = value.target or "General"
                self.title_lbl.setText("[%s] %s" % (e_type, target))

                c_def = ENTRY_TYPE_COLORS.get(e_type, ENTRY_TYPE_COLORS["NOTE"])
                self.title_lbl.setForeground(hex_to_color(c_def["fg"]))

                self.pin_lbl.setText("📌" if value.pinned else "")

                # Snippet
                clean_text = value.text.replace("\n", " ").strip()
                if not clean_text and value.linked_requests:
                    clean_text = "(Linked Request Note)"
                if len(clean_text) > 55:
                    clean_text = clean_text[:52] + "..."
                self.snippet_lbl.setText(clean_text or "(Empty Note)")

                # Meta
                tag_str = (" #" + " #".join(value.tags)) if value.tags else ""
                self.meta_lbl.setText(value.updated_at[:10] + tag_str)

                req_cnt = len(value.linked_requests)
                self.req_count_lbl.setText("%d reqs" % req_cnt if req_cnt > 0 else "")

            return self


    class FieldbookMainTab(JPanel):
        """
        Main split-pane tab component for Fieldbook.
        """
        def __init__(self, store, callbacks=None, helpers=None):
            JPanel.__init__(self, BorderLayout())
            self.store = store
            self.callbacks = callbacks
            self.helpers = helpers
            self.current_selected_entry = None
            self.is_edit_mode = False
            self.search_thread_lock = threading.Lock()

            self.init_ui()
            self.refresh_entries_async()

        def init_ui(self):
            # Split Pane
            self.split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
            self.split_pane.setResizeWeight(0.35)

            # Left Component (Search, Filters, Entry List, Quick Compose Bar)
            left_panel = JPanel(BorderLayout(4, 4))
            left_panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

            # Filter Controls Panel
            filter_panel = JPanel(GridBagLayout())
            filter_panel.setBorder(BorderFactory.createTitledBorder("Search & Filter"))
            gbc = GridBagConstraints()
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.insets = Insets(2, 2, 2, 2)

            # Search Box
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.gridwidth = 4
            gbc.weightx = 1.0
            self.search_field = JTextField()
            self.search_field.setToolTipText("Search notes, tags, targets, requests...")

            # Live search document listener
            class SearchDocListener(DocumentListener):
                def insertUpdate(d_self, e): self.on_search_changed()
                def removeUpdate(d_self, e): self.on_search_changed()
                def changedUpdate(d_self, e): self.on_search_changed()
            self.search_field.getDocument().addDocumentListener(SearchDocListener())
            filter_panel.add(self.search_field, gbc)

            # Dropdowns
            gbc.gridwidth = 1
            gbc.gridy = 1

            gbc.gridx = 0
            gbc.weightx = 0.25
            self.type_filter_combo = JComboBox(["ALL"] + ENTRY_TYPES)
            self.type_filter_combo.addActionListener(lambda e: self.on_search_changed())
            filter_panel.add(self.type_filter_combo, gbc)

            gbc.gridx = 1
            gbc.weightx = 0.25
            self.target_filter_combo = JComboBox(["ALL"])
            self.target_filter_combo.addActionListener(lambda e: self.on_search_changed())
            filter_panel.add(self.target_filter_combo, gbc)

            gbc.gridx = 2
            gbc.weightx = 0.25
            self.tag_filter_combo = JComboBox(["ALL"])
            self.tag_filter_combo.addActionListener(lambda e: self.on_search_changed())
            filter_panel.add(self.tag_filter_combo, gbc)

            gbc.gridx = 3
            gbc.weightx = 0.25
            self.pinned_chk = JCheckBox("📌 Only")
            self.pinned_chk.addActionListener(lambda e: self.on_search_changed())
            filter_panel.add(self.pinned_chk, gbc)

            left_panel.add(filter_panel, BorderLayout.NORTH)

            # Entry JList
            self.list_model = DefaultListModel()
            self.entry_jlist = JList(self.list_model)
            self.entry_jlist.setCellRenderer(EntryListCellRenderer())

            # Selection Listener
            def on_list_select(e):
                if not e.getValueIsAdjusting():
                    selected = self.entry_jlist.getSelectedValue()
                    if isinstance(selected, NotebookEntry):
                        self.display_entry_detail(selected)
            self.entry_jlist.addListSelectionListener(on_list_select)

            # Keyboard Navigation
            class ListKeyAdapter(KeyAdapter):
                def keyPressed(k_self, event):
                    if event.getKeyCode() == KeyEvent.VK_ENTER:
                        sel = self.entry_jlist.getSelectedValue()
                        if isinstance(sel, NotebookEntry):
                            self.display_entry_detail(sel)
            self.entry_jlist.addKeyListener(ListKeyAdapter())

            left_panel.add(JScrollPane(self.entry_jlist), BorderLayout.CENTER)

            # Persistent Quick Compose Bar
            compose_panel = JPanel(BorderLayout(4, 4))
            compose_panel.setBorder(BorderFactory.createTitledBorder("Quick Compose"))

            self.compose_type_combo = JComboBox(ENTRY_TYPES)
            last_type = getattr(self.store, "last_used_entry_type", DEFAULT_ENTRY_TYPE)
            if last_type in ENTRY_TYPES:
                self.compose_type_combo.setSelectedItem(last_type)
            compose_panel.add(self.compose_type_combo, BorderLayout.WEST)

            self.compose_field = JTextField()
            self.compose_field.setToolTipText("Type a quick thought and press Enter...")

            def submit_compose():
                text = str(self.compose_field.getText()).strip()
                if not text:
                    return
                e_type = str(self.compose_type_combo.getSelectedItem())
                self.compose_field.setText("")

                def bg_create():
                    new_entry = self.store.create_entry(entry_type=e_type, text=text)
                    SwingUtilities.invokeLater(lambda: self.on_entry_created(new_entry))
                t = threading.Thread(target=bg_create)
                t.daemon = True
                t.start()

            class ComposeKeyAdapter(KeyAdapter):
                def keyPressed(k_self, event):
                    if event.getKeyCode() == KeyEvent.VK_ENTER:
                        submit_compose()
            self.compose_field.addKeyListener(ComposeKeyAdapter())
            compose_panel.add(self.compose_field, BorderLayout.CENTER)

            add_btn = JButton("+ Add")
            add_btn.setFont(Font("SansSerif", Font.BOLD, 12))
            add_btn.addActionListener(lambda e: submit_compose())
            compose_panel.add(add_btn, BorderLayout.EAST)

            left_panel.add(compose_panel, BorderLayout.SOUTH)

            self.split_pane.setLeftComponent(left_panel)

            # Right Component (Detail / Edit View)
            self.right_panel = JPanel(BorderLayout(6, 6))
            self.right_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

            # Header / Action Toolbar
            self.toolbar_panel = JPanel(BorderLayout())
            self.action_btns_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 2))

            self.pin_btn = JButton("📌 Pin")
            self.pin_btn.addActionListener(lambda e: self.toggle_current_pin())
            self.action_btns_panel.add(self.pin_btn)

            self.edit_btn = JButton("Edit")
            self.edit_btn.addActionListener(lambda e: self.toggle_edit_mode())
            self.action_btns_panel.add(self.edit_btn)

            self.delete_btn = JButton("Delete")
            self.delete_btn.addActionListener(lambda e: self.delete_current_entry())
            self.action_btns_panel.add(self.delete_btn)

            self.export_md_btn = JButton("Export MD")
            self.export_md_btn.addActionListener(lambda e: self.export_view_markdown())
            self.action_btns_panel.add(self.export_md_btn)

            self.export_json_btn = JButton("Export JSON")
            self.export_json_btn.addActionListener(lambda e: self.export_view_json())
            self.action_btns_panel.add(self.export_json_btn)

            self.toolbar_panel.add(self.action_btns_panel, BorderLayout.EAST)
            self.right_panel.add(self.toolbar_panel, BorderLayout.NORTH)

            # Cards for View vs. Edit Mode
            self.detail_card_panel = JPanel(CardLayout())

            # VIEW CARD
            view_card = JPanel(BorderLayout(6, 6))
            self.editor_pane = JEditorPane()
            self.editor_pane.setEditable(False)
            self.editor_pane.setContentType("text/html")

            # Hyperlink listener for #req:N and #note:ID
            class DetailHyperlinkListener(HyperlinkListener):
                def hyperlinkUpdate(h_self, e):
                    if e.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
                        url_str = str(e.getDescription())
                        self.handle_hyperlink(url_str)
            self.editor_pane.addHyperlinkListener(DetailHyperlinkListener())

            view_card.add(JScrollPane(self.editor_pane), BorderLayout.CENTER)

            # Bottom Details Panel (Linked Requests + Backlinks)
            bottom_details_panel = JPanel(BorderLayout(4, 4))

            self.req_panel = JPanel(BorderLayout())
            self.req_panel.setBorder(BorderFactory.createTitledBorder("Attached HTTP Requests"))
            self.req_summary_lbl = JLabel("No requests attached.")
            self.req_panel.add(self.req_summary_lbl, BorderLayout.CENTER)
            bottom_details_panel.add(self.req_panel, BorderLayout.NORTH)

            self.backlinks_panel = JPanel(BorderLayout())
            self.backlinks_panel.setBorder(BorderFactory.createTitledBorder("Referenced By (Backlinks)"))
            self.backlinks_summary_lbl = JLabel("No incoming references.")
            self.backlinks_panel.add(self.backlinks_summary_lbl, BorderLayout.CENTER)
            bottom_details_panel.add(self.backlinks_panel, BorderLayout.SOUTH)

            view_card.add(bottom_details_panel, BorderLayout.SOUTH)

            self.detail_card_panel.add(view_card, "VIEW")

            # EDIT CARD
            edit_card = JPanel(BorderLayout(6, 6))
            edit_form = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.insets = Insets(4, 4, 4, 4)

            gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0
            edit_form.add(JLabel("Type:"), gbc)

            gbc.gridx = 1; gbc.weightx = 0.3
            self.edit_type_combo = JComboBox(ENTRY_TYPES)
            edit_form.add(self.edit_type_combo, gbc)

            gbc.gridx = 2; gbc.weightx = 0.0
            edit_form.add(JLabel("Target:"), gbc)

            gbc.gridx = 3; gbc.weightx = 0.7
            self.edit_target_field = JTextField()
            edit_form.add(self.edit_target_field, gbc)

            gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0
            edit_form.add(JLabel("Tags:"), gbc)

            gbc.gridx = 1; gbc.gridwidth = 3; gbc.weightx = 1.0
            self.edit_tags_field = JTextField()
            edit_form.add(self.edit_tags_field, gbc)

            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1; gbc.weightx = 0.0
            gbc.anchor = GridBagConstraints.NORTH
            edit_form.add(JLabel("Text:"), gbc)

            gbc.gridx = 1; gbc.gridwidth = 3; gbc.weightx = 1.0; gbc.weighty = 1.0
            gbc.fill = GridBagConstraints.BOTH
            self.edit_text_area = JTextArea()
            self.edit_text_area.setLineWrap(True)
            self.edit_text_area.setWrapStyleWord(True)
            edit_form.add(JScrollPane(self.edit_text_area), gbc)

            edit_card.add(edit_form, BorderLayout.CENTER)

            edit_btn_bar = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 2))
            cancel_edit_btn = JButton("Cancel")
            cancel_edit_btn.addActionListener(lambda e: self.set_edit_mode(False))
            edit_btn_bar.add(cancel_edit_btn)

            save_edit_btn = JButton("Save Changes")
            save_edit_btn.setFont(Font("SansSerif", Font.BOLD, 12))
            save_edit_btn.addActionListener(lambda e: self.save_edit_changes())
            edit_btn_bar.add(save_edit_btn)

            edit_card.add(edit_btn_bar, BorderLayout.SOUTH)

            self.detail_card_panel.add(edit_card, "EDIT")

            self.right_panel.add(self.detail_card_panel, BorderLayout.CENTER)

            self.split_pane.setRightComponent(self.right_panel)
            self.add(self.split_pane, BorderLayout.CENTER)

        def on_search_changed(self):
            self.refresh_entries_async()

        def update_filter_dropdowns(self):
            """Updates target and tag filter dropdown lists with latest values."""
            current_target_sel = self.target_filter_combo.getSelectedItem() or "ALL"
            targets = ["ALL"] + self.store.get_all_targets()
            self.target_filter_combo.removeAllItems()
            for t in targets:
                self.target_filter_combo.addItem(t)
            if current_target_sel in targets:
                self.target_filter_combo.setSelectedItem(current_target_sel)

            current_tag_sel = self.tag_filter_combo.getSelectedItem() or "ALL"
            tags = ["ALL"] + self.store.get_all_tags()
            self.tag_filter_combo.removeAllItems()
            for t in tags:
                self.tag_filter_combo.addItem(t)
            if current_tag_sel in tags:
                self.tag_filter_combo.setSelectedItem(current_tag_sel)

        def refresh_entries_async(self):
            """Runs search and filter query off EDT and updates JList."""
            query = self.search_field.getText() if hasattr(self, "search_field") else ""
            entry_type = str(self.type_filter_combo.getSelectedItem()) if hasattr(self, "type_filter_combo") else "ALL"
            target = str(self.target_filter_combo.getSelectedItem()) if hasattr(self, "target_filter_combo") else "ALL"
            tag = str(self.tag_filter_combo.getSelectedItem()) if hasattr(self, "tag_filter_combo") else "ALL"
            pinned_only = self.pinned_chk.isSelected() if hasattr(self, "pinned_chk") else False

            def bg_query():
                with self.search_thread_lock:
                    results = self.store.search_and_filter(
                        query=query,
                        entry_type=entry_type,
                        target=target,
                        tag=tag,
                        pinned_only=pinned_only
                    )

                def update_ui():
                    self.list_model.clear()
                    for r in results:
                        self.list_model.addElement(r)
                    if results and not self.current_selected_entry:
                        self.entry_jlist.setSelectedIndex(0)

                SwingUtilities.invokeLater(update_ui)

            t = threading.Thread(target=bg_query)
            t.daemon = True
            t.start()

        def display_entry_detail(self, entry):
            self.current_selected_entry = entry
            self.set_edit_mode(False)

            if not entry:
                self.editor_pane.setText("<html><body><p>No entry selected.</p></body></html>")
                self.req_summary_lbl.setText("No requests attached.")
                self.backlinks_summary_lbl.setText("No incoming references.")
                return

            # Fetch incoming backlinks
            backlinks = self.store.get_backlinks(entry.id) if self.store else []
            if not backlinks:
                self.backlinks_summary_lbl.setText("No incoming references.")
            else:
                bl_details = []
                for b in backlinks:
                    b_target = b.target or "General"
                    bl_details.append("• [%s] %s - <a href='note:%s'>%s</a>" % (b.entry_type, b_target, b.id, b.text[:40].replace("\n", " ") or "Note"))
                self.backlinks_summary_lbl.setText("<html>" + "<br/>".join(bl_details) + "</html>")

            self.pin_btn.setText("Unpin" if entry.pinned else "📌 Pin")

            # Render HTML
            html_content = markdown_to_html(entry.text, entry.linked_requests)
            self.editor_pane.setText(html_content)

            # Linked requests summary
            req_cnt = len(entry.linked_requests)
            if req_cnt == 0:
                self.req_summary_lbl.setText("No requests attached.")
            else:
                req_details = []
                for idx, req in enumerate(entry.linked_requests, 1):
                    if isinstance(req, dict):
                        label = req.get("label", req.get("url", "Request"))
                        status = req.get("raw_response_status", "")
                        req_details.append("#req:%d - %s (Status: %s)" % (idx, label, str(status or "N/A")))
                self.req_summary_lbl.setText("<br/>".join(req_details))

        def set_edit_mode(self, edit_mode):
            self.is_edit_mode = edit_mode
            card_layout = self.detail_card_panel.getLayout()
            if edit_mode and self.current_selected_entry:
                e = self.current_selected_entry
                self.edit_type_combo.setSelectedItem(e.entry_type)
                self.edit_target_field.setText(e.target)
                self.edit_tags_field.setText(", ".join(e.tags))
                self.edit_text_area.setText(e.text)
                card_layout.show(self.detail_card_panel, "EDIT")
            else:
                card_layout.show(self.detail_card_panel, "VIEW")

        def toggle_edit_mode(self):
            if self.current_selected_entry:
                self.set_edit_mode(not self.is_edit_mode)

        def save_edit_changes(self):
            if not self.current_selected_entry:
                return
            entry_id = self.current_selected_entry.id
            entry_type = str(self.edit_type_combo.getSelectedItem())
            target = str(self.edit_target_field.getText()).strip()
            raw_tags = str(self.edit_tags_field.getText()).strip()
            tags = [t.strip().lstrip("#") for t in raw_tags.split(",") if t.strip()]
            text = str(self.edit_text_area.getText()).strip()

            def bg_save():
                updated = self.store.update_entry(
                    entry_id,
                    entry_type=entry_type,
                    target=target,
                    tags=tags,
                    text=text
                )
                def on_saved():
                    self.update_filter_dropdowns()
                    self.display_entry_detail(updated)
                    self.refresh_entries_async()
                SwingUtilities.invokeLater(on_saved)

            t = threading.Thread(target=bg_save)
            t.daemon = True
            t.start()

        def toggle_current_pin(self):
            if not self.current_selected_entry:
                return
            entry_id = self.current_selected_entry.id
            new_pin = not self.current_selected_entry.pinned

            def bg_pin():
                updated = self.store.update_entry(entry_id, pinned=new_pin)
                def on_pinned():
                    self.display_entry_detail(updated)
                    self.refresh_entries_async()
                SwingUtilities.invokeLater(on_pinned)

            t = threading.Thread(target=bg_pin)
            t.daemon = True
            t.start()

        def delete_current_entry(self):
            if not self.current_selected_entry:
                return
            confirm = JOptionPane.showConfirmDialog(
                self,
                "Are you sure you want to delete this research note?",
                "Delete Note",
                JOptionPane.YES_NO_OPTION
            )
            if confirm == JOptionPane.YES_OPTION:
                entry_id = self.current_selected_entry.id
                def bg_del():
                    self.store.delete_entry(entry_id)
                    def on_deleted():
                        self.current_selected_entry = None
                        self.display_entry_detail(None)
                        self.update_filter_dropdowns()
                        self.refresh_entries_async()
                    SwingUtilities.invokeLater(on_deleted)

                t = threading.Thread(target=bg_del)
                t.daemon = True
                t.start()

        def on_entry_created(self, new_entry):
            self.update_filter_dropdowns()
            self.display_entry_detail(new_entry)
            self.refresh_entries_async()

        def handle_hyperlink(self, link_str):
            if not link_str:
                return
            if link_str.startswith("note:"):
                note_id = link_str.split("note:", 1)[1]
                target_entry = self.store.get_entry(note_id)
                if target_entry:
                    self.display_entry_detail(target_entry)
            elif link_str.startswith("req:"):
                req_num_str = link_str.split("req:", 1)[1]
                try:
                    req_idx = int(req_num_str) - 1
                    if self.current_selected_entry and 0 <= req_idx < len(self.current_selected_entry.linked_requests):
                        req = self.current_selected_entry.linked_requests[req_idx]
                        self.show_request_viewer_dialog(req)
                except ValueError:
                    pass

        def show_request_viewer_dialog(self, req_dict):
            if not isinstance(req_dict, dict):
                return
            label = req_dict.get("label", "Linked Request")
            raw_req = req_dict.get("raw_request", "")
            raw_resp = req_dict.get("raw_response_headers_and_body_or_reference", "")

            dlg = JOptionPane.getRootFrame()
            msg_panel = JPanel(BorderLayout(6, 6))
            msg_panel.setPreferredSize(Dimension(700, 500))

            split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            split.setResizeWeight(0.5)

            req_area = JTextArea(raw_req or "(No Request Data)")
            req_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            req_panel_scroll = JScrollPane(req_area)
            req_panel_scroll.setBorder(BorderFactory.createTitledBorder("HTTP Request"))
            split.setTopComponent(req_panel_scroll)

            resp_area = JTextArea(raw_resp or "(No Response Data)")
            resp_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            resp_panel_scroll = JScrollPane(resp_area)
            resp_panel_scroll.setBorder(BorderFactory.createTitledBorder("HTTP Response"))
            split.setBottomComponent(resp_panel_scroll)

            msg_panel.add(split, BorderLayout.CENTER)

            JOptionPane.showMessageDialog(
                self,
                msg_panel,
                "Request Viewer - " + label,
                JOptionPane.PLAIN_MESSAGE
            )

        def export_view_markdown(self):
            def bg_exp():
                entries = self.store.get_all_entries()
                md_text = export_to_markdown(entries, store=self.store)

                def save_file():
                    chooser = JFileChooser()
                    chooser.setDialogTitle("Export Fieldbook Notes to Markdown")
                    if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
                        file_path = chooser.getSelectedFile().getAbsolutePath()
                        if not file_path.endswith(".md"):
                            file_path += ".md"
                        with open(file_path, "w") as f:
                            f.write(md_text)
                        JOptionPane.showMessageDialog(self, "Exported successfully to " + file_path)

                SwingUtilities.invokeLater(save_file)

            t = threading.Thread(target=bg_exp)
            t.daemon = True
            t.start()

        def export_view_json(self):
            def bg_exp():
                entries = self.store.get_all_entries()
                json_text = export_to_json(entries)

                def save_file():
                    chooser = JFileChooser()
                    chooser.setDialogTitle("Export Fieldbook Notes to JSON")
                    if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
                        file_path = chooser.getSelectedFile().getAbsolutePath()
                        if not file_path.endswith(".json"):
                            file_path += ".json"
                        with open(file_path, "w") as f:
                            f.write(json_text)
                        JOptionPane.showMessageDialog(self, "Exported successfully to " + file_path)

                SwingUtilities.invokeLater(save_file)

            t = threading.Thread(target=bg_exp)
            t.daemon = True
            t.start()
else:
    class FieldbookMainTab(object):
        pass
