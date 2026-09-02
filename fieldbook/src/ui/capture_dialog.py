"""
Quick Capture Dialog for Fieldbook.
Enables instant note taking from context menu or global hotkey (< 5 sec target time).
"""

import logging
import threading

from fieldbook.src.model.notebook import ENTRY_TYPES, DEFAULT_ENTRY_TYPE, NotebookEntry

logger = logging.getLogger("Fieldbook.CaptureDialog")

try:
    from javax.swing import (
        JDialog, JPanel, JLabel, JTextField, JTextArea, JComboBox,
        JButton, JScrollPane, SwingUtilities, BorderFactory
    )
    from java.awt import (
        BorderLayout, GridBagLayout, GridBagConstraints, Insets,
        FlowLayout, Dimension, Font, Color
    )
    from java.awt.event import KeyAdapter, KeyEvent, ActionListener
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

if GUI_AVAILABLE:
    class QuickCaptureDialog(JDialog):
        """
        Fast capture popup dialog.
        """
        def __init__(self, parent_frame, store, linked_requests=None, default_target="", on_save_callback=None):
            JDialog.__init__(self, parent_frame, "Quick Capture - Fieldbook", False)
            self.store = store
            self.linked_requests = linked_requests or []
            self.default_target = default_target
            self.on_save_callback = on_save_callback

            self.init_ui()
            self.setSize(550, 420)
            self.setLocationRelativeTo(parent_frame)

        def init_ui(self):
            content_panel = JPanel(BorderLayout(8, 8))
            content_panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))

            # Header info
            header_panel = JPanel(BorderLayout())
            title_lbl = JLabel("Quick Note Capture")
            title_lbl.setFont(Font("SansSerif", Font.BOLD, 14))
            header_panel.add(title_lbl, BorderLayout.WEST)

            if self.linked_requests:
                req_count_lbl = JLabel("%d Request(s) Attached" % len(self.linked_requests))
                req_count_lbl.setFont(Font("SansSerif", Font.ITALIC, 11))
                req_count_lbl.setForeground(Color(3, 105, 161))
                header_panel.add(req_count_lbl, BorderLayout.EAST)

            content_panel.add(header_panel, BorderLayout.NORTH)

            # Form fields
            form_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.insets = Insets(4, 4, 4, 4)

            # Row 0: Type & Target
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.weightx = 0.0
            form_panel.add(JLabel("Type:"), gbc)

            gbc.gridx = 1
            gbc.weightx = 0.4
            self.type_combo = JComboBox(ENTRY_TYPES)
            last_type = getattr(self.store, "last_used_entry_type", DEFAULT_ENTRY_TYPE)
            if last_type in ENTRY_TYPES:
                self.type_combo.setSelectedItem(last_type)
            form_panel.add(self.type_combo, gbc)

            gbc.gridx = 2
            gbc.weightx = 0.0
            form_panel.add(JLabel("Target:"), gbc)

            gbc.gridx = 3
            gbc.weightx = 0.6
            auto_target = self.default_target
            if not auto_target and self.linked_requests:
                first_req = self.linked_requests[0]
                if isinstance(first_req, dict):
                    auto_target = first_req.get("host", "")
            self.target_field = JTextField(auto_target)
            form_panel.add(self.target_field, gbc)

            # Row 1: Tags
            gbc.gridx = 0
            gbc.gridy = 1
            gbc.weightx = 0.0
            form_panel.add(JLabel("Tags:"), gbc)

            gbc.gridx = 1
            gbc.gridwidth = 3
            gbc.weightx = 1.0
            self.tags_field = JTextField()
            self.tags_field.setToolTipText("Comma-separated tags e.g. idor, auth, graphql")
            form_panel.add(self.tags_field, gbc)

            # Row 2: Note Text
            gbc.gridx = 0
            gbc.gridy = 2
            gbc.gridwidth = 1
            gbc.weightx = 0.0
            gbc.anchor = GridBagConstraints.NORTH
            form_panel.add(JLabel("Note:"), gbc)

            gbc.gridx = 1
            gbc.gridwidth = 3
            gbc.weightx = 1.0
            gbc.weighty = 1.0
            gbc.fill = GridBagConstraints.BOTH
            self.text_area = JTextArea()
            self.text_area.setLineWrap(True)
            self.text_area.setWrapStyleWord(True)
            self.text_area.setRows(8)

            # Key Listener for Ctrl+Enter / Cmd+Enter
            class SaveShortcutListener(KeyAdapter):
                def __init__(dialog_self):
                    self.dialog_ref = dialog_self
                def keyPressed(k_self, event):
                    is_ctrl_or_cmd = (event.getModifiers() & (KeyEvent.CTRL_MASK | KeyEvent.META_MASK)) != 0
                    if is_ctrl_or_cmd and event.getKeyCode() == KeyEvent.VK_ENTER:
                        event.consume()
                        self.save_and_close()

            self.text_area.addKeyListener(SaveShortcutListener())
            form_panel.add(JScrollPane(self.text_area), gbc)

            content_panel.add(form_panel, BorderLayout.CENTER)

            # Bottom Action Bar
            btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 4))
            hint_lbl = JLabel("Press Ctrl+Enter to save")
            hint_lbl.setFont(Font("SansSerif", Font.ITALIC, 11))
            hint_lbl.setForeground(Color.GRAY)
            btn_panel.add(hint_lbl)

            cancel_btn = JButton("Cancel")
            class CancelListener(ActionListener):
                def actionPerformed(c_self, e):
                    self.dispose()
            cancel_btn.addActionListener(CancelListener())
            btn_panel.add(cancel_btn)

            save_btn = JButton("Save Note")
            save_btn.setFont(Font("SansSerif", Font.BOLD, 12))
            class SaveBtnListener(ActionListener):
                def actionPerformed(s_self, e):
                    self.save_and_close()
            save_btn.addActionListener(SaveBtnListener())
            btn_panel.add(save_btn)

            content_panel.add(btn_panel, BorderLayout.SOUTH)

            self.setContentPane(content_panel)

        def save_and_close(self):
            entry_type = str(self.type_combo.getSelectedItem())
            target = str(self.target_field.getText()).strip()
            raw_tags = str(self.tags_field.getText()).strip()
            tags = [t.strip().lstrip("#") for t in raw_tags.split(",") if t.strip()]
            text = str(self.text_area.getText()).strip()

            if not text and not self.linked_requests:
                # Don't save completely empty notes
                self.dispose()
                return

            def bg_save():
                try:
                    entry = self.store.create_entry(
                        entry_type=entry_type,
                        text=text,
                        tags=tags,
                        target=target,
                        linked_requests=self.linked_requests
                    )
                    logger.info("Quick capture entry saved: %s", entry.id)
                    if self.on_save_callback:
                        SwingUtilities.invokeLater(lambda: self.on_save_callback(entry))
                except Exception as ex:
                    logger.error("Failed to save quick capture note: %s", ex)

            t = threading.Thread(target=bg_save)
            t.daemon = True
            t.start()

            self.dispose()
else:
    class QuickCaptureDialog(object):
        pass
