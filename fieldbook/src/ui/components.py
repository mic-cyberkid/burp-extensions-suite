"""
UI Components and Color Schemes for Fieldbook.
"""

try:
    from javax.swing import (
        JPanel, JLabel, JTextField, JComboBox, DefaultComboBoxModel,
        JComponent, SwingUtilities, BorderFactory, JTextArea, JScrollPane
    )
    from java.awt import (
        Color, Font, Dimension, FlowLayout, BorderLayout,
        Graphics, Graphics2D, RenderingHints
    )
    from java.awt.event import KeyAdapter, KeyEvent
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

ENTRY_TYPE_COLORS = {
    "NOTE": {"bg": "#e2e8f0", "fg": "#334155", "border": "#cbd5e1"},
    "OBSERVATION": {"bg": "#dbeafe", "fg": "#1e40af", "border": "#93c5fd"},
    "HYPOTHESIS": {"bg": "#fef3c7", "fg": "#92400e", "border": "#fde68a"},
    "TEST_RESULT": {"bg": "#e0e7ff", "fg": "#3730a3", "border": "#c7d2fe"},
    "EVIDENCE": {"bg": "#dcfce7", "fg": "#166534", "border": "#86efac"},
    "TODO": {"bg": "#fee2e2", "fg": "#991b1b", "border": "#fca5a5"}
}

def hex_to_color(hex_str, default_color=None):
    if not GUI_AVAILABLE:
        return None
    if not hex_str or not hex_str.startswith("#"):
        return default_color or Color.GRAY
    hex_str = hex_str.lstrip("#")
    if len(hex_str) == 6:
        r = int(hex_str[0:2], 16)
        g = int(hex_str[2:4], 16)
        b = int(hex_str[4:6], 16)
        return Color(r, g, b)
    return default_color or Color.GRAY


if GUI_AVAILABLE:
    class ColorChipLabel(JLabel):
        """
        Custom color-coded pill chip for entry_type badges.
        """
        def __init__(self, text, entry_type="NOTE"):
            JLabel.__init__(self, " " + str(text) + " ")
            self.setFont(Font("SansSerif", Font.BOLD, 10))
            color_def = ENTRY_TYPE_COLORS.get(entry_type, ENTRY_TYPE_COLORS["NOTE"])
            self.bg_color = hex_to_color(color_def["bg"])
            self.fg_color = hex_to_color(color_def["fg"])
            self.border_color = hex_to_color(color_def["border"])

            self.setForeground(self.fg_color)
            self.setOpaque(False)
            self.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(self.border_color, 1),
                BorderFactory.createEmptyBorder(2, 6, 2, 6)
            ))

        def paintComponent(self, g):
            g2 = g.create()
            if hasattr(g2, "setRenderingHint"):
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g2.setColor(self.bg_color)
            g2.fillRoundRect(0, 0, self.getWidth(), self.getHeight(), 8, 8)
            g2.dispose()
            JLabel.paintComponent(self, g)

    class TagAutoCompleteField(JPanel):
        """
        Combines a text field with inline tag autocompletion support.
        """
        def __init__(self, initial_tags="", available_tags=None):
            JPanel.__init__(self, BorderLayout())
            self.available_tags = available_tags or []
            self.text_field = JTextField(initial_tags)
            self.add(self.text_field, BorderLayout.CENTER)

        def get_tags_list(self):
            raw = self.text_field.getText()
            if not raw:
                return []
            parts = [p.strip().lstrip("#") for p in raw.split(",") if p.strip()]
            return list(set(parts))

        def set_tags(self, tags_list):
            if isinstance(tags_list, list):
                self.text_field.setText(", ".join(tags_list))
            else:
                self.text_field.setText(str(tags_list or ""))
else:
    class ColorChipLabel(object):
        pass
    class TagAutoCompleteField(object):
        pass
