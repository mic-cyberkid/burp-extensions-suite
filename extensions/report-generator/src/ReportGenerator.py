from burp import IBurpExtender
from burp import ITab
from burp import IExtensionStateListener
from javax.swing import JPanel, JScrollPane, JTable, JLabel, JButton, JTextArea, SwingUtilities, JFileChooser
from java.awt import BorderLayout
from javax.swing.table import DefaultTableModel
import sys
import os

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        # Resolve paths without relying on __file__
        extension_file = callbacks.getExtensionFilename()
        base_dir = os.path.dirname(extension_file)
        common_dir = os.path.join(base_dir, "../../../common/python")

        if base_dir not in sys.path: sys.path.append(base_dir)
        if common_dir not in sys.path: sys.path.append(common_dir)

        # Deferred imports to ensure sys.path is ready
        from ReportLogic import ReportLogic
        from burp_utils import get_logger
        from burp_shared import FindingReporter

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Report Generator and Vulnerability Tracker")

        self._logger = get_logger("ReportGenerator")
        self._reporter = FindingReporter.get()

        # Path for persistence
        persistence_path = os.path.join(os.path.expanduser("~"), "burp_vuln_tracker.json")
        self.logic = ReportLogic(persistence_path)

        # Setup UI
        self.setup_ui()

        # Register listeners
        callbacks.registerExtensionStateListener(self)
        callbacks.addSuiteTab(self)

        # Register with shared reporter
        self._reporter.register_callback(self.addFinding)

        self._logger.info("Report Generator loaded. Persistence at: " + persistence_path)

    def setup_ui(self):
        self.panel = JPanel(BorderLayout())

        # Table for findings
        self.column_names = ["Issue", "Severity", "URL", "Timestamp"]
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.refresh_table()

        self.table = JTable(self.table_model)
        scroll_pane = JScrollPane(self.table)

        # Buttons
        button_panel = JPanel()

        refresh_btn = JButton("Refresh", actionPerformed=lambda x: self.refresh_table())
        export_md_btn = JButton("Export Markdown", actionPerformed=lambda x: self.export_report("md"))
        export_html_btn = JButton("Export HTML", actionPerformed=lambda x: self.export_report("html"))
        clear_btn = JButton("Clear All", actionPerformed=lambda x: self.clear_findings())

        button_panel.add(refresh_btn)
        button_panel.add(export_md_btn)
        button_panel.add(export_html_btn)
        button_panel.add(clear_btn)

        self.panel.add(JLabel("Vulnerability Tracker"), BorderLayout.NORTH)
        self.panel.add(scroll_pane, BorderLayout.CENTER)
        self.panel.add(button_panel, BorderLayout.SOUTH)

    def refresh_table(self):
        self.table_model.setRowCount(0)
        for f in self.logic.findings:
            self.table_model.addRow([f['name'], f['severity'], f['url'], f['timestamp']])

    def clear_findings(self):
        self.logic.findings = []
        self.logic.save_findings()
        self.refresh_table()

    def export_report(self, format):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            if format == "md":
                content = self.logic.generate_markdown()
                if not file_path.endswith(".md"): file_path += ".md"
            else:
                content = self.logic.generate_html()
                if not file_path.endswith(".html"): file_path += ".html"

            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                self._callbacks.issueAlert("Report exported to " + file_path)
            except Exception as e:
                self._logger.error("Failed to export report: " + str(e))

    def getTabCaption(self):
        return "Tracker"

    def getUiComponent(self):
        return self.panel

    def extensionUnloaded(self):
        self.logic.save_findings()
        self._logger.info("Report Generator unloaded.")

    # Public API for other extensions
    def addFinding(self, name, severity, confidence, url, description, remediation):
        self.logic.add_finding(name, severity, confidence, url, description, remediation)
        SwingUtilities.invokeLater(self.refresh_table)
