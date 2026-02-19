# Report Generation and Vulnerability Tracking Logic

import json
import os
from datetime import datetime

class ReportLogic:
    def __init__(self, persistence_file):
        self.persistence_file = persistence_file
        self.findings = self.load_findings()

    def load_findings(self):
        if os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def save_findings(self):
        try:
            with open(self.persistence_file, 'w') as f:
                json.dump(self.findings, f, indent=4)
        except Exception as e:
            print("Error saving findings: " + str(e))

    def add_finding(self, name, severity, confidence, url, description, remediation):
        # Avoid duplicates
        for f in self.findings:
            if f['name'] == name and f['url'] == url:
                return False

        finding = {
            'name': name,
            'severity': severity,
            'confidence': confidence,
            'url': url,
            'description': description,
            'remediation': remediation,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.findings.append(finding)
        self.save_findings()
        return True

    def generate_markdown(self):
        md = "# Vulnerability Assessment Report\n"
        md += "Generated on: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if not self.findings:
            md += "No findings recorded.\n"
            return md

        md += "## Summary\n"
        md += "| Issue | Severity | URL |\n"
        md += "| --- | --- | --- |\n"
        for f in self.findings:
            md += "| {} | {} | {} |\n".format(f['name'], f['severity'], f['url'])

        md += "\n## Detailed Findings\n"
        for f in self.findings:
            md += "### {}\n".format(f['name'])
            md += "- **Severity**: {}\n".format(f['severity'])
            md += "- **Confidence**: {}\n".format(f['confidence'])
            md += "- **URL**: {}\n".format(f['url'])
            md += "- **Timestamp**: {}\n\n".format(f['timestamp'])
            md += "#### Description\n{}\n\n".format(f['description'])
            md += "#### Remediation\n{}\n\n".format(f['remediation'])
            md += "---\n\n"

        return md

    def generate_html(self):
        html = "<html><head><title>Vulnerability Report</title>"
        html += "<style>body { font-family: sans-serif; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ccc; padding: 8px; text-align: left; } th { background-color: #eee; }</style>"
        html += "</head><body>"
        html += "<h1>Vulnerability Assessment Report</h1>"
        html += "<p>Generated on: {}</p>".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if not self.findings:
            html += "<p>No findings recorded.</p></body></html>"
            return html

        html += "<h2>Summary</h2><table><tr><th>Issue</th><th>Severity</th><th>URL</th></tr>"
        for f in self.findings:
            html += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(f['name'], f['severity'], f['url'])
        html += "</table>"

        for f in self.findings:
            html += "<h2>{}</h2>".format(f['name'])
            html += "<p><b>Severity:</b> {} | <b>Confidence:</b> {}</p>".format(f['severity'], f['confidence'])
            html += "<p><b>URL:</b> {}</p>".format(f['url'])
            html += "<h3>Description</h3><p>{}</p>".format(f['description'])
            html += "<h3>Remediation</h3><p>{}</p>".format(f['remediation'])
            html += "<hr>"

        html += "</body></html>"
        return html
