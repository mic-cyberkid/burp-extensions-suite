# Shared reporter for cross-extension findings

class FindingReporter:
    _instance = None

    def __init__(self):
        self.add_finding_callback = None
        # Storage for findings if the reporter is not yet loaded
        self.pending_findings = []

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def report(self, finding_dict):
        """
        finding_dict expected keys:
        - name
        - severity
        - confidence
        - url
        - description
        - remediation
        """
        if self.add_finding_callback:
            try:
                self.add_finding_callback(
                    finding_dict.get('name'),
                    finding_dict.get('severity'),
                    finding_dict.get('confidence'),
                    finding_dict.get('url'),
                    finding_dict.get('description'),
                    finding_dict.get('remediation')
                )
            except Exception as e:
                print("Error in report callback: " + str(e))
        else:
            self.pending_findings.append(finding_dict)
            print("Finding reported (pending tracker): " + finding_dict.get('name'))

    def register_callback(self, callback):
        self.add_finding_callback = callback
        # Flush pending findings
        while self.pending_findings:
            f = self.pending_findings.pop(0)
            self.report(f)
