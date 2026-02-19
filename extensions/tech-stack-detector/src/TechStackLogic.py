import re

class TechStackLogic:
    def __init__(self):
        # Fingerprints for various technologies
        self.fingerprints = {
            "Server Headers": {
                "Apache": r"Apache",
                "Nginx": r"nginx",
                "IIS": r"Microsoft-IIS",
                "LiteSpeed": r"LiteSpeed"
            },
            "Powered-By Headers": {
                "PHP": r"PHP",
                "ASP.NET": r"ASP.NET",
                "Express": r"Express",
                "Phusion Passenger": r"Phusion Passenger"
            },
            "Frameworks (Cookies/Content)": {
                "Django": r"csrftoken",
                "Laravel": r"laravel_session",
                "React": r"data-reactroot",
                "Vue.js": r"v-attr|v-bind",
                "Angular": r"ng-app|ng-controller|ng-version",
                "WordPress": r"wp-content|wp-includes",
                "Drupal": r"Drupal",
                "Joomla": r"Joomla"
            }
        }

    def analyze_message(self, headers, body):
        detected = set()

        # Check headers
        for h_name, h_val in headers.items():
            h_name_lower = h_name.lower()
            if h_name_lower == "server":
                for tech, pattern in self.fingerprints["Server Headers"].items():
                    if re.search(pattern, h_val, re.IGNORECASE):
                        detected.add(tech)
            elif h_name_lower == "x-powered-by":
                for tech, pattern in self.fingerprints["Powered-By Headers"].items():
                    if re.search(pattern, h_val, re.IGNORECASE):
                        detected.add(tech)
            elif h_name_lower == "set-cookie":
                 for tech, pattern in self.fingerprints["Frameworks (Cookies/Content)"].items():
                    if re.search(pattern, h_val, re.IGNORECASE):
                        detected.add(tech)

        # Check body
        for tech, pattern in self.fingerprints["Frameworks (Cookies/Content)"].items():
            if re.search(pattern, body, re.IGNORECASE):
                detected.add(tech)

        return list(detected)
