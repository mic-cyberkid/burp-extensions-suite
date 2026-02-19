# Fingerprinting & Tech Stack Detector

This extension identifies the technologies used by a web application by analyzing HTTP headers, cookies, and response bodies.

## Features
- **Header Analysis**: Checks `Server` and `X-Powered-By` headers for common server and language signatures.
- **Cookie Recognition**: Identifies frameworks through unique session cookie names (e.g., `laravel_session`, `csrftoken`).
- **Content Fingerprinting**: Detects front-end frameworks and CMS platforms by scanning response bodies for characteristic tags and paths (e.g., `data-reactroot`, `wp-content`).
- **Tech Dashboard**: Provides a consolidated view of the tech stack detected for each unique domain.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `ITab`).
- **Extensible Rules**: Uses a dictionary of regex patterns for tech identification.

## How to Use
1. Load the extension via `extensions/tech-stack-detector/src/TechStackDetector.py`.
2. Browse the application.
3. Check the **Tech Detector** tab to see the identified technologies for each domain you've visited.
