# Jules AI Assistant

The Jules AI Assistant brings the power of advanced AI reasoning directly into Burp Suite to help you identify complex vulnerabilities and business logic flaws.

## Features
- **Deep Contextual Analysis**: Analyze full request/response pairs with a security-focused AI agent.
- **Logic Flaw Detection**: Specifically designed to spot subtle logic bypasses and authorization issues that traditional scanners miss.
- **Ruthless Payload Generation**: Suggests targeted exploit payloads based on the observed application behavior.
- **Interactive Chat Interface**: Dedicated "Jules AI" tab to view analysis history and suggested steps.
- **Customizable Backend**: Configure your own LLM endpoint (e.g., OpenAI, Anthropic) and API key for full control.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `ITab`, `IContextMenuFactory`).
- **Communication**: Uses background threading to ensure the Burp UI remains responsive during AI processing.

## How to Use
1. Load the extension via `extensions/jules-ai-assistant/src/JulesAI.py`.
2. (Optional) Provide your AI API Key and Endpoint in the **Jules AI** tab.
3. Right-click any interesting request in Proxy, Repeater, or Intruder and select **Ask Jules AI for Analysis**.
4. Review the analysis and suggested payloads in the **Jules AI** tab.
5. Use the suggested payloads to verify vulnerabilities.
