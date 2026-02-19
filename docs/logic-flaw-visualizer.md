# Logic Flaw & State Machine Visualizer

This extension helps security researchers visualize and identify logical flaws and state machine bypasses in authentication and business logic flows.

## Features

- **Flow Recording**: Automatically captures and logs HTTP requests and responses to critical endpoints (login, reset, verify, etc.).
- **State Machine Visualization**: Uses a Swing-based `JTree` to display the sequence of operations, making it easy to see the order of transitions.
- **Anomaly Detection**: Flags suspicious patterns, such as a "password change" success without preceding "reset" or "OTP" steps.
- **Unified Logging**: Anomalies and significant transitions are logged to the Burp extension console.

## Implementation Details

- **Language**: Java 17.
- **API**: Montoya API.
- **Build System**: Maven.
- **Key Interface**: `HttpHandler` for flow capture, `SuiteTab` for the UI.

## How to Use

1. Build the extension using `mvn package` in `extensions/logic-flaw-visualizer/`.
2. Load the generated JAR into Burp.
3. Open the **Logic Visualizer** tab.
4. Interact with the target application's authentication, registration, or password reset flows.
5. Review the tree view to see the flow of states and check for any unexpected transitions or step-skipping vulnerabilities.
