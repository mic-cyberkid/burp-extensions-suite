# ApexBountyToolkit - Unified Burp Suite Bug Bounty Extension

ApexBountyToolkit is an advanced, unified Jython 2.7 Burp Suite extension designed for elite security engineers and bug bounty hunters. It integrates four powerful security testing tools into a clean, multi-tabbed Java Swing interface.

---

## The Four Included Tools

### 1. State-Aware Logic Breaker (Tab 1)
- **Purpose:** Identifies multi-step business logic flaws and state-machine bypasses by permuting recorded request sequences.
- **Key Features:**
  - Send requests directly from Burp Proxy/Repeater via right-click context menu ("Send to Logic Breaker").
  - Sequence builder view displaying recorded step order.
  - Automatic permutation attack generation:
    - Step removal (dropping step 1, 2, etc.)
    - Step duplication (repeating steps)
    - Sequence reversal
    - Adjacent step swapping
    - Direct jump to final step
  - Real-time results logging with final HTTP status code and response length comparison.

### 2. LLM Context Fuzzer (Tab 2)
- **Purpose:** Context-aware WAF bypass payload generation using LLM models (OpenAI/Anthropic APIs) or smart fallback payloads.
- **Key Features:**
  - Automatic parameter extraction from URL query parameters, POST body parameters, and JSON keys.
  - Customizable API Key and LLM Endpoint URL (`https://api.openai.com/v1/chat/completions`).
  - Context-aware prompt construction requesting bypass payloads tailored specifically to parameter names.
  - Asynchronous HTTP payload generation and injection.
  - Interactive fuzzing results table paired with a Burp `IMessageEditor` response viewer.

### 3. Multi-Endpoint Race Orchestrator (Tab 3)
- **Purpose:** Discovers race conditions across two distinct HTTP endpoints simultaneously.
- **Key Features:**
  - Dual `IMessageEditor` panels for Request A and Request B.
  - High-precision synchronization using Java's `java.util.concurrent.CountDownLatch`.
  - Configurable thread count (e.g. 20–50 threads) and delay settings.
  - Releases queued threads at the exact same millisecond.
  - Custom table cell renderer highlighting anomalous responses (500 status codes, deviating content lengths) in soft red and yellow.

### 4. Dynamic Privilege Matrix (Tab 4)
- **Purpose:** Automated BOLA (Broken Object Level Authorization) and IDOR detection via background session replays across distinct authorization roles.
- **Key Features:**
  - Configuration grid for 4 distinct roles: Admin, User A, User B, Unauth.
  - Background `IHttpListener` toggle ("Enable Background Matrix Replay").
  - Strips existing session headers (`Authorization`, `Cookie`, `X-Auth-Token`, etc.) and injects configured role headers for each request intercepted via Proxy.
  - Live matrix UI featuring status indicators color-coded by HTTP status (Green = 200 OK, Red = 401/403, Yellow = Redirects, Orange = Server Errors).
  - Role-by-role response inspectors using Burp `IMessageEditor` tabs.

---

## Step-by-Step Loading Instructions in Burp Suite

### Prerequisites
1. Download Jython 2.7 Standalone JAR (e.g., `jython-standalone-2.7.3.jar`).
2. Open **Burp Suite**.
3. Navigate to **Extensions** > **Options** (or **Extender** > **Options** in older Burp versions).
4. Under **Python Environment**, click **Select file...** and select your downloaded `jython-standalone-2.7.3.jar`.

### Loading ApexBountyToolkit
1. In Burp Suite, navigate to **Extensions** > **Installed**.
2. Click **Add**.
3. In the **Add Extension** dialog:
   - **Extension type:** Select `Python`.
   - **Extension file:** Browse to and select `extensions/apexbounty-toolkit/src/ApexBountyToolkit.py`.
4. Click **Next**.
5. Verify that the output tab displays:
   `[+] ApexBountyToolkit successfully loaded and initialized!`
6. You will now see a new top-level tab in Burp Suite titled **"Apex Toolkit"**.

---

## Technical & Swing UI Architecture

### Swing UI Thread Safety
- **CRITICAL:** Swing components in Jython/Burp Suite are not thread-safe. All UI state changes (adding rows to `JTable`, updating label text, enabling/disabling buttons) are wrapped in `SwingUtilities.invokeLater()` to prevent locking or freezing the main Burp Suite GUI.
- Network requests, active fuzzing, and race attack executions run strictly inside background threads (`threading.Thread` or `java.lang.Thread`).

### Burp API Integration Breakdown
- `IBurpExtender`: Main entry point class implementing `registerExtenderCallbacks()`.
- `ITab`: Registers the top-level `"Apex Toolkit"` tab with `addSuiteTab()`.
- `IHttpListener`: Listens to `TOOL_PROXY` traffic for background Privilege Matrix replays.
- `IContextMenuFactory`: Provides right-click context menu options across Proxy, Repeater, Target, and Logger tabs.
- `IMessageEditor`: Embedded Burp message editors for viewing and editing raw HTTP requests and responses cleanly.
