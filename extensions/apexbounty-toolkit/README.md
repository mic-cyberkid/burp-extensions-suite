# ApexBountyToolkit - Unified Burp Suite Bug Bounty Extension (Montoya API Edition)

ApexBountyToolkit is an advanced, unified Burp Suite extension written in **Java 17** using PortSwigger's modern **Montoya API** (`net.portswigger.burp.extensions:montoya-api`). It integrates four security testing tools into a clean, multi-tabbed Java Swing interface.

---

## The Four Included Tools

### 1. State-Aware Logic Breaker (Tab 1)
- **Purpose:** Identifies multi-step business logic flaws and state-machine bypasses by permuting recorded request sequences.
- **Key Features:**
  - Send requests directly from Burp Proxy/Repeater via right-click context menu ("Send to Logic Breaker").
  - Sequence builder view displaying recorded step order.
  - Target scope safety enforcement (`isInScope`) and cancellation control.
  - Automatic permutation attack generation (drops, duplicates, sequence reversal, adjacent swaps, jump to final step).

### 2. LLM Context Fuzzer (Tab 2)
- **Purpose:** Context-aware WAF bypass payload generation using LLM models or smart fallback payloads.
- **Key Features:**
  - Parameter extraction from URL query parameters, POST body parameters, and JSON keys via Montoya's native parameter API.
  - Secret header redaction (`Authorization`, `Cookie`, `X-API-Key`, etc.) before building prompts.
  - Default-off opt-in checkbox for external LLM API calls.
  - Password-masked API key field and configurable model name.
  - Object-level payload injection and automatic `Content-Length` management.

### 3. Multi-Endpoint Race Orchestrator (Tab 3)
- **Purpose:** Discovers race conditions across two distinct HTTP endpoints simultaneously.
- **Key Features:**
  - High-precision synchronization using `java.util.concurrent.CountDownLatch`.
  - Configurable thread count (capped at 100 per endpoint) and delay settings.
  - Pre-flight baseline request length collection for anomaly detection.
  - Custom cell renderer highlighting 500 errors and deviating content lengths.

### 4. Dynamic Privilege Matrix (Tab 4)
- **Purpose:** Automated BOLA and IDOR detection via background session replays across distinct authorization roles.
- **Key Features:**
  - Configuration grid for 4 distinct roles: Admin, User A, User B, Unauth.
  - Background `ProxyRequestHandler` replay.
  - Target scope enforcement (`isInScope`) and state-changing method safety filter (POST/PUT/DELETE).
  - Native header removal and injection via Montoya `HttpRequest` object methods.

---

## Building and Loading in Burp Suite

### Building the JAR
```bash
cd extensions/apexbounty-toolkit
mvn package
```
This builds `target/apexbounty-toolkit-1.0-SNAPSHOT-jar-with-dependencies.jar`.

### Loading into Burp Suite
1. Open **Burp Suite**.
2. Navigate to **Extensions** > **Installed**.
3. Click **Add**.
4. Set **Extension type** to `Java`.
5. Select `target/apexbounty-toolkit-1.0-SNAPSHOT-jar-with-dependencies.jar`.
6. Click **Next**.
7. Verify that output tab displays:
   `[+] ApexBountyToolkit (Montoya API Java Edition) successfully initialized!`
