# Automated Parameter Fuzzer

The Automated Parameter Fuzzer provides smart fuzzing capabilities for identifying injection vulnerabilities such as SQL Injection (SQLi) and Cross-Site Scripting (XSS).

## Features
- **Smart Payloads**: Includes a curated list of payloads for SQLi and XSS.
- **Intruder Integration**: Registers as a custom payload generator and processor in Burp Intruder.
- **Anomaly Detection**: Basic logic to identify potential vulnerabilities based on HTTP status code changes and significant response length variations.
- **Extensible**: Easily updated with new payload types or detection rules.

## Implementation Details
- **Language**: Java 17.
- **API**: Montoya API.
- **Build System**: Maven.
- **Key Interfaces**: `PayloadGeneratorProvider`, `PayloadGenerator`, `PayloadProcessor`.

## How to Use
1. Build the extension using `mvn package` in `extensions/param-fuzzer/`.
2. Load the generated `param-fuzzer-1.0-SNAPSHOT-jar-with-dependencies.jar` into Burp.
3. Send a request to **Intruder**.
4. In the **Payloads** tab, select **Payload type**: `Extension-generated`.
5. Select **Smart Fuzzer Payloads** from the list.
6. Start the attack.
