# JWT IDOR Tester

The JWT IDOR Tester is a "ruthless" tool designed specifically to uncover Insecure Direct Object Reference (IDOR) vulnerabilities within applications that use JSON Web Tokens (JWT) for session management or authorization.

## Features
- **Automatic Field Detection**: Identifies ID-like fields in the JWT payload (e.g., `id`, `user_id`, `sub`, `account`).
- **Ruthless Mutation Strategies**:
    - **`alg: none` Bypass**: Automatically attempts to bypass signature verification by changing the algorithm to `none`.
    - **Integer Manipulation**: Increments/decrements numeric IDs.
    - **Hex/ObjectID Variation**: Flips bits or changes neighboring characters in hexadecimal IDs (common in MongoDB).
    - **Empty Signature**: Tests if the server incorrectly accepts tokens with the original algorithm but no signature.
- **Results Dashboard**: A dedicated UI tab ("JWT IDOR") that displays the results of every mutation attempt, including HTTP status codes and response lengths.
- **Success Identification**: Automatically flags 200 OK responses as potential IDOR hits and reports them to the global **Report Generator**.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `IContextMenuFactory`, `ITab`).
- **Threaded Execution**: Mutation tests are run in background threads to keep the Burp UI responsive.

## How to Use
1. Load the extension via `extensions/jwt-idor-tester/src/JWTIDORTester.py`.
2. Find a request containing a JWT in the `Authorization: Bearer` header (in Proxy history or Repeater).
3. Right-click the request and select **Test for JWT IDOR**.
4. Monitor the **JWT IDOR** tab for results.
5. Any successful bypasses (200 OK) will be automatically added to the **Tracker** tab findings.
