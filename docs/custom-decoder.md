# Custom Decoder/Encoder

The Custom Decoder/Encoder provides a flexible framework for decoding and encoding data in various formats, helping pentesters deal with non-standard or proprietary data representations.

## Features
- **Auto-Detection**: Automatically identifies potential encodings (Base64, Hex) and attempts to decode them if the result is printable ASCII.
- **Transformations**:
    - **Base64**: Standard Base64 decoding.
    - **Hex**: Converts hexadecimal strings to plain text.
    - **XOR**: (Logic implemented) Support for single-byte XOR transformations.
- **Message Editor Integration**: Adds a "Custom Decoder" tab to the Burp HTTP request editor, allowing for quick analysis of request bodies.

## Implementation Details
- **Language**: Java 17.
- **API**: Montoya API.
- **Build System**: Maven.
- **Key Interface**: `HttpRequestEditorProvider`, `ExtensionProvidedHttpRequestEditor`.

## How to Use
1. Build the extension using `mvn package` in `extensions/custom-decoder/`.
2. Load the generated `custom-decoder-1.0-SNAPSHOT-jar-with-dependencies.jar` into Burp.
3. Select any request in Burp (e.g., in Proxy history or Repeater).
4. Click the **Custom Decoder** tab in the request viewer.
5. Click **Auto-Detect & Decode** to analyze the request body.
