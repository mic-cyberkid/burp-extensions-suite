# API Documentation & Swagger Miner

This extension passively scans for API documentation and extracts potential endpoints for further testing.

## Features
- **Swagger/OpenAPI Detection**: Automatically identifies common API documentation paths (e.g., `/swagger.json`, `/v2/api-docs`).
- **Endpoint Extraction**: Parses JSON Swagger/OpenAPI files to extract all defined API paths.
- **Information Gathering**: Helps pentesters quickly map out an application's internal or undocumented APIs.
- **Custom Tab**: Displays discovered API documentation and the count of extracted endpoints.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `ITab`).
- **Parsing**: Uses a combination of JSON parsing and regex for robust extraction.

## How to Use
1. Load the extension via `extensions/api-miner/src/APIMiner.py`.
2. Browse the application.
3. Check the **API Miner** tab for discovered documentation.
4. Review extracted endpoints in the extension console.
