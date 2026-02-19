# GraphQL Security Auditor

This extension passively scans for common GraphQL security misconfigurations and data exposure issues.

## Features
- **Introspection Detection**: Identifies if GraphQL introspection is enabled, which allows attackers to map the entire API schema.
- **Sensitive Data Exposure**: Scans GraphQL responses for potentially sensitive fields such as `password`, `token`, `secret`, `email`, etc.
- **Automatic Identification**: Recognizes GraphQL traffic based on URL patterns and request body content.
- **Reporting**: Integrates with the global **Report Generator**.

## Implementation Details
- **Language**: Python (Jython 2.7 compatible).
- **API**: Legacy Burp Extender API (`IBurpExtender`, `IHttpListener`, `ITab`).

## How to Use
1. Load the extension via `extensions/graphql-auditor/src/GraphQLAuditor.py`.
2. Browse the application.
3. Check the **GraphQL Auditor** tab for findings.
