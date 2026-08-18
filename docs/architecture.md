# Architecture Overview

The Burp Extensions Suite is designed as a modular monorepo containing both Java (Montoya API) and Python (Legacy API) extensions.

## System Diagram

```mermaid
graph TD
    Burp[Burp Suite Community Edition]

    subgraph "Legacy API (Python/Jython)"
        PS[Passive Scanner]
        AA[Auth Analyzer]
        RG[Report Generator]
        RO[Reset/OTP Analyzer]
        JS[JS Miner]
        CH[Cloud Hunter]
        TD[Tech Detector]
        GQ[GraphQL Auditor]
        AM[API Miner]
        SH[Subdomain Hunter]
        JI[JWT IDOR Tester]
        JA[Jules AI]
    end

    subgraph "Montoya API (Java)"
        PF[Param Fuzzer]
        CD[Custom Decoder]
        LV[Logic Visualizer]
    end

    Burp --> PS
    Burp --> AA
    Burp --> RG
    Burp --> PF
    Burp --> CD
    Burp --> RO
    Burp --> LV
    Burp --> JS
    Burp --> CH
    Burp --> TD
    Burp --> GQ
    Burp --> AM
    Burp --> SH
    Burp --> JI
    Burp --> JA

    PS -.-> RG
    AA -.-> RG
    PF -.-> RG
```

## Modular Design
Each extension is self-contained in its own directory under `extensions/`, with its own build and test configurations.

## Shared Utilities
- `common/java`: Shared Java logic for the Montoya API extensions.
- `common/python`: Shared Python logic for the Legacy API extensions.
