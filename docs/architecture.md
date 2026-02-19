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

    PS -.-> RG
    AA -.-> RG
    PF -.-> RG
```

## Modular Design
Each extension is self-contained in its own directory under `extensions/`, with its own build and test configurations.

## Shared Utilities
- `common/java`: Shared Java logic for the Montoya API extensions.
- `common/python`: Shared Python logic for the Legacy API extensions.
