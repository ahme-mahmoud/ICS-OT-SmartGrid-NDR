# ICS-OT Smart Grid Network Detection & Response (AI-Based)

## Overview

This project presents a real-time AI-based Network Detection and
Response (NDR) system designed for Industrial Control Systems (ICS/OT)
in Smart Grid (electrical power systems) environments.

The system analyzes industrial network traffic, detects anomalies,
classifies cyber attacks, and generates alerts to simulate protection of
electrical substations and power infrastructure.

------------------------------------------------------------------------

## Objectives

-   Detect abnormal behavior in industrial power networks\
-   Classify cyber attacks (DoS, scanning, flooding, etc.)\
-   Support real-time monitoring and alerting\
-   Generalize across multiple industrial vendors (ABB, Siemens,
    Schneider)

------------------------------------------------------------------------

## Key Features

-   Real-time traffic analysis (simulated streaming)\
-   AI-based anomaly detection\
-   Multi-class attack classification\
-   Multi-vendor dataset support\
-   Alerting and response simulation\
-   Interactive dashboard (Streamlit)

------------------------------------------------------------------------

## Datasets

```
ذذ```
Datasets/
├── 01_core/
│   └── ABB_LONG_tcpflood_faster_1_01-.csv
│
├── 02_diversity/
│   ├── ABB_nmap_0715_.csv
│   ├── ABB_pingofdeath_0715_.csv
│   ├── ABB_portscan_0715.csv
│   ├── ABB_smurf_faster_0715_01_.csv
│   ├── ABB_teardrop_fast_0715.csv
│   └── ABB_winNuke_faster_0715_part1.csv
│
├── 03_cross_vendor/
│   ├── Schneider_portscan_0710.csv
│   └── Siemens_pingofdeath_0710-.csv

```


------------------------------------------------------------------------

### Layer 1: Core Dataset (Real Industrial Traffic)

-   ABB_LONG_tcpflood_faster_1_01-.csv

Purpose:

-   Simulates real-world high-volume industrial traffic\
-   Represents DoS attacks on smart grid / power systems\
-   Used for primary model training (baseline learning)

------------------------------------------------------------------------

### Layer 2: Attack Diversity (Behavior Coverage)

#### Selected Datasets:

-   ABB_portscan_0715.csv\
-   ABB_nmap_0715\_.csv\
-   ABB_pingofdeath_0715\_.csv\
-   ABB_smurf_faster_0715_01\_.csv\
-   ABB_teardrop_fast_0715.csv\
-   ABB_winNuke_faster_0715_part1.csv

Purpose:

-   Introduces diverse attack behaviors\
-   Improves model generalization\
-   Enables multi-class attack classification

Attack Mapping:

-   ABB_portscan_0715.csv → Recon (Network Scanning)\
-   ABB_nmap_0715\_.csv → Advanced Recon\
-   ABB_pingofdeath_0715\_.csv → DoS (Packet-based)\
-   ABB_smurf_faster_0715_01\_.csv → Amplification Attack\
-   ABB_teardrop_fast_0715.csv → Fragmentation Attack\
-   ABB_winNuke_faster_0715_part1.csv → Exploit-style Attack

------------------------------------------------------------------------

### Layer 3: Cross-Vendor Validation (Generalization)

#### Selected Datasets:

-   Schneider_portscan_0710.csv\
-   Siemens_pingofdeath_0710-.csv

Purpose:

-   Simulates different industrial environments\
-   Tests model robustness across vendors\
-   Ensures the system is not vendor-dependent

------------------------------------------------------------------------

## Training Strategy

-   Training Data: Layer 1 + Layer 2 (ABB datasets only)\
-   Testing Data: Layer 3 (Siemens and Schneider datasets)

Key Insight:

-   The model is trained on a single vendor (ABB)\
-   It is evaluated on different vendors to test generalization\
-   This simulates real-world deployment in heterogeneous industrial
    environments

------------------------------------------------------------------------

## System Workflow (Real-Time)

1.  Network traffic is captured (CSV stream, Zeek, or PCAP)\
2.  Features are extracted from traffic\
3.  Data is passed to the trained ML model\
4.  The model predicts:
    -   BENIGN\
    -   ATTACK (with type)\
5.  Alerts are generated and displayed

------------------------------------------------------------------------

## Final Objective

Build an AI-based ICS/OT NDR system capable of:

-   Detecting anomalies in industrial power networks (Smart Grid)\
-   Classifying multiple attack types\
-   Operating in real-time environments\
-   Generalizing across different ICS vendors (ABB, Siemens, Schneider)

------------------------------------------------------------------------

## Summary

-   Layer 1: Core attack (TCP Flood)\
-   Layer 2: Attack diversity (behavior coverage)\
-   Layer 3: Cross-vendor validation
