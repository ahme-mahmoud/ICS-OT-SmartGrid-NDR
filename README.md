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

### Layer 1: Core Dataset

-   ABB_LONG_tcpflood_faster_1_01-.csv

### Layer 2: Attack Diversity

-   ABB_portscan_0715.csv\
-   ABB_nmap_0715\_.csv\
-   ABB_pingofdeath_0715\_.csv

### Layer 3: Cross-Vendor Validation

-   Schneider_portscan_0710.csv\
-   Siemens_pingofdeath_0710.csv

These datasets represent industrial network traffic similar to
electrical substations and smart grid environments.

------------------------------------------------------------------------
