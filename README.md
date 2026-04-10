# ICS-OT Smart Grid Network Detection & Response (AI-Based)

## Overview
This project implements a Network Detection and Response (NDR) system designed for Industrial Control Systems (ICS/OT) in Smart Grid environments.

The system analyzes industrial network traffic, detects anomalies, classifies cyber attacks, and simulates response actions to protect electrical infrastructure such as substations and power systems.

## Objectives

- Detect abnormal behavior in industrial network traffic  
- Classify cyber attacks (DoS, scanning, flooding, etc.)  
- Support real-time monitoring and alerting  
- Generalize detection across multiple industrial vendors (ABB, Siemens, Schneider)  

## Key Features

- Real-time traffic analysis (simulated streaming)  
- AI-based detection:
  - XGBoost for known attack classification  
  - Autoencoder for anomaly and zero-day detection  
- Severity classification (LOW, MEDIUM, HIGH, CRITICAL)  
- Attack grouping (Flood, Scan, Exploit, etc.)  
- Structured logging (SOC-style)  
- Response simulation (block, alert, log)  
- REST API using FastAPI  
- Ready for frontend or dashboard integration  

## Project Structure

NDR_Project/
```
api/  
engine/  
models/  
preprocessing/  
config/  
utils/  
```
requirements.txt  
README.md  

## Installation

pip install -r requirements.txt

## Running the System

uvicorn api.api:app --host 0.0.0.0 --port 8000

Open in browser:
http://127.0.0.1:8000/docs

## API Usage

POST /predict

## Example Input
```
{
  "duration": 0.5,
  "sPackets": 100,
  "rPackets": 5,
  "sBytesSum": 15000,
  "rBytesSum": 300,
  "sLoad": 240000,
  "rLoad": 4800,
  "sSynRate": 0.0,
  "sAckRate": 1.0,
  "sFinRate": 0.0,
  "sRstRate": 0.0,
  "sPayloadAvg": 150,
  "rPayloadAvg": 60,
  "protocol": "tcp",
  "sAddress": "192.168.1.10"
}
```
## Example Output

{
  "attack": "UNKNOWN",
  "group": "UNKNOWN_THREAT",
  "severity": "HIGH",
  "confidence": 98.4,
  "recon_error": 35.2,
  "detected_by": "Autoencoder",
  "action": "Isolate + investigate"
}

## Detection Logic

XGBoost: Known attack detection  
Autoencoder: Anomaly and zero-day detection  


------------------------------------------------------------------------

## Datasets

##

Layer 1: Core  
Layer 2: Diversity  
Layer 3: Cross-vendor  


```

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
