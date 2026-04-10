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
```
{
  "attack": "UNKNOWN",
  "group": "UNKNOWN_THREAT",
  "severity": "HIGH",
  "confidence": 98.4,
  "recon_error": 35.2,
  "detected_by": "Autoencoder",
  "action": "Isolate + investigate"
}
```
## Detection Logic

XGBoost: Known attack detection  
Autoencoder: Anomaly and zero-day detection  


---

## Supported Attack Types

The system is capable of detecting the following attack categories:

### Known Attacks (XGBoost)

- TCP Flood  
- ICMP Flood  
- Ping of Death  
- Smurf  
- Teardrop  
- WinNuke  
- Portscan  
- Nmap  

### Unknown / Zero-Day Attacks (Autoencoder)

- Any anomalous or unseen network behavior  
- Deviations from normal industrial traffic patterns  

---

## Model Design

The system follows a hybrid AI architecture:

- XGBoost  
  A supervised machine learning model trained on labeled attack data  
  Responsible for detecting known attack patterns  

- Autoencoder  
  A deep learning model trained on normal traffic behavior  
  Used for anomaly detection and identifying zero-day attacks  

- Fusion Logic  
  Combines outputs from both models to produce the final decision  
  Improves detection accuracy and reduces false positives  

---

## Limitations

The current system does not yet cover:

- MITM / ARP Spoofing  
- Replay Attacks  
- Data Manipulation Attacks  

These attack types require deeper packet inspection and protocol-level analysis, which can be incorporated in future versions.

---

## Future Improvements

- Add detection for MITM and ARP Spoofing  
- Implement replay attack detection  
- Integrate deep packet inspection (DPI)  
- Deploy in real-time industrial environments  
- Build a frontend dashboard for monitoring  

---

---
## Datasets

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
---
### Layer 1: Core Dataset (Real Industrial Traffic)

-   ABB_LONG_tcpflood_faster_1_01-.csv

Purpose:

-   Simulates real-world high-volume industrial traffic\
-   Represents DoS attacks on smart grid / power systems\
-   Used for primary model training (baseline learning)

---
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

---
### Layer 3: Cross-Vendor Validation (Generalization)

#### Selected Datasets:

-   Schneider_portscan_0710.csv\
-   Siemens_pingofdeath_0710-.csv

Purpose:

-   Simulates different industrial environments\
-   Tests model robustness across vendors\
-   Ensures the system is not vendor-dependent

---
## Notes

- Large datasets are included for research and testing purposes  
- System is designed for simulation and academic use  
- Can be extended to real-time industrial deployment  

---

## Use Cases

- Smart Grid Security Monitoring  
- Industrial Network Intrusion Detection  
- SOC Automation for ICS/OT environments  

---

## Status

- Production-ready  
- API integrated  
- Full pipeline implemented
---
