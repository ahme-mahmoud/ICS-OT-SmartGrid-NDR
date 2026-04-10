# ICS-OT Smart Grid Network Detection & Response (AI-Based)

## Overview

This project implements a production-ready AI-based Network Detection and Response (NDR) system designed for Industrial Control Systems (ICS/OT) in Smart Grid environments.

The system analyzes industrial network traffic, detects anomalies, classifies cyber attacks, and simulates automated response actions to protect critical infrastructure such as substations and power systems.

---

## Objectives

* Detect abnormal behavior in industrial network traffic
* Classify cyber attacks (DoS, scanning, flooding, exploitation, etc.)
* Support real-time monitoring and alerting
* Generalize detection across multiple industrial vendors (ABB, Siemens, Schneider)

---

## Key Features

* Real-time traffic analysis (simulated streaming)
* AI-based detection:

  * XGBoost for known attack classification
  * Autoencoder for anomaly and zero-day detection
* Hybrid fusion logic combining supervised and unsupervised models
* Severity classification (LOW, MEDIUM, HIGH, CRITICAL)
* Attack grouping (Flood, Scan, Exploit, etc.)
* Structured SOC-style logging
* Automated response simulation (block, alert, log)
* REST API using FastAPI
* Ready for frontend or dashboard integration

---

## Project Structure

```
NDR_Project/
│
├── api/  
├── engine/  
├── models/  
├── preprocessing/  
├── config/  
├── utils/  
│
├── requirements.txt  
└── README.md  
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Running the System

```bash
uvicorn api.api:app --host 0.0.0.0 --port 8000
```

Open in browser:

```
http://127.0.0.1:8000/docs
```

---

## API Usage

POST `/predict`

---

## Example Input

```json
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

---

## Example Output

```json
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

---

## Detection Logic

* XGBoost: Known attack detection
* Autoencoder: Anomaly and zero-day detection

---

## Supported Attack Types

### Known Attacks (XGBoost)

* TCP Flood
* ICMP Flood
* Ping of Death
* Smurf
* Teardrop
* WinNuke
* Portscan
* Nmap

### Unknown / Zero-Day Attacks (Autoencoder)

* Any anomalous or unseen network behavior
* Deviations from normal industrial traffic patterns

---

## Model Design

The system follows a hybrid AI architecture:

* XGBoost
  A supervised machine learning model trained on labeled attack data

* Autoencoder
  A deep learning model trained on normal traffic behavior

* Fusion Logic
  Combines outputs from both models for final decision

---

## System Design

For a detailed explanation of the system architecture, pipeline, and production design, see:

[SYSTEM_DESIGN.md](SYSTEM_DESIGN.md)

---

## Limitations

* MITM / ARP Spoofing
* Replay Attacks
* Data Manipulation Attacks

These require deeper packet inspection and protocol-level analysis.

---

## Future Improvements

* Add detection for MITM and ARP Spoofing
* Implement replay attack detection
* Integrate deep packet inspection (DPI)
* Deploy in real-time industrial environments
* Build a frontend dashboard

---

## Datasets

```
Datasets/
├── 01_core/
├── 02_diversity/
├── 03_cross_vendor/
```

### Layer 1: Core

* Real industrial traffic simulation
* Used for baseline model training

### Layer 2: Diversity

* Multiple attack types
* Improves generalization

### Layer 3: Cross-Vendor

* Siemens / Schneider
* Tests robustness across environments

---

## Notes

* Large datasets are included
* System is designed for research and simulation
* Can be extended to real-world deployment

---

## Use Cases

* Smart Grid Security Monitoring
* Industrial Network Intrusion Detection
* SOC Automation for ICS/OT

---

## Status

* Production-ready
* API integrated
* Full pipeline implemented

---
