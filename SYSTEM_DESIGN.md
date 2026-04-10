# System Design & Architecture

## Overview

This document describes the internal architecture and production design of the AI-based Network Detection and Response (NDR) system implemented in this project.

The system is designed to operate in industrial environments (ICS/OT), providing real-time detection, classification, and response to cyber threats in smart grid networks.

---

## NDR Pipeline Architecture

```
RAW TRAFFIC (PCAP / NetFlow / IPFIX)
        ↓
Feature Extraction (Zeek / CICFlowMeter / Argus)
        ↓
 ┌───────────────────────┬────────────────────────┐
 ↓                       ↓
Supervised Model        Unsupervised Model
(XGBoost)               (Autoencoder)
Known Attacks           Zero-Day Detection
        ↓                       ↓
        └─────────── Fusion Engine ───────────┘
                        ↓
                Risk Scoring Engine
                        ↓
        ┌───────────────┬────────────────┐
        ↓                                ↓
Auto Response                    Analyst Dashboard
(Block / Rate-limit)            (Monitoring / Alerts)
```

---

## Risk Scoring System

The system calculates a dynamic risk score based on:

* Model confidence
* Attack severity
* Recurrence frequency
* Anomaly deviation (Autoencoder contribution)

### Formula

```python
score = (confidence * base_severity * 10)
score += recurrence_penalty
score += anomaly_bonus
```

### Risk Levels

* HIGH → Automatic blocking and alerting
* MEDIUM → Alert analyst for investigation
* LOW → Log and monitor

---

## Attack Grouping

Attacks are categorized into logical groups:

* FLOOD_ATTACK → ACKFLOOD, TCPFLOOD, ICMPFLOOD, Smurf
* SCAN_ATTACK → PORTSCAN, NMAP
* ICMP_ATTACK → PINGOFDEATH
* EXPLOIT_ATTACK → WinNuke
* UNKNOWN_THREAT → Zero-day or anomalous behavior

---

## Fusion Logic

The system combines outputs from both models:

* High-confidence XGBoost → trusted directly
* Medium-confidence XGBoost + anomaly → confirmed attack
* Low-confidence XGBoost + anomaly → UNKNOWN (Autoencoder-driven detection)
* Both models uncertain → BENIGN

This hybrid logic improves detection accuracy and reduces false positives.

---

## Model Design

The system follows a hybrid AI architecture:

* XGBoost
  A supervised machine learning model trained on labeled attack data
  Responsible for detecting known attack patterns

* Autoencoder
  A deep learning model trained on normal traffic behavior
  Used for anomaly detection and identifying zero-day attacks

* Fusion Engine
  Combines both models into a single decision pipeline

---

## Logging System

The system provides dual logging outputs:

* JSON logs
  Structured logs suitable for SIEM platforms (Elasticsearch, Splunk)

* Text logs
  Human-readable logs for monitoring and debugging

---

## Response System

Automated response actions include:

* Blocking malicious source IP addresses
* Triggering alerts to security operators
* Logging events for forensic analysis

A cooldown mechanism is implemented to prevent alert flooding.

---

## API Design

The system exposes a REST API for integration:

* POST /predict
  Perform detection on a single network flow

* POST /predict/batch
  Perform detection on multiple flows

* GET /health
  Check system status and model availability

* GET /session/stats
  Retrieve detection statistics and metrics

* POST /session/reset
  Reset session state between test runs

---

## System Characteristics

* Real-time capable (low-latency inference)
* Hybrid AI detection (supervised + unsupervised)
* Designed for SOC and SIEM integration
* Modular and extensible architecture

---

## Limitations

The current system does not yet cover:

* MITM / ARP Spoofing
* Replay Attacks
* Data Manipulation Attacks

These require deeper packet inspection and protocol-aware analysis.

---

## Future Improvements

* Add detection for MITM and ARP Spoofing
* Implement replay attack detection
* Integrate deep packet inspection (DPI)
* Add ICS protocol parsing (Modbus, DNP3, IEC 104)
* Implement model versioning (MLflow)
* Add drift detection for evolving traffic patterns
* Integrate explainability (SHAP) for model transparency
* Build a real-time monitoring dashboard

---
