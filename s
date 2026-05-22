┌──────────────────────────────────────────────────────────────────────────────┐
│ AI / ML Detection Pipeline                     ICS-OT Smart Grid NDR         │
└──────────────────────────────────────────────────────────────────────────────┘


[ LAYER 1 — INPUT ]
───────────────────────────────────────────────────────────────────────────────
┌──────────────────────────────────────────────────────────────────────────────┐
│ Raw Network Traffic                                                          │
│ PCAP  ·  NetFlow  ·  IPFIX                                                   │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼


[ LAYER 2 — PREP ]
───────────────────────────────────────────────────────────────────────────────
┌──────────────────────────────────────────────────────────────────────────────┐
│ Feature Engineering                                                          │
│ utils/feature_engineering.py · Scalers · Label Encoder · Feature Lists       │
│                                                                              │
│ [xgb_features] [autoencoder_scaler] [label_encoder]                          │
└──────────────────────────────────────────────────────────────────────────────┘
                         │                             │
                         ▼                             ▼


[ LAYER 3 — MODELS ]
───────────────────────────────────────────────────────────────────────────────

┌──────────────────────────────────────┐
│ XGBoost                              │
│ [Supervised]                         │
│ models/xgboost_model.pkl             │
│                                      │
│ • Attack label (e.g. TCPFLOOD)       │
│ • Confidence score (0–100%)          │
│ • Probability vector per class       │
└──────────────────────────────────────┘


┌──────────────────────────────────────┐
│ Autoencoder                          │
│ [Unsupervised]                       │
│ models/autoencoder_model.keras       │
│                                      │
│ • Reconstruction error (MSE)         │
│ • Anomaly flag (true / false)        │
│ • Z-score vs trained threshold       │
└──────────────────────────────────────┘
                    │
                    ▼


[ LAYER 4 — FUSION ]
───────────────────────────────────────────────────────────────────────────────
┌──────────────────────────────────────────────────────────────────────────────┐
│ Fusion Engine                                                                │
│ 7-case decision table · engine/ndr_engine.py                                 │
│ config/autoencoder_thresholds.json                                           │
│                                                                              │
│ [XGB ≥75% → trusted]                                                         │
│ [50–75% + AE → confirmed]                                                    │
│ [Benign + AE → zero-day]                                                     │
│ [Both uncertain → benign]                                                    │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼


[ LAYER 5 — SCORING ]
───────────────────────────────────────────────────────────────────────────────
┌──────────────────────────────────────────────────────────────────────────────┐
│ Risk Scoring Engine                                                          │
│                                                                              │
│ score = (conf × severity × 10)                                               │ 
│       + anomaly_bonus(+20)                                                   │
│       + recurrence_penalty(+20)                                              │
│                                                                              │
│ [CRITICAL 90+] [HIGH 65] [MED 35] [LOW 0]                                    │
└──────────────────────────────────────────────────────────────────────────────┘
                         │                             │
                         ▼                             ▼


[ LAYER 6 — RESPONSE ]
───────────────────────────────────────────────────────────────────────────────

┌──────────────────────────────────────┐
│ Response Simulator                  │
│ [Auto Response]                     │
│                                      │
│ • BLOCK_IP → blocked set            │
│ • ALERT_ADMIN → 60s cooldown/IP     │
│ • LOGGED → always written           │
│ • IP recurrence counter updated     │
└──────────────────────────────────────┘


┌──────────────────────────────────────┐
│ Structured Logging                  │
│ [SOC Logger]                        │
│                                      │
│ • ndr_YYYYMMDD.jsonl (SIEM)         │
│ • ndr_YYYYMMDD.log (human)          │
│ • Elasticsearch / Splunk ready      │
│ • Non-benign events only            │
└──────────────────────────────────────┘
                         │
                         ▼


[ LAYER 7 — OUTPUT ]
───────────────────────────────────────────────────────────────────────────────
┌──────────────────────────────────────────────────────────────────────────────┐
│ Unified API Response — FastAPI                                           │
│                                                                            │
│ [attack] [severity] [risk_score] [confidence]                             │
│ [is_blocked] [actions_taken] [detected_by]                                │
└──────────────────────────────────────────────────────────────────────────────┘


