"""
api.py  ──  FastAPI service for ICS/OT NDR Engine
═══════════════════════════════════════════════════════════════

Endpoints:
  POST /predict          → analyse a single network flow
  POST /predict/batch    → analyse a list of flows
  GET  /health           → liveness + model status
  GET  /session/stats    → current session statistics
  POST /session/reset    → reset session state

Run:
  uvicorn api:app --host 0.0.0.0 --port 8000 --reload

Docker:
  CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ndr_engine import NDREngine

# ═══════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════

app = FastAPI(
    title="ICS/OT NDR Engine API",
    description="AI-based Network Detection & Response for Smart Grid / ICS environments",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global engine instance (loaded once at startup) ──
_engine: Optional[NDREngine] = None
_startup_time: float = 0.0


@app.on_event("startup")
async def startup_event():
    global _engine, _startup_time
    _startup_time = time.time()
    _engine = NDREngine(enable_logging=True, enable_response=True)


def get_engine() -> NDREngine:
    if _engine is None:
        raise HTTPException(status_code=503, detail="NDR Engine not initialised")
    return _engine


# ═══════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════

class NetworkFlow(BaseModel):
    """
    Minimum required fields for a network flow sample.
    All other raw dataset columns can be included and will be
    passed through to feature engineering.
    """
    # Core traffic features
    duration:    float = Field(0.0,   description="Flow duration in seconds")
    sPackets:    int   = Field(0,     description="Sender packet count")
    rPackets:    int   = Field(0,     description="Receiver packet count")
    sBytesSum:   float = Field(0.0,   description="Total bytes sent")
    rBytesSum:   float = Field(0.0,   description="Total bytes received")
    sLoad:       float = Field(0.0,   description="Sender throughput (bps)")
    rLoad:       float = Field(0.0,   description="Receiver throughput (bps)")
    sSynRate:    float = Field(0.0,   description="SYN rate (sender)")
    sAckRate:    float = Field(0.0,   description="ACK rate (sender)")
    sFinRate:    float = Field(0.0,   description="FIN rate (sender)")
    sRstRate:    float = Field(0.0,   description="RST rate (sender)")
    sPayloadAvg: float = Field(0.0,   description="Average payload size (sender)")
    rPayloadAvg: float = Field(0.0,   description="Average payload size (receiver)")
    protocol:    str   = Field("tcp", description="Protocol: tcp/udp/icmp/arp/igmp/other")
    # Optional — used for source tracking and logging
    sAddress:    Optional[str] = Field(None, description="Source IP address")

    class Config:
        extra = "allow"   # allow extra fields (full dataset rows)


class PredictResponse(BaseModel):
    timestamp:    str
    src:          str
    attack:       str
    group:        str
    severity:     str
    risk_score:   float
    confidence:   float
    recon_error:  float
    is_anomaly:   bool
    detected_by:  str
    action:       str
    is_blocked:   bool
    actions_taken: list[str]


class BatchRequest(BaseModel):
    flows: list[NetworkFlow] = Field(..., min_items=1, max_items=1000)


class BatchResponse(BaseModel):
    total:    int
    results:  list[dict]
    summary:  dict


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """Liveness + readiness probe."""
    engine = get_engine()
    return {
        "status":        "ok",
        "uptime_seconds": round(time.time() - _startup_time, 1),
        "models": {
            "xgboost_features":    len(engine.xgb_feats),
            "autoencoder_features": len(engine.ae_feats),
            "ae_threshold":        engine.ae_threshold,
        },
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(flow: NetworkFlow):
    """
    Analyse a single network flow.

    Returns a standardised detection result including:
    - attack label & group
    - severity (CRITICAL / HIGH / MEDIUM / LOW)
    - confidence score
    - anomaly reconstruction error
    - recommended action
    - whether the source IP was blocked
    """
    engine = get_engine()
    try:
        row = flow.dict()
        result = engine.predict_json(row)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

    return {
        "timestamp":    result["timestamp"],
        "src":          result.get("src", "unknown"),
        "attack":       result["label"],
        "group":        result.get("group", "UNKNOWN"),
        "severity":     result.get("severity", "LOW"),
        "risk_score":   result.get("risk_score", 0.0),
        "confidence":   result.get("confidence", 0.0),
        "recon_error":  result.get("recon_error", 0.0),
        "is_anomaly":   result.get("is_anomaly", False),
        "detected_by":  result.get("detected_by", ""),
        "action":       result.get("action", ""),
        "is_blocked":   result.get("is_blocked", False),
        "actions_taken": result.get("actions_taken", []),
    }


@app.post("/predict/batch", response_model=BatchResponse)
async def predict_batch(request: BatchRequest):
    """
    Analyse a list of network flows (up to 1000 per request).
    Returns individual results plus an aggregated summary.
    """
    engine  = get_engine()
    results = []
    counts: dict[str, int] = {}
    sevs:   dict[str, int] = {}

    for flow in request.flows:
        try:
            r = engine.predict_json(flow.dict())
        except Exception as e:
            r = {"label": "ERROR", "severity": "LOW", "error": str(e)}
        results.append(r)
        lbl = r.get("label", "ERROR")
        sev = r.get("severity", "LOW")
        counts[lbl] = counts.get(lbl, 0) + 1
        sevs[sev]   = sevs.get(sev, 0) + 1

    return {
        "total":   len(results),
        "results": results,
        "summary": {"attack_counts": counts, "severity_counts": sevs},
    }


@app.get("/session/stats")
async def session_stats():
    """Return aggregated statistics for the current detection session."""
    engine = get_engine()
    return engine.get_session_stats()


@app.post("/session/reset")
async def session_reset():
    """Reset per-session counters, blocked-IP list, and alert history."""
    engine = get_engine()
    engine.reset_session()
    return {"status": "ok", "message": "Session reset successfully"}


# ═══════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "path": str(request.url)},
    )
