"""
api.py  ──  FastAPI service for ICS/OT NDR Engine  v2.1
═══════════════════════════════════════════════════════════════
AI-based Network Detection & Response for Smart Grid / ICS

Endpoints:
  POST /predict          → analyse a single network flow
  POST /predict/batch    → analyse a list of flows  (max 1000)
  GET  /test             → run a built-in sample and return result
  GET  /health           → liveness + model readiness probe
  GET  /session/stats    → current session statistics
  POST /session/reset    → reset session state

Run locally:
  uvicorn api.api:app --host 0.0.0.0 --port 8000 --reload

Docker:
  CMD ["uvicorn", "api.api:app", "--host", "0.0.0.0", "--port", "8000"]

Swagger UI:
  http://localhost:8000/docs
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from engine.ndr_engine import NDREngine


# ═══════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════

# Ensure logs directory always exists before engine starts
Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("NDR-API")


# ═══════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════

app = FastAPI(
    title="ICS/OT NDR Engine API",
    description=(
        "AI-based Network Detection & Response for Smart Grid / ICS environments.\n\n"
        "Hybrid detection: XGBoost (known attacks) + Autoencoder (zero-day anomalies).\n\n"
        "Use **GET /test** to verify the system is working end-to-end before integration."
    ),
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — allow all origins during development ──────────────
# Restrict allow_origins in production to your frontend domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # e.g. ["https://your-dashboard.com"] in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global state ─────────────────────────────────────────────
_engine: Optional[NDREngine] = None
_startup_time: float = 0.0
_engine_ready: bool = False


# ═══════════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event() -> None:
    global _engine, _startup_time, _engine_ready
    _startup_time = time.time()
    logger.info("Loading NDR Engine …")
    try:
        _engine = NDREngine(enable_logging=True, enable_response=True)
        _engine_ready = True
        logger.info("NDR Engine loaded successfully.")
    except Exception as exc:
        _engine_ready = False
        logger.error("Engine failed to load: %s", exc)
        # Do NOT re-raise — let /health surface the failure gracefully


@app.on_event("shutdown")
async def shutdown_event() -> None:
    logger.info("NDR API shutting down.")


# ── Helper ───────────────────────────────────────────────────

def get_engine() -> NDREngine:
    """Return the global engine or raise 503 if not ready."""
    if _engine is None or not _engine_ready:
        raise HTTPException(
            status_code=503,
            detail="NDR Engine is not ready. Check /health for details.",
        )
    return _engine


# ═══════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════

class NetworkFlow(BaseModel):
    """
    A single network flow record.  Only the fields listed below
    are required; any extra fields in the payload are forwarded
    to the feature-engineering pipeline unchanged.
    """
    duration:    float          = Field(0.0,   description="Flow duration (seconds)")
    sPackets:    int            = Field(0,     description="Sender packet count")
    rPackets:    int            = Field(0,     description="Receiver packet count")
    sBytesSum:   float          = Field(0.0,   description="Total bytes sent")
    rBytesSum:   float          = Field(0.0,   description="Total bytes received")
    sLoad:       float          = Field(0.0,   description="Sender throughput (bps)")
    rLoad:       float          = Field(0.0,   description="Receiver throughput (bps)")
    sSynRate:    float          = Field(0.0,   description="SYN flag rate (sender)")
    sAckRate:    float          = Field(0.0,   description="ACK flag rate (sender)")
    sFinRate:    float          = Field(0.0,   description="FIN flag rate (sender)")
    sRstRate:    float          = Field(0.0,   description="RST flag rate (sender)")
    sPayloadAvg: float          = Field(0.0,   description="Avg payload size — sender (bytes)")
    rPayloadAvg: float          = Field(0.0,   description="Avg payload size — receiver (bytes)")
    protocol:    str            = Field("tcp", description="Protocol: tcp / udp / icmp / arp / igmp / other")
    sAddress:    Optional[str]  = Field(None,  description="Source IP address (used for tracking & logging)")

    class Config:
        extra = "allow"   # extra dataset columns pass through to feature engineering


class DetectionResult(BaseModel):
    """Standardised detection response — every field always present."""
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
    actions_taken: List[str]


class BatchRequest(BaseModel):
    flows: List[NetworkFlow] = Field(..., min_items=1, max_items=1000)


class BatchResponse(BaseModel):
    total:   int
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


# ── Default / safe result builder ────────────────────────────

_SAFE_DEFAULTS: Dict[str, Any] = {
    "timestamp":    "",
    "src":          "unknown",
    "attack":       "ERROR",
    "group":        "ERROR",
    "severity":     "LOW",
    "risk_score":   0.0,
    "confidence":   0.0,
    "recon_error":  0.0,
    "is_anomaly":   False,
    "detected_by":  "",
    "action":       "Check engine logs",
    "is_blocked":   False,
    "actions_taken": [],
}


def _safe_result(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge raw engine output with safe defaults so the response
    always contains every required field — even if the engine
    returned a partial or error dict.
    """
    out = dict(_SAFE_DEFAULTS)
    out.update({k: v for k, v in raw.items() if v is not None})

    # Normalise key: engine uses 'label', API uses 'attack'
    if "label" in raw and "attack" not in raw:
        out["attack"] = raw["label"]

    # Ensure timestamp is always set
    if not out.get("timestamp"):
        out["timestamp"] = datetime.utcnow().isoformat()

    return out


# ═══════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════

# ── Health ───────────────────────────────────────────────────

@app.get(
    "/health",
    summary="Liveness & readiness probe",
    tags=["System"],
)
async def health() -> Dict[str, Any]:
    """
    Returns the current status of the API and the NDR engine.

    - **status**: `"running"` when the API process is alive
    - **engine_ready**: `true` when models loaded successfully
    - **models_loaded**: mirrors `engine_ready`
    - **uptime_seconds**: seconds since the API process started
    """
    uptime = round(time.time() - _startup_time, 1)

    if not _engine_ready or _engine is None:
        return JSONResponse(
            status_code=503,
            content={
                "status":        "running",
                "engine_ready":  False,
                "models_loaded": False,
                "uptime_seconds": uptime,
                "detail":        "Engine failed to initialise — check server logs.",
            },
        )

    return {
        "status":         "running",
        "engine_ready":   True,
        "models_loaded":  True,
        "uptime_seconds": uptime,
        "models": {
            "xgboost_features":     len(_engine.xgb_feats),
            "autoencoder_features": len(_engine.ae_feats),
            "ae_threshold":         round(_engine.ae_threshold, 6),
        },
    }


# ── Test ─────────────────────────────────────────────────────

# A realistic sample that typically triggers a TCPFLOOD detection.
_SAMPLE_FLOW = {
    "duration":    0.5,
    "sPackets":    2000,
    "rPackets":    5,
    "sBytesSum":   300000.0,
    "rBytesSum":   300.0,
    "sLoad":       4800000.0,
    "rLoad":       4800.0,
    "sSynRate":    0.0,
    "sAckRate":    1.0,
    "sFinRate":    0.0,
    "sRstRate":    0.0,
    "sPayloadAvg": 150.0,
    "rPayloadAvg": 60.0,
    "protocol":    "tcp",
    "sAddress":    "192.168.1.100",
}


@app.get(
    "/test",
    response_model=DetectionResult,
    summary="End-to-end smoke test",
    tags=["System"],
)
async def test_endpoint() -> Dict[str, Any]:
    """
    Runs the built-in sample flow through the full detection pipeline
    and returns the result.

    **Use this to:**
    - Verify the engine is working before integration
    - Give the frontend team a live example response
    - Let the attack simulation team confirm the API is reachable

    The sample simulates a TCP-flood pattern — you should see
    a HIGH or CRITICAL severity result.
    """
    engine = get_engine()
    try:
        raw = engine.predict_json(_SAMPLE_FLOW)
        return _safe_result(raw)
    except Exception as exc:
        logger.error("Test endpoint error: %s", exc)
        raise HTTPException(status_code=500, detail="Test prediction failed. Check server logs.")


# ── Predict (single) ─────────────────────────────────────────

@app.post(
    "/predict",
    response_model=DetectionResult,
    summary="Analyse a single network flow",
    tags=["Detection"],
)
async def predict(flow: NetworkFlow) -> Dict[str, Any]:
    """
    Submit a single network flow for detection.

    Returns a standardised result with:
    - **attack** label and **group** category
    - **severity** tier (CRITICAL / HIGH / MEDIUM / LOW)
    - **confidence** score (0–100 %)
    - **recon_error** from the Autoencoder
    - **action** recommended by the engine
    - **is_blocked** — whether the source IP was blocked this request
    - **actions_taken** — list of automated response actions executed
    """
    engine = get_engine()
    try:
        raw = engine.predict_json(flow.dict())
        return _safe_result(raw)
    except Exception as exc:
        logger.error("Prediction error: %s", exc)
        raise HTTPException(status_code=500, detail="Prediction failed. Check server logs.")


# ── Predict (batch) ──────────────────────────────────────────

@app.post(
    "/predict/batch",
    response_model=BatchResponse,
    summary="Analyse a batch of network flows",
    tags=["Detection"],
)
async def predict_batch(request: BatchRequest) -> Dict[str, Any]:
    """
    Submit 1–1000 flows in a single request.

    Returns:
    - **total**: number of flows processed
    - **results**: list of individual detection dicts
    - **summary**: aggregated attack_counts and severity_counts
    """
    engine  = get_engine()
    results: List[Dict[str, Any]] = []
    counts:  Dict[str, int]       = {}
    sevs:    Dict[str, int]       = {}

    for flow in request.flows:
        try:
            raw = engine.predict_json(flow.dict())
            r   = _safe_result(raw)
        except Exception as exc:
            logger.warning("Batch item error: %s", exc)
            r = dict(_SAFE_DEFAULTS)
            r["timestamp"] = datetime.utcnow().isoformat()
            r["attack"]    = "ERROR"

        results.append(r)
        lbl = r.get("attack", "ERROR")
        sev = r.get("severity", "LOW")
        counts[lbl] = counts.get(lbl, 0) + 1
        sevs[sev]   = sevs.get(sev, 0) + 1

    return {
        "total":   len(results),
        "results": results,
        "summary": {
            "attack_counts":   counts,
            "severity_counts": sevs,
        },
    }


# ── Session ──────────────────────────────────────────────────

@app.get(
    "/session/stats",
    summary="Current session statistics",
    tags=["Session"],
)
async def session_stats() -> Dict[str, Any]:
    """
    Returns aggregated statistics for the running session:
    - total flows analysed
    - per-attack-type counts
    - per-severity counts
    - currently blocked IPs
    """
    engine = get_engine()
    return engine.get_session_stats()


@app.post(
    "/session/reset",
    summary="Reset session state",
    tags=["Session"],
)
async def session_reset() -> Dict[str, Any]:
    """
    Clears session counters, blocked-IP set, and alert history.
    Call this between test runs to start fresh.
    """
    engine = get_engine()
    engine.reset_session()
    logger.info("Session reset.")
    return {"status": "ok", "message": "Session reset successfully."}


# ═══════════════════════════════════════════════════════════════
# GLOBAL ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error":   exc.detail,
            "path":    str(request.url),
            "status":  exc.status_code,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s — %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={
            "error":  "An internal server error occurred.",
            "path":   str(request.url),
            "status": 500,
        },
    )
