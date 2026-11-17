"""
Feedback endpoints for NIDS-XAI analyst loop.

POST /api/feedback  — submit a true_positive / false_positive label for an alert
GET  /api/feedback  — retrieve the last N feedback entries
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from config.config import FEEDBACK_FILE

router = APIRouter(tags=["feedback"])

_feedback_lock = threading.Lock()


# ------------------------------------------------------------------ #
#  Schema                                                              #
# ------------------------------------------------------------------ #

class FeedbackBody(BaseModel):
    alert_id: str
    label: Literal["true_positive", "false_positive"]


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _ensure_feedback_file() -> None:
    """Create the feedback file (and parent dirs) if they don't exist."""
    path = FEEDBACK_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        open(path, "w", encoding="utf-8").close()


def _append_feedback(record: dict) -> None:
    """Thread-safe append of one JSON record as a new line."""
    _ensure_feedback_file()
    with _feedback_lock:
        with open(FEEDBACK_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")


def _read_feedback(limit: int = 100) -> list:
    """Return the last *limit* feedback entries (most-recent last)."""
    _ensure_feedback_file()
    with _feedback_lock:
        try:
            with open(FEEDBACK_FILE, "r", encoding="utf-8") as fh:
                lines = [l.strip() for l in fh if l.strip()]
        except FileNotFoundError:
            return []

    records = []
    for line in lines[-limit:]:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # skip corrupted lines
    return records


# ------------------------------------------------------------------ #
#  Endpoints                                                           #
# ------------------------------------------------------------------ #

@router.post("/api/feedback")
def submit_feedback(body: FeedbackBody):
    """
    Submit analyst feedback for an alert.

    - **alert_id**: The ID of the alert being labelled.
    - **label**: ``"true_positive"`` (confirmed attack) or ``"false_positive"`` (benign, mis-classified).
    """
    record = {
        "alert_id": body.alert_id,
        "label": body.label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    from api.services.alert_store import alert_store
    alert = alert_store.get_by_id(body.alert_id)
    if alert and alert.get("features") is not None:
        record.update(features=alert["features"], dataset=alert.get("model_dataset"),
                      feature_names=alert.get("model_features", []),
                      schema_id=alert.get("schema_id"), traffic_origin=alert.get("traffic_origin"))
    try:
        _append_feedback(record)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store feedback: {exc}")

    return {"stored": True, "alert_id": body.alert_id, "label": body.label}


@router.get("/api/feedback")
def get_feedback(limit: int = Query(default=100, ge=1, le=1000)):
    """Return the last *limit* feedback entries (oldest → newest)."""
    return {"feedback": _read_feedback(limit), "count": min(limit, len(_read_feedback(limit)))}
