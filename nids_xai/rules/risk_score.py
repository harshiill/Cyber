"""
Risk Score computation for NIDS-XAI.

Combines the ML model's attack probability with the rule engine's severity
score into a single 0-100 integer risk score with a named risk level.
"""

from __future__ import annotations


def compute_risk_score(ml_score: float, rule_score: float) -> dict:
    """
    Combine ML and rule scores into a 0-100 risk score.

    Parameters
    ----------
    ml_score:
        ML model attack probability (0.0 – 1.0).
    rule_score:
        Rule engine severity score (0.0 – 1.0); see engine.compute_rule_score.

    Returns
    -------
    dict with keys:
        "score"  – integer 0-100
        "level"  – one of "LOW", "MEDIUM", "HIGH", "CRITICAL"

    Weights are read from config.config (RISK_WEIGHT_ML, RISK_WEIGHT_RULE).
    Risk level boundaries are read from config.config (RISK_LEVELS).
    """
    try:
        from config.config import RISK_WEIGHT_ML, RISK_WEIGHT_RULE, RISK_LEVELS
    except ImportError:
        # Defensive fallback — should not happen in normal operation
        RISK_WEIGHT_ML = 0.7
        RISK_WEIGHT_RULE = 0.3
        RISK_LEVELS = {
            "LOW":      (0,  39),
            "MEDIUM":   (40, 69),
            "HIGH":     (70, 89),
            "CRITICAL": (90, 100),
        }

    # Clamp inputs to [0, 1]
    ml_score = max(0.0, min(1.0, float(ml_score)))
    rule_score = max(0.0, min(1.0, float(rule_score)))

    combined = max(rule_score, RISK_WEIGHT_ML * ml_score + RISK_WEIGHT_RULE * rule_score)
    score = int(round(combined * 100))
    score = max(0, min(100, score))

    level = "LOW"
    for lvl_name, (lo, hi) in RISK_LEVELS.items():
        if lo <= score <= hi:
            level = lvl_name
            break

    return {"score": score, "level": level}
