"""
Rule Engine for NIDS-XAI.

Evaluates network flow metadata against YAML-defined detection rules and
produces a normalised 0-1 risk score based on matched rule severities.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fallback rules used when PyYAML is unavailable or the YAML file is missing
# ---------------------------------------------------------------------------
_FALLBACK_RULES: Dict = {
    "rules": [
        {
            "id": "PORTSCAN_01",
            "name": "Port Scan",
            "severity": "HIGH",
            "description": "Many distinct destination ports from one source in a time window",
            "thresholds": {"distinct_ports": 50, "window_seconds": 60},
        },
        {
            "id": "BRUTEFORCE_01",
            "name": "Brute Force",
            "severity": "HIGH",
            "description": "Many connections to SSH/FTP/RDP ports from one source",
            "thresholds": {
                "target_ports": [22, 21, 3389],
                "connections": 20,
                "window_seconds": 60,
            },
        },
        {
            "id": "DOS_01",
            "name": "DoS-like High Rate",
            "severity": "CRITICAL",
            "description": "High connection or packet rate per source",
            "thresholds": {"connections_per_second": 50, "window_seconds": 10},
        },
        {
            "id": "SYN_FLOOD_01",
            "name": "Excessive SYN without ACK",
            "severity": "HIGH",
            "description": "High SYN flag count relative to ACK flag count",
            "thresholds": {"syn_ack_ratio": 5.0, "min_syn_count": 10},
        },
    ]
}

# Module-level cache: loaded once per process
_rules_cache: Optional[List[Dict]] = None
_rules_path_used: Optional[str] = None


def _load_rules(rules_path: Optional[str] = None) -> List[Dict]:
    """Load rules from YAML; fall back to hardcoded dict on failure."""
    global _rules_cache, _rules_path_used

    # Return cached copy if already loaded from the same path
    if _rules_cache is not None and _rules_path_used == rules_path:
        return _rules_cache

    if rules_path is None:
        rules_path = str(Path(__file__).parent / "rules.yaml")

    try:
        import yaml  # PyYAML

        with open(rules_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        loaded = data.get("rules", [])
        logger.debug("Rules engine: loaded %d rules from %s", len(loaded), rules_path)
    except ImportError:
        logger.warning("PyYAML not available; using hardcoded fallback rules.")
        loaded = _FALLBACK_RULES["rules"]
    except FileNotFoundError:
        logger.warning("rules.yaml not found at %s; using hardcoded fallback rules.", rules_path)
        loaded = _FALLBACK_RULES["rules"]
    except Exception as exc:
        logger.error("Failed to load rules from %s: %s; using fallback.", rules_path, exc)
        loaded = _FALLBACK_RULES["rules"]

    _rules_cache = loaded
    _rules_path_used = rules_path
    return _rules_cache


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    """Represents a single rule that matched a flow."""
    matched: bool
    rule_id: str
    severity: str
    reason: str  # plain-English explanation


# ---------------------------------------------------------------------------
# Severity → numeric weight
# ---------------------------------------------------------------------------
_SEVERITY_SCORE: Dict[str, float] = {
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}


# ---------------------------------------------------------------------------
# Individual rule evaluators
# ---------------------------------------------------------------------------

def _eval_portscan(flow: Dict[str, Any], rule: Dict) -> Optional[RuleMatch]:
    """PORTSCAN_01: many distinct destination ports in window."""
    t = rule.get("thresholds", {})
    threshold = int(t.get("distinct_ports", 50))
    distinct = int(flow.get("distinct_dst_ports", 0))
    if distinct >= threshold:
        return RuleMatch(
            matched=True,
            rule_id=rule["id"],
            severity=rule["severity"],
            reason=(
                f"Source contacted {distinct} distinct destination ports "
                f"(threshold: {threshold}), suggesting a possible port scan."
            ),
        )
    return None


def _eval_bruteforce(flow: Dict[str, Any], rule: Dict) -> Optional[RuleMatch]:
    """BRUTEFORCE_01: many connections to SSH/FTP/RDP ports."""
    t = rule.get("thresholds", {})
    threshold = int(t.get("connections", 20))
    connections = int(flow.get("connections_to_brute_ports", 0))
    if connections >= threshold:
        target_ports = t.get("target_ports", [22, 21, 3389])
        return RuleMatch(
            matched=True,
            rule_id=rule["id"],
            severity=rule["severity"],
            reason=(
                f"Source made {connections} connections to brute-force target ports "
                f"{target_ports} (threshold: {threshold}), suggesting possible brute-force activity."
            ),
        )
    return None


def _eval_dos(flow: Dict[str, Any], rule: Dict) -> Optional[RuleMatch]:
    """DOS_01: high connection/packet rate per source."""
    t = rule.get("thresholds", {})
    threshold = float(t.get("connections_per_second", 50))
    cps = float(flow.get("connections_per_second", 0.0))
    if cps >= threshold:
        return RuleMatch(
            matched=True,
            rule_id=rule["id"],
            severity=rule["severity"],
            reason=(
                f"Source generated {cps:.1f} connections/s "
                f"(threshold: {threshold}), suggesting a possible DoS-like flood."
            ),
        )
    return None


def _eval_syn_flood(flow: Dict[str, Any], rule: Dict) -> Optional[RuleMatch]:
    """SYN_FLOOD_01: high SYN/ACK ratio with enough SYN count."""
    t = rule.get("thresholds", {})
    ratio_threshold = float(t.get("syn_ack_ratio", 5.0))
    min_syn = int(t.get("min_syn_count", 10))
    syn = int(flow.get("syn_flag_count", 0))
    ack = int(flow.get("ack_flag_count", 0))
    if syn >= min_syn:
        ratio = syn / max(ack, 1)
        if ratio >= ratio_threshold:
            return RuleMatch(
                matched=True,
                rule_id=rule["id"],
                severity=rule["severity"],
                reason=(
                    f"SYN/ACK ratio is {ratio:.1f} (SYN={syn}, ACK={ack}; "
                    f"threshold ratio: {ratio_threshold}), suggesting a possible SYN flood."
                ),
            )
    return None


# Map rule IDs to their evaluator functions
_EVALUATORS = {
    "PORTSCAN_01": _eval_portscan,
    "BRUTEFORCE_01": _eval_bruteforce,
    "DOS_01": _eval_dos,
    "SYN_FLOOD_01": _eval_syn_flood,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_flow(flow: Dict[str, Any], rules_path: Optional[str] = None) -> List[RuleMatch]:
    """
    Evaluate a flow dict against all loaded rules.

    Parameters
    ----------
    flow:
        Dict with keys such as: src_ip, dst_port, syn_flag_count,
        ack_flag_count, connections_per_second, distinct_dst_ports,
        connections_to_brute_ports, flow_packets_per_s.
    rules_path:
        Optional override for the YAML file location.

    Returns
    -------
    List of RuleMatch objects where matched=True.
    """
    rules = _load_rules(rules_path)
    matches: List[RuleMatch] = []
    for rule in rules:
        rule_id = rule.get("id", "")
        evaluator = _EVALUATORS.get(rule_id)
        if evaluator is None:
            logger.debug("No evaluator registered for rule id=%s; skipping.", rule_id)
            continue
        try:
            result = evaluator(flow, rule)
            if result is not None:
                matches.append(result)
        except Exception as exc:
            logger.warning("Error evaluating rule %s: %s", rule_id, exc)
    return matches


def compute_rule_score(matches: List[RuleMatch]) -> float:
    """
    Return a 0.0-1.0 score based on the severity of matched rules.

    Severity weights:
        CRITICAL → 1.0
        HIGH     → 0.75
        MEDIUM   → 0.50
        LOW      → 0.25

    Returns the maximum severity score across all matches, or 0.0 if no matches.
    """
    if not matches:
        return 0.0
    return max(_SEVERITY_SCORE.get(m.severity.upper(), 0.0) for m in matches)
