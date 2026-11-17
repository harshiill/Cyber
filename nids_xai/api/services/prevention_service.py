"""
Prevention service for NIDS-XAI.

Modes:
  monitor  — log only, no blocking
  dry_run  — log what *would* happen, no actual blocking
  enforce  — call iptables to drop traffic from the offending IP

Only calls iptables inside _block_with_iptables() / _unblock_with_iptables(),
which are ONLY reached when ENFORCEMENT_MODE == "enforce".

Auto-expires blocks after BLOCK_TTL_SECONDS.
Keeps an IP whitelist (never blocks whitelisted IPs).
Logs every action with reason.
"""

import logging
import threading
import time
import subprocess
from typing import Dict, List, Optional

from config.config import ENFORCEMENT_MODE, BLOCK_TTL_SECONDS, IP_WHITELIST, IPTABLES_CHAIN

logger = logging.getLogger(__name__)

_VALID_MODES = {"monitor", "dry_run", "enforce"}


class PreventionService:
    def __init__(self):
        self._lock = threading.Lock()
        # ip -> {blocked_at: float, ttl: int, reason: str}
        self._blocked: Dict[str, dict] = {}
        self._mode = ENFORCEMENT_MODE if ENFORCEMENT_MODE in _VALID_MODES else "dry_run"
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="prevention-cleanup"
        )
        self._cleanup_thread.start()
        logger.info("PreventionService started in mode=%s", self._mode)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> None:
        """Change enforcement mode at runtime."""
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of {_VALID_MODES}.")
        with self._lock:
            old = self._mode
            self._mode = mode
        logger.warning("PreventionService mode changed: %s -> %s", old, mode)

    def block_ip(self, ip: str, reason: str, ttl: Optional[int] = None) -> dict:
        """
        Block an IP address.

        Respects the current mode and the IP whitelist.
        Returns a dict describing the action taken.
        """
        effective_ttl = ttl if ttl is not None else BLOCK_TTL_SECONDS

        if ip in IP_WHITELIST:
            msg = f"[{self._mode}] SKIP block {ip} — whitelisted. reason={reason}"
            logger.info(msg)
            return {"action": "skipped", "ip": ip, "reason": "whitelisted", "mode": self._mode}

        with self._lock:
            entry = self._blocked.get(ip)
            if entry:
                if entry["mode"] == "dry_run" and self._mode == "enforce":
                    try:
                        self._block_with_iptables(ip)
                    except Exception as exc:
                        return {"action": "failed", "ip": ip, "reason": str(exc), "mode": self._mode}
                    entry["mode"] = "enforce"
                    entry.update(blocked_at=time.time(), ttl=effective_ttl, reason=reason)
                    return {"action": "blocked_iptables", "ip": ip, "ttl": effective_ttl, "mode": "enforce"}
                entry.update(blocked_at=time.time(), ttl=effective_ttl, reason=reason)
                return {"action": "refreshed", "ip": ip, "ttl": effective_ttl, "mode": entry["mode"]}

            mode = self._mode
            if mode == "enforce":
                try:
                    self._block_with_iptables(ip)
                except Exception as exc:
                    logger.error("iptables block failed for %s: %s", ip, exc)
                    return {"action": "failed", "ip": ip, "reason": str(exc), "mode": mode}
                action = "blocked_iptables"
            elif mode == "dry_run":
                action = "dry_run_blocked"
            else:
                return {"action": "logged", "ip": ip, "ttl": effective_ttl, "reason": reason, "mode": mode}

            self._blocked[ip] = {
                "ip": ip, "blocked_at": time.time(), "ttl": effective_ttl,
                "reason": reason, "mode": mode,
            }
        return {"action": action, "ip": ip, "ttl": effective_ttl, "reason": reason, "mode": mode}

    def unblock_ip(self, ip: str) -> dict:
        """Remove a recorded block using the mode in which it was created."""
        with self._lock:
            entry = self._blocked.get(ip)
            if entry is None:
                return {"action": "not_found", "ip": ip}
            mode = entry["mode"]
            if mode == "enforce":
                try:
                    self._unblock_with_iptables(ip)
                except Exception as exc:
                    logger.error("iptables unblock failed for %s: %s", ip, exc)
                    return {"action": "failed", "ip": ip, "reason": str(exc), "mode": mode}
                action = "unblocked_iptables"
            else:
                action = "dry_run_unblocked"
            del self._blocked[ip]
        return {"action": action, "ip": ip, "mode": mode}

    def get_blocked(self) -> List[dict]:
        """Return list of currently blocked IPs with metadata."""
        now = time.time()
        with self._lock:
            result = []
            for ip, meta in self._blocked.items():
                elapsed = now - meta["blocked_at"]
                remaining = max(0.0, meta["ttl"] - elapsed)
                result.append({
                    "ip": ip,
                    "reason": meta["reason"],
                    "mode": meta["mode"],
                    "blocked_at": meta["blocked_at"],
                    "ttl": meta["ttl"],
                    "expires_in_seconds": round(remaining, 1),
                })
        return result

    # ------------------------------------------------------------------ #
    #  iptables helpers (only reached in enforce mode)                    #
    # ------------------------------------------------------------------ #

    def _block_with_iptables(self, ip: str) -> None:
        """
        ONLY called in enforce mode.
        Creates NIDS_BLOCK chain if it doesn't exist, then adds a DROP rule.
        """
        subprocess.run(["iptables", "-N", IPTABLES_CHAIN], capture_output=True, check=False)
        ret = subprocess.run(["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN], capture_output=True)
        if ret.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-j", IPTABLES_CHAIN], capture_output=True, check=True)
        subprocess.run(["iptables", "-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], capture_output=True, check=True)

    def _unblock_with_iptables(self, ip: str) -> None:
        """Remove the DROP rule for this IP from the NIDS chain."""
        subprocess.run(["iptables", "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], capture_output=True, check=True)

    # ------------------------------------------------------------------ #
    #  Background TTL cleanup                                             #
    # ------------------------------------------------------------------ #

    def _cleanup_loop(self) -> None:
        """Background daemon thread: expire blocks after their TTL."""
        while True:
            time.sleep(10)  # check every 10 s
            try:
                now = time.time()
                expired = []
                with self._lock:
                    for ip, meta in list(self._blocked.items()):
                        if now - meta["blocked_at"] >= meta["ttl"]:
                            expired.append(ip)
                for ip in expired:
                    logger.info("TTL expired for blocked IP %s — auto-unblocking.", ip)
                    self.unblock_ip(ip)
            except Exception as exc:
                logger.error("prevention cleanup loop error: %s", exc)


# Module-level singleton
prevention_service = PreventionService()
