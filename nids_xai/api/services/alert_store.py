import uuid
import threading
from collections import deque
from typing import Dict, List, Optional


class AlertStore:
    """Thread-safe ring buffer for flow alert dicts."""

    def __init__(self, maxlen: int = 500):
        self._lock = threading.Lock()
        self._deque: deque = deque(maxlen=maxlen)

    def push(self, alert: Dict) -> Dict:
        """Assign a UUID id and store the alert. Returns the stored alert."""
        alert = dict(alert)
        alert["id"] = str(uuid.uuid4())
        with self._lock:
            self._deque.append(alert)
        return alert

    def get(self, limit: int = 100, filter_type: str = "all") -> List[Dict]:
        """Return alerts newest-first, optionally filtered."""
        with self._lock:
            items = list(self._deque)
        items.reverse()
        if filter_type == "attack":
            items = [a for a in items if a.get("is_attack")]
        elif filter_type == "benign":
            items = [a for a in items if not a.get("is_attack") and a.get("prediction") != "Unclassified"]
        return items[:limit]

    def get_by_id(self, alert_id: str) -> Optional[Dict]:
        with self._lock:
            for alert in self._deque:
                if alert.get("id") == alert_id:
                    return dict(alert)
        return None

    def stats(self) -> Dict:
        with self._lock:
            items = list(self._deque)
        attacks = sum(1 for a in items if a.get("is_attack"))
        unclassified = sum(1 for a in items if not a.get("is_attack") and a.get("prediction") == "Unclassified")
        return {"total": len(items), "attacks": attacks, "benign": len(items) - attacks - unclassified,
                "unclassified": unclassified}

    def clear(self) -> int:
        """Empty the buffer. Returns number of alerts removed."""
        with self._lock:
            n = len(self._deque)
            self._deque.clear()
        return n


# Global singleton used by all routers
alert_store = AlertStore(maxlen=500)
