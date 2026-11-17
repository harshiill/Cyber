"""
Real-Time Network Monitor for NIDS-XAI.

Captures live network traffic or replays PCAP files, assembles packets into
flows, and classifies each completed flow using the trained NIDS model.

Flow lifecycle:
  1. Packets arrive -> routed to NetworkFlow by 5-tuple FlowKey
  2. Sweep thread expires idle flows -> extract CIC-IDS features
  3. Features -> preprocessor.transform() -> model.predict_proba()
  4. If P(Attack) >= threshold -> emit alert via callback

Author: Final Year CS Project
"""

import sys
import os
import threading
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable
from pathlib import Path

import pandas as pd
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Reuse existing flow tracking -- do NOT duplicate
from tools.pcap_to_csv import FlowKey, NetworkFlow

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from config.config import (
    MONITOR_IDLE_TIMEOUT_LIVE,
    MONITOR_IDLE_TIMEOUT_REPLAY,
    MONITOR_DEFAULT_THRESHOLD,
    MONITOR_SWEEP_INTERVAL,
    MONITOR_MIN_FLOW_PACKETS,
    MONITOR_LOG_FEATURES,
)

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Real-time network flow monitor.

    Supports two capture modes:
      - Live: Scapy sniff() on a selected network interface
      - Replay: Process a PCAP file packet-by-packet

    Results are emitted via event_callback (called from a worker thread).
    The callback receives a MonitorEvent dict -- the caller is responsible
    for thread-safe dispatch to the GUI (e.g., via a Queue).
    """

    def __init__(
        self,
        model,
        preprocessor,
        explainer,
        event_callback: Callable[[Dict], None],
        threshold: float = MONITOR_DEFAULT_THRESHOLD,
        min_packets: int = MONITOR_MIN_FLOW_PACKETS,
    ):
        self.model = model
        self.preprocessor = preprocessor
        self.explainer = explainer
        self.event_callback = event_callback
        self.threshold = threshold
        self.min_packets = min_packets
        self.idle_timeout = MONITOR_IDLE_TIMEOUT_LIVE  # updated per mode

        # Flow table
        self._flows: Dict = {}
        self._flows_lock = threading.Lock()

        # Control
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._sweep_thread: Optional[threading.Thread] = None

        # Stats
        self._stats = {"active_flows": 0, "classified": 0, "alerts": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_live(self, interface: str) -> None:
        """Start capturing from a live network interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install scapy\n"
                "On Windows, also install Npcap from https://nmap.org/npcap/"
            )
        self.idle_timeout = MONITOR_IDLE_TIMEOUT_LIVE
        self._stop_event.clear()
        self._start_threads(target=self._capture_live, args=(interface,))

    def start_replay(self, pcap_path: str) -> None:
        """Replay a PCAP file, processing flows as if live."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. Run: pip install scapy"
            )
        if not Path(pcap_path).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.idle_timeout = MONITOR_IDLE_TIMEOUT_REPLAY
        self._stop_event.clear()
        self._start_threads(target=self._capture_replay, args=(pcap_path,))

    def stop(self) -> None:
        """Signal all threads to stop and flush remaining flows."""
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout=3.0)
        if self._sweep_thread:
            self._sweep_thread.join(timeout=3.0)
        self._flush_all()

    def update_threshold(self, threshold: float) -> None:
        """Hot-update confidence threshold without restarting capture."""
        self.threshold = max(0.0, min(1.0, threshold))

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set()

    # ------------------------------------------------------------------
    # Thread management
    # ------------------------------------------------------------------

    def _start_threads(self, target: Callable, args: tuple) -> None:
        self._sweep_thread = threading.Thread(
            target=self._sweep_loop, daemon=True, name="monitor-sweep"
        )
        self._capture_thread = threading.Thread(
            target=target, args=args, daemon=True, name="monitor-capture"
        )
        self._sweep_thread.start()
        self._capture_thread.start()

    # ------------------------------------------------------------------
    # Capture threads
    # ------------------------------------------------------------------

    def _capture_live(self, interface: str) -> None:
        """Thread: sniff live packets on interface."""
        try:
            while not self._stop_event.is_set():
                sniff(iface=interface, prn=self._packet_handler, store=False, timeout=1)
        except Exception as e:
            self._stop_event.set()
            logger.error(f"Live capture error on {interface}: {e}")
            # Emit an error event so the GUI can show a message
            self.event_callback({
                "type": "monitor_error",
                "message": str(e),
            })

    def _capture_replay(self, pcap_path: str) -> None:
        """Thread: replay a PCAP file packet by packet."""
        try:
            pkts = rdpcap(pcap_path)
            for pkt in pkts:
                if self._stop_event.is_set():
                    break
                self._packet_handler(pkt)
            # Signal replay complete
            if not self._stop_event.is_set():
                self._stop_event.set()
                self._flush_all()
                self.event_callback({
                    "type": "monitor_replay_done",
                    "message": f"Replay complete: {len(pkts)} packets processed",
                    "stats": dict(self._stats),
                })
        except Exception as e:
            logger.error(f"PCAP replay error: {e}")
            self.event_callback({
                "type": "monitor_error",
                "message": str(e),
            })

    # ------------------------------------------------------------------
    # Packet handling (called from capture thread)
    # ------------------------------------------------------------------

    def _packet_handler(self, pkt) -> None:
        """
        Route a Scapy packet to the correct NetworkFlow.
        Mirrors PcapConverter._process_packet() logic from tools/pcap_to_csv.py,
        using the exact same add_packet() signature:
            flow.add_packet(src_ip, packet_size, timestamp, header_length,
                            tcp_flags, window_size)
        """
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto

        src_port = 0
        dst_port = 0
        tcp_flags = {}
        window_size = 0
        header_length = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            header_length = (tcp.dataofs or 5) * 4
            window_size = tcp.window if hasattr(tcp, 'window') else 0

            # Parse TCP flags into dict (same format as PcapConverter)
            flags = tcp.flags if hasattr(tcp, 'flags') else 0
            tcp_flags = {
                'FIN': bool(int(flags) & 0x01),
                'SYN': bool(int(flags) & 0x02),
                'RST': bool(int(flags) & 0x04),
                'PSH': bool(int(flags) & 0x08),
                'ACK': bool(int(flags) & 0x10),
                'URG': bool(int(flags) & 0x20),
                'ECE': bool(int(flags) & 0x40),
                'CWR': bool(int(flags) & 0x80),
            }
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            header_length = 8

        # Build flow key (bidirectional matching handled by FlowKey.__eq__)
        fwd_key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)

        timestamp = float(pkt.time)
        # Measure at the IP layer to match CICFlowMeter (which generated the
        # training data). len(pkt) would include the 14-byte Ethernet frame
        # header, shifting every packet-length feature off the trained
        # distribution. ip.len is the IP total-length field; fall back to the
        # dissected length only if it is unset.
        packet_size = int(ip.len) if getattr(ip, "len", 0) else len(ip)

        with self._flows_lock:
            if fwd_key in self._flows:
                flow = self._flows[fwd_key]
            else:
                # New flow -- create with the original src as the flow initiator
                flow = NetworkFlow(
                    src_ip, dst_ip, src_port, dst_port, protocol, timestamp
                )
                self._flows[fwd_key] = flow

            # Call add_packet with the exact signature from NetworkFlow
            flow.add_packet(
                src_ip=src_ip,
                src_port=src_port,
                packet_size=packet_size,
                timestamp=timestamp,
                header_length=header_length,
                tcp_flags=tcp_flags,
                window_size=window_size,
            )
            self._stats["active_flows"] = len(self._flows)

    # ------------------------------------------------------------------
    # Sweep thread (expires idle flows)
    # ------------------------------------------------------------------

    def _sweep_loop(self) -> None:
        """Thread: periodically expire idle flows and classify them."""
        while not self._stop_event.is_set():
            time.sleep(MONITOR_SWEEP_INTERVAL)
            self._expire_flows()
        # Final flush when stopped
        self._flush_all()

    def _expire_flows(self) -> None:
        """Find idle flows and classify them."""
        now = time.time()
        expired = []

        with self._flows_lock:
            for key, flow in list(self._flows.items()):
                # NetworkFlow tracks last packet time via end_time attribute
                last_seen = flow.end_time
                if now - last_seen >= self.idle_timeout:
                    expired.append((key, flow))
                    del self._flows[key]
            self._stats["active_flows"] = len(self._flows)

        for key, flow in expired:
            self._classify_and_emit(flow, key)

    def _flush_all(self) -> None:
        """Classify and emit all remaining flows."""
        with self._flows_lock:
            remaining = list(self._flows.items())
            self._flows.clear()
            self._stats["active_flows"] = 0

        for key, flow in remaining:
            self._classify_and_emit(flow, key)

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify_and_emit(self, flow, key) -> None:
        """Extract features, classify, and emit MonitorEvent."""
        try:
            # Check minimum packet count
            # NetworkFlow stores packets as lists: fwd_packets, bwd_packets
            total_pkts = len(flow.fwd_packets) + len(flow.bwd_packets)
            if total_pkts < self.min_packets:
                return

            # Extract CIC-IDS features
            raw = flow.get_features()
            if not raw:
                return

            missing = sorted(set(getattr(self.preprocessor, "feature_names", [])) - set(raw))
            experimental = os.environ.get("NIDS_EXPERIMENTAL_LIVE_ML", "0") == "1"
            if missing or not experimental:
                reason = ("Missing model features: " + ", ".join(missing)) if missing else (
                    "Live flow features are unvalidated against the training extractor; ML is disabled."
                )
                self.event_callback({
                    "type": "monitor_event", "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "src_ip": key.src_ip, "src_port": key.src_port, "dst_ip": key.dst_ip,
                    "dst_port": key.dst_port, "prediction": "Unclassified", "confidence": None,
                    "is_alert": False, "features": None, "missing_features": missing, "ml_reason": reason,
                    "syn_flag_count": raw.get("SYN Flag Count", 0),
                    "ack_flag_count": raw.get("ACK Flag Count", 0),
                })
                return

            # Transform via preprocessor
            df = pd.DataFrame([raw])
            X = self.preprocessor.transform(df)

            # Predict
            proba = self.model.predict_proba(X)[0]
            pred_code = int(self.model.predict(X)[0])
            confidence = float(proba[pred_code])
            prediction = "Attack" if pred_code == 1 else "Benign"
            is_alert = (pred_code == 1) and (proba[1] >= self.threshold)

            # Live debug: dump the raw feature vector so it can be compared
            # against a dataset row to diagnose the live-vs-CICFlowMeter gap.
            if MONITOR_LOG_FEATURES:
                model_feats = getattr(self.preprocessor, "feature_names", []) or []
                shown = {k: raw.get(k) for k in model_feats} if model_feats else raw
                logger.info(
                    "FLOW %s:%s->%s:%s pkts=%d pred=%s P(attack)=%.3f feats=%s",
                    key.src_ip, key.src_port, key.dst_ip, key.dst_port,
                    total_pkts, prediction, float(proba[1]), shown,
                )

            # SHAP explanation (attacks only, if explainer ready)
            shap_factors = []
            if is_alert and self.explainer is not None and self.explainer.is_ready:
                try:
                    expl = self.explainer.explain(X, method="shap")
                    shap_expl = expl.get("shap_explanation", {})
                    if shap_expl and "contributions" in shap_expl:
                        for c in shap_expl["contributions"][:3]:
                            shap_factors.append({
                                "feature": c["feature"],
                                "shap_value": round(c["shap_value"], 4),
                                "direction": c["direction"],
                            })
                except Exception as e:
                    logger.debug(f"SHAP failed for flow: {e}")

            # Update stats
            self._stats["classified"] += 1
            if is_alert:
                self._stats["alerts"] += 1

            # Build protocol string
            proto_map = {6: "TCP", 17: "UDP"}
            proto_str = proto_map.get(key.protocol, "OTHER")

            event = {
                "type": "monitor_event",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "src_ip": key.src_ip,
                "src_port": key.src_port,
                "dst_ip": key.dst_ip,
                "dst_port": key.dst_port,
                "protocol": proto_str,
                "prediction": prediction,
                "confidence": float(proba[1]),  # always show attack probability
                "is_alert": is_alert,
                "shap_factors": shap_factors,
                "features": X[0].tolist(),
                "stats": dict(self._stats),
                "syn_flag_count": raw.get("SYN Flag Count", 0),
                "ack_flag_count": raw.get("ACK Flag Count", 0),
            }

            self.event_callback(event)

        except Exception as e:
            logger.error(f"Classification error: {e}", exc_info=True)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def get_interfaces() -> List[str]:
        """Return list of available (up) network interface names."""
        if not PSUTIL_AVAILABLE:
            return ["eth0", "Wi-Fi", "Ethernet"]
        try:
            stats = psutil.net_if_stats()
            return [name for name, s in stats.items() if s.isup] or list(stats.keys())
        except Exception:
            return ["eth0", "Wi-Fi", "Ethernet"]
