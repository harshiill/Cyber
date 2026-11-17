import pytest
import numpy as np
from scapy.all import IP, TCP
from src.monitor import NetworkMonitor


class Preprocessor:
    feature_names = ['Total Fwd Packets', 'Total Backward Packets', 'Flow Duration']

    def transform(self, data):
        assert data['Total Fwd Packets'].iloc[0] == 1
        assert data['Total Backward Packets'].iloc[0] == 1
        assert data['Flow Duration'].iloc[0] == pytest.approx(1000000)
        return np.array([[0, 0, 0]])


class Model:
    def predict_proba(self, x): return [[0.9, 0.1]]
    def predict(self, x): return [0]


def test_bidirectional_packet_flow_produces_one_classified_event(monkeypatch):
    monkeypatch.setenv("NIDS_EXPERIMENTAL_LIVE_ML", "1")
    events = []
    monitor = NetworkMonitor(Model(), Preprocessor(), None, events.append)
    first = IP(src='192.0.2.1', dst='192.0.2.2') / TCP(sport=40000, dport=443, flags='S')
    second = IP(src='192.0.2.2', dst='192.0.2.1') / TCP(sport=443, dport=40000, flags='SA')
    first.time, second.time = 1000.0, 1001.0
    monitor._packet_handler(first)
    monitor._packet_handler(second)
    monitor._flush_all()
    assert len(events) == 1
    assert events[0]['src_ip'] == '192.0.2.1'
    assert events[0]['prediction'] == 'Benign'


def test_incompatible_live_features_emit_rule_only_event(monkeypatch):
    monkeypatch.setenv("NIDS_EXPERIMENTAL_LIVE_ML", "1")
    events = []
    preprocessor = Preprocessor()
    preprocessor.feature_names = ['unsupported feature']
    monitor = NetworkMonitor(Model(), preprocessor, None, events.append)
    packet = IP(src='192.0.2.1', dst='192.0.2.2') / TCP(sport=40000, dport=443, flags='S')
    packet.time = 1000.0
    monitor._packet_handler(packet)
    monitor._flush_all()
    assert len(events) == 1
    assert events[0]['confidence'] is None
    assert events[0]['prediction'] == 'Unclassified'


def test_capture_can_stop_without_receiving_packets(monkeypatch):
    import threading
    import src.monitor as monitor_module
    seen = threading.Event()
    def sniff_once(**kwargs):
        assert kwargs['timeout'] == 1
        seen.set()
        monitor._stop_event.set()
    monkeypatch.setattr(monitor_module, 'sniff', sniff_once)
    monitor = NetworkMonitor(Model(), Preprocessor(), None, lambda event: None)
    monitor._capture_live('test')
    assert seen.is_set()


def test_live_ml_requires_explicit_opt_in_for_unvalidated_extractor(monkeypatch):
    monkeypatch.delenv('NIDS_EXPERIMENTAL_LIVE_ML', raising=False)
    events = []
    monitor = NetworkMonitor(Model(), Preprocessor(), None, events.append)
    packet = IP(src='192.0.2.1', dst='192.0.2.2') / TCP(sport=40000, dport=443, flags='S')
    packet.time = 1000.0
    monitor._packet_handler(packet)
    monitor._flush_all()
    assert events[0]['prediction'] == 'Unclassified'
    assert 'unvalidated' in events[0]['ml_reason'].lower()


def test_loopback_flow_distinguishes_packet_direction():
    from tools.pcap_to_csv import NetworkFlow
    flow = NetworkFlow('127.0.0.1', '127.0.0.1', 40000, 8080, 6, 1.0)
    flow.add_packet('127.0.0.1', 40, 1.0, 20, {}, 0, src_port=40000)
    flow.add_packet('127.0.0.1', 40, 2.0, 20, {}, 0, src_port=8080)
    assert len(flow.fwd_packets) == len(flow.bwd_packets) == 1


def test_packets_flow_through_rule_alert_and_simulated_prevention(monkeypatch):
    from api.services.alert_store import AlertStore
    from api.services.monitor_service import MonitorService
    from api.services.prevention_service import prevention_service
    calls = []
    monkeypatch.delenv('NIDS_EXPERIMENTAL_LIVE_ML', raising=False)
    monkeypatch.setattr(prevention_service, 'block_ip', lambda ip, reason: calls.append((ip, reason)) or {'action': 'dry_run_blocked'})
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._mode = 'live'
    service._traffic_origin = 'live'
    monitor = NetworkMonitor(Model(), Preprocessor(), None, service._on_event)
    for port in range(1000, 1050):
        packet = IP(src='192.0.2.1', dst='192.0.2.2') / TCP(sport=40000, dport=port, flags='S')
        packet.time = 1000.0
        monitor._packet_handler(packet)
    monitor._flush_all()
    alert = service._alert_store.get(limit=1)[0]
    assert alert['is_attack']
    assert alert['ml_available'] is False
    assert any(rule['rule_id'] == 'PORTSCAN_01' for rule in alert['matched_rules'])
    assert alert['prevention']['action'] == 'dry_run_blocked'
    assert calls[0][0] == '192.0.2.1'
