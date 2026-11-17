from api.services.alert_store import AlertStore
from api.services.monitor_service import MonitorService


def test_port_scan_is_detected_from_real_source_window():
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._mode = 'live'
    service._source = 'eth0'
    for port in range(1000, 1050):
        service._on_event({'type': 'monitor_event', 'src_ip': '192.0.2.5',
                           'dst_ip': '192.0.2.6', 'dst_port': port,
                           'is_alert': False, 'prediction': 'Benign', 'confidence': 0.05})
    alert = service._alert_store.get(limit=1)[0]
    assert alert['is_attack']
    assert any(rule['rule_id'] == 'PORTSCAN_01' for rule in alert['matched_rules'])


def test_simulated_flow_does_not_trigger_enforcement(monkeypatch):
    from api.services.prevention_service import prevention_service
    called = []
    monkeypatch.setattr(prevention_service, 'block_ip', lambda *args, **kwargs: called.append(args))
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._mode = 'replay'
    service._on_event({'type': 'monitor_event', 'src_ip': '192.0.2.5',
                       'is_alert': True, 'prediction': 'Attack', 'confidence': 1.0,
                       'distinct_dst_ports': 100})
    assert called == []


def test_stream_alert_includes_predicted_attack_type(monkeypatch):
    from api.services.model_service import model_service
    from api.services.type_classifier_service import type_classifier_service
    monkeypatch.setattr(model_service, '_metadata', {'dataset': '2017'})
    monkeypatch.setattr(type_classifier_service, 'predict', lambda x, ds: {'type': 'PortScan', 'confidence': 0.91})
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._mode = 'replay'
    service._on_event({'type': 'monitor_event', 'is_alert': True, 'prediction': 'Attack',
                       'confidence': 0.9, 'features': [0.5, 1.0]})
    alert = service._alert_store.get(limit=1)[0]
    assert alert['attack_type'] == 'PortScan'
    assert alert['attack_type_confidence'] == 0.91


def test_rule_severity_keeps_rule_only_risk_visible():
    from rules.risk_score import compute_risk_score
    risk = compute_risk_score(0.0, 0.75)
    assert risk['level'] == 'HIGH'
    assert risk['score'] >= 70


def test_anomaly_is_visible_without_becoming_a_firewall_block(monkeypatch):
    from api.services.anomaly_service import anomaly_service
    from api.services.model_service import model_service
    from api.services.prevention_service import prevention_service
    monkeypatch.setattr(model_service, '_metadata', {'dataset': '2017'})
    monkeypatch.setattr(anomaly_service, 'predict', lambda *args: {'is_anomaly': True, 'margin': -0.2})
    blocked = []
    monkeypatch.setattr(prevention_service, 'block_ip', lambda *args: blocked.append(args))
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._mode = 'live'
    service._on_event({'type': 'monitor_event', 'src_ip': '192.0.2.10', 'dst_port': 443,
                       'is_alert': False, 'prediction': 'Benign', 'confidence': 0.1, 'features': [1, 2]})
    alert = service._alert_store.get(limit=1)[0]
    assert alert['anomaly']['is_anomaly']
    assert alert['prediction'] == 'Anomaly'
    assert alert['risk_level'] == 'MEDIUM'
    assert blocked == []


def test_stats_payload_reports_monitor_lifecycle():
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._running = True
    assert service.get_stats_payload()['running'] is True
    service._running = False
    assert service.get_stats_payload()['running'] is False


def test_stopped_monitor_does_not_continue_counting_uptime():
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._start_time = 10
    service._end_time = 20
    service._running = False
    assert service.get_stats_payload()['uptime_seconds'] == 10


def test_cannot_replace_active_model_during_monitoring(monkeypatch):
    import pytest
    from fastapi import HTTPException
    from api.routers.model import load_model, LoadRequest
    from api.routers.train import start_training, TrainRequest
    from api.services.monitor_service import monitor_service
    monkeypatch.setattr(monitor_service, '_running', True)
    with pytest.raises(HTTPException) as load_error:
        load_model(LoadRequest(filename='model.joblib'))
    assert load_error.value.status_code == 409
    with pytest.raises(HTTPException) as train_error:
        start_training(TrainRequest())
    assert train_error.value.status_code == 409


def test_anomaly_alone_never_enforces_even_if_its_model_score_is_high(monkeypatch):
    from api.services.anomaly_service import anomaly_service
    from api.services.model_service import model_service
    from api.services.prevention_service import prevention_service
    monkeypatch.setattr(model_service, '_metadata', {'dataset': '2017'})
    monkeypatch.setattr(anomaly_service, 'predict', lambda *args: {'is_anomaly': True, 'margin': -0.2})
    calls = []
    monkeypatch.setattr(prevention_service, 'block_ip', lambda *args: calls.append(args))
    service = MonitorService()
    service.configure(AlertStore(), None, None, None)
    service._mode = 'live'
    service._on_event({'type': 'monitor_event', 'src_ip': '192.0.2.10', 'dst_port': 443,
                       'is_alert': False, 'prediction': 'Benign', 'confidence': 1.0, 'features': [1, 2]})
    assert calls == []
