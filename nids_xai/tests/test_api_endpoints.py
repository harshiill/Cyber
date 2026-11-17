"""Smoke tests against the live FastAPI app."""
import pytest


def test_status_endpoint_returns_required_fields(api_client):
    r = api_client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert "model_loaded" in body
    assert "monitor_running" in body
    assert isinstance(body["monitor_running"], bool)


def test_model_endpoint_reports_loaded_state(api_client):
    r = api_client.get("/api/model")
    assert r.status_code == 200
    body = r.json()
    assert "loaded" in body
    if body["loaded"]:
        assert isinstance(body.get("feature_count"), int)
        assert body["feature_count"] > 0


def test_alerts_endpoint_returns_list(api_client):
    r = api_client.get("/api/alerts?limit=10")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_alerts_clear_endpoint(api_client):
    r = api_client.post("/api/alerts/clear")
    assert r.status_code == 200
    assert r.json().get("cleared") is True


def test_evaluate_metrics_in_valid_range(api_client):
    """Run evaluate against the loaded model — metrics must be in [0,1]."""
    r = api_client.get("/api/model")
    if not r.json().get("loaded"):
        pytest.skip("No model loaded — train one first to run this test.")

    r = api_client.post("/api/evaluate", json={})
    if r.status_code == 404:
        pytest.skip("No processed dataset available.")
    assert r.status_code == 200, r.text
    body = r.json()
    for key in ("accuracy", "precision", "recall", "f1", "roc_auc", "specificity"):
        assert 0.0 <= body[key] <= 1.0, f"{key}={body[key]} out of [0,1]"
    assert body["tp"] + body["tn"] + body["fp"] + body["fn"] == body["test_samples"]


def test_attack_breakdown_does_not_include_benign(api_client):
    if not api_client.get('/api/model').json().get('loaded'):
        pytest.skip('No model loaded')
    response = api_client.post('/api/evaluate', json={})
    if response.status_code == 404:
        pytest.skip('No holdout data')
    assert response.status_code == 200
    assert all(str(row['attack']).strip().upper() != 'BENIGN' for row in response.json()['attack_breakdown'])
