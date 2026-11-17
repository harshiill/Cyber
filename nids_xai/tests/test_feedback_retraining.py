import numpy as np
from scripts.retrain import collect_feedback_samples


def test_feedback_uses_latest_compatible_live_labels_only():
    records = [
        {'alert_id': 'a', 'label': 'true_positive', 'features': [1, 2], 'dataset': '2017', 'feature_names': ['a', 'b'], 'schema_id': 'v1', 'traffic_origin': 'live'},
        {'alert_id': 'a', 'label': 'false_positive', 'features': [1, 2], 'dataset': '2017', 'feature_names': ['a', 'b'], 'schema_id': 'v1', 'traffic_origin': 'live'},
        {'alert_id': 'b', 'label': 'true_positive', 'features': [3, 4], 'dataset': '2017', 'feature_names': ['a', 'b'], 'schema_id': 'old', 'traffic_origin': 'live'},
        {'alert_id': 'c', 'label': 'true_positive', 'features': [5, 6], 'dataset': '2017', 'feature_names': ['a', 'b'], 'schema_id': 'v1', 'traffic_origin': 'dataset_replay'},
    ]
    X, y = collect_feedback_samples(records, '2017', ['a', 'b'], 'v1')
    np.testing.assert_array_equal(X, [[1, 2]])
    np.testing.assert_array_equal(y, [0])


def test_feedback_candidate_is_listed_without_becoming_active(tmp_path):
    import json
    from scripts.retrain import register_candidate
    metadata = tmp_path / 'model_metadata.json'
    metadata.write_text(json.dumps({'current.joblib': {'last_used': '2026-01-01'}}))
    register_candidate(metadata, 'candidate.joblib', '2018', 3)
    data = json.loads(metadata.read_text())
    assert data['candidate.joblib']['dataset'] == '2018'
    assert data['candidate.joblib']['last_used'] == ''
    assert data['candidate.joblib']['review_required'] is True
