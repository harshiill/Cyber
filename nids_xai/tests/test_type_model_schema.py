import joblib
from api.services.type_classifier_service import TypeClassifierService
from api.services.model_service import model_service


def test_type_model_with_different_preprocessing_is_not_used(tmp_path, monkeypatch):
    import api.services.type_classifier_service as module
    model_dir = tmp_path / 'models'
    model_dir.mkdir()
    joblib.dump({'model': 'stale', 'attack_types': [], 'schema_id': 'old'}, model_dir / 'type_model_2017.joblib')
    monkeypatch.setattr(module, '_BASE', tmp_path)
    monkeypatch.setattr(model_service, '_preprocessor', None)
    service = TypeClassifierService()
    assert not service._load('2017')
