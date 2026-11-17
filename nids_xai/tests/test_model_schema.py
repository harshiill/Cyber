import joblib
import numpy as np
import pytest
from sklearn.preprocessing import StandardScaler
from api.services.model_service import ModelService
from src.preprocessor import Preprocessor


def test_mismatched_preprocessing_cannot_replace_loaded_model(tmp_path, monkeypatch):
    import api.services.model_service as module
    monkeypatch.setattr(module, '_MODEL_DIR', tmp_path)
    joblib.dump({'model': 'new', 'feature_names': ['x'], 'schema_id': 'other'}, tmp_path / 'model_2018.joblib')
    def load(self, dataset):
        self.feature_names = ['x']
        self.scaler = StandardScaler().fit(np.array([[0.], [1.]]))
    monkeypatch.setattr(Preprocessor, 'load', load)
    service = ModelService()
    service._model = 'old'
    with pytest.raises(ValueError, match='preprocessing'):
        service.load('model_2018.joblib')
    assert service.model == 'old'
