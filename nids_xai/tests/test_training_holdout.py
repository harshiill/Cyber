import numpy as np
import pandas as pd
from src.preprocessor import Preprocessor
from src.training_data import prepare_holdout


def test_preprocessing_is_fitted_only_on_training_rows():
    data = pd.DataFrame({'signal': np.arange(100, dtype=float),
                         'Label': ['BENIGN', 'Attack'] * 50})
    preprocessor = Preprocessor()
    result = prepare_holdout(data, preprocessor, '2017')
    assert len(result['X_train']) == 80
    assert len(result['X_test']) == 20
    assert np.mean(result['X_train'], axis=0) == pytest_approx_zero()
    assert abs(float(np.mean(result['X_test']))) > 0.001
    assert len(set(result['y_train'])) == 2


def pytest_approx_zero():
    import pytest
    return pytest.approx([0.0], abs=1e-6)


def test_training_endpoint_accepts_explicit_bundled_sample(monkeypatch):
    from api.routers.train import TrainRequest, start_training
    from api.services.training_service import training_service
    seen = []
    monkeypatch.setattr(training_service, '_running', False)
    monkeypatch.setattr(training_service, 'start', lambda dataset, mode, service, source: seen.append(source))
    start_training(TrainRequest(dataset='2018', source='sample'))
    assert seen == ['sample']
