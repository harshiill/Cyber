import numpy as np
from src.anomaly import train_anomaly_detector, score_anomaly


def test_detector_fits_benign_data_and_flags_extreme_outlier():
    rng = np.random.default_rng(4)
    X = np.r_[rng.normal(0, 1, (200, 2)), [[40., 40.]]]
    y = np.r_[np.zeros(200), [1]]
    detector = train_anomaly_detector(X, y)
    result = score_anomaly(detector, [[40., 40.]])
    assert result['is_anomaly'] is True
    assert isinstance(result['margin'], float)
