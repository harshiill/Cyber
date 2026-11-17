"""Isolation Forest trained only on benign training flows."""
import numpy as np
from sklearn.ensemble import IsolationForest


def train_anomaly_detector(X, y):
    benign = np.asarray(X)[np.asarray(y) == 0]
    if len(benign) < 20:
        raise ValueError('At least 20 benign training flows are required for anomaly detection')
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    return model.fit(benign)


def score_anomaly(model, X):
    margin = float(model.decision_function(np.asarray(X))[0])
    return {'is_anomaly': margin < 0, 'margin': margin}
