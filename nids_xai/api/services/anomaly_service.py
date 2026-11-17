"""Load a dataset's anomaly model only for its matching preprocessing schema."""
from pathlib import Path
import joblib
from src.anomaly import score_anomaly

_BASE = Path(__file__).resolve().parents[2]


class AnomalyService:
    def __init__(self):
        self._key = None
        self._model = None

    def reset(self):
        self._key = None
        self._model = None

    def predict(self, X, dataset, schema_id):
        path = _BASE / 'models' / f'anomaly_model_{dataset}.joblib'
        if not path.exists() or not schema_id:
            return None
        key = (str(path), path.stat().st_mtime_ns, schema_id)
        if key != self._key:
            artifact = joblib.load(path)
            self._model = artifact['model'] if artifact.get('schema_id') == schema_id else None
            self._key = key
        return score_anomaly(self._model, X) if self._model is not None else None


anomaly_service = AnomalyService()
