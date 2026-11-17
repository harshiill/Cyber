import json
import joblib
from pathlib import Path
from typing import Dict, Optional

# Resolve paths relative to nids_xai/
_BASE = Path(__file__).parent.parent.parent
_MODEL_DIR = _BASE / "models"
_METADATA_FILE = _MODEL_DIR / "model_metadata.json"


class ModelService:
    """Singleton that owns the loaded model and preprocessor."""

    def __init__(self):
        self._model = None
        self._preprocessor = None
        self._feature_names = []
        self._current_file: Optional[str] = None
        self._metadata: Optional[Dict] = None

    # -- public properties --------------------------------------------------

    @property
    def model(self):
        return self._model

    @property
    def preprocessor(self):
        return self._preprocessor

    @property
    def feature_names(self):
        return self._feature_names

    @property
    def dataset(self) -> Optional[str]:
        return self._metadata.get("dataset") if self._metadata else None

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    # -- public methods -----------------------------------------------------

    def list_models(self) -> Dict:
        """Return contents of model_metadata.json (empty dict if absent)."""
        if not _METADATA_FILE.exists():
            return {}
        with open(_METADATA_FILE) as f:
            return json.load(f)

    def status(self) -> Dict:
        return {
            "loaded": self.is_loaded,
            "model_file": self._current_file,
            "dataset": self.dataset,
            "metadata": self._metadata,
            "feature_count": len(self._feature_names),
        }

    def load(self, model_filename: str) -> Dict:
        """Load a model + matching preprocessor by filename."""
        from api.services.monitor_service import monitor_service
        if monitor_service.is_running:
            raise RuntimeError("Stop monitoring before switching models.")
        model_path = _MODEL_DIR / model_filename
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_filename}")

        saved = joblib.load(model_path)
        if not isinstance(saved, dict) or not saved.get("schema_id"):
            raise ValueError("Model has no preprocessing identity. Retrain it from raw data.")
        new_model = saved["model"]
        new_feature_names = list(saved.get("feature_names", []))

        import sys
        sys.path.insert(0, str(_BASE))
        from src.preprocessor import Preprocessor
        from src.training_data import preprocessing_id
        dataset = self._resolve_dataset(model_filename)
        prep = Preprocessor()
        try:
            prep.load(dataset)
        except FileNotFoundError as exc:
            raise ValueError("Matching preprocessing data is missing. Retrain the model.") from exc
        if saved["schema_id"] != preprocessing_id(prep) or new_feature_names != list(prep.feature_names):
            raise ValueError("Model and preprocessing data do not match. Retrain the model.")
        self._model = new_model
        self._feature_names = new_feature_names
        self._preprocessor = prep

        # Record metadata
        all_meta = self.list_models()
        self._metadata = all_meta.get(model_filename, {"dataset": dataset})
        self._current_file = model_filename

        # Invalidate any cached SHAP/LIME explainer so it rebuilds against the
        # newly loaded model (local import avoids a circular dependency).
        from api.services.explainer_service import explainer_service
        explainer_service.reset()
        from api.services.type_classifier_service import type_classifier_service
        type_classifier_service.reset()

        return self.status()

    def load_latest(self) -> Optional[Dict]:
        """Load the most recently used model from metadata. Returns None if none exist."""
        models = self.list_models()
        if not models:
            return None
        latest = max(models.items(), key=lambda kv: kv[1].get("last_used", ""), default=None)
        if latest:
            try:
                return self.load(latest[0])
            except (FileNotFoundError, ValueError):
                return None
        return None

    # -- helpers ------------------------------------------------------------

    def _resolve_dataset(self, filename: str) -> str:
        """Infer dataset (2017/2018) from filename or fall back to default."""
        if "2018" in filename:
            return "2018"
        return "2017"


# Global singleton
model_service = ModelService()
