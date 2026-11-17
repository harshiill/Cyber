"""
Secondary multi-class classifier that names the attack type (Port Scan, DoS Hulk,
SSH-Bruteforce, ...) for a flow the binary detector has already flagged as an attack.
Kept separate from the binary model so the headline detection results are unchanged.
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
_BASE = Path(__file__).parent.parent.parent


class TypeClassifierService:
    def __init__(self):
        self._model = None
        self._types = None
        self._dataset = None
        self._shap = None
        self._lime = None
        self._feature_names = None

    def _load(self, dataset: str) -> bool:
        if self._model is not None and self._dataset == dataset:
            return True
        import joblib
        path = _BASE / "models" / f"type_model_{dataset}.joblib"
        if not path.exists():
            self._model = None
            self._dataset = dataset
            return False
        data = joblib.load(path)
        from api.services.model_service import model_service
        from src.training_data import preprocessing_id
        schema_id = preprocessing_id(model_service.preprocessor)
        if not schema_id or data.get("schema_id") != schema_id:
            self._model = None
            self._dataset = dataset
            return False
        self._model = data["model"]
        self._types = list(data["attack_types"])
        self._dataset = dataset
        return True

    def predict(self, X, dataset: str):
        """X: shape (1, n_features). Returns {'type', 'confidence'} or None."""
        if not self._load(dataset) or self._model is None:
            return None
        try:
            proba = self._model.predict_proba(X)[0]
            j = int(proba.argmax())
            cls = int(self._model.classes_[j])
            name = self._types[cls] if (self._types and 0 <= cls < len(self._types)) else "Unknown"
            return {"type": name, "confidence": float(proba[j])}
        except Exception as e:
            logger.debug("Attack-type prediction failed: %s", e)
            return None

    def _ensure_explainers(self, dataset, feature_names):
        """Lazily build a SHAP TreeExplainer and a LIME explainer for the type model."""
        if self._shap is not None and self._dataset == dataset and self._lime is not None:
            return
        import numpy as np
        import shap
        import lime.lime_tabular
        npz = _BASE / "data" / "processed" / f"processed_data_{dataset}.npz"
        data = np.load(npz, allow_pickle=True)
        X, y = data["X"], data["y"]
        atk = X[y == 1]
        idx = np.random.choice(len(atk), min(150, len(atk)), replace=False)
        bg = atk[idx]
        self._shap = shap.TreeExplainer(self._model)
        class_names = [self._types[int(c)] if (self._types and 0 <= int(c) < len(self._types)) else str(c)
                       for c in self._model.classes_]
        self._lime = lime.lime_tabular.LimeTabularExplainer(
            bg, feature_names=list(feature_names), class_names=class_names,
            mode="classification", discretize_continuous=True)
        self._feature_names = list(feature_names)

    def explain_type(self, X, dataset, feature_names, want_lime=True):
        """Explain WHY the type model assigned this attack type, with SHAP and LIME."""
        if not self._load(dataset) or self._model is None:
            return None
        import numpy as np
        try:
            self._ensure_explainers(dataset, feature_names)
        except Exception as e:
            logger.debug("Type explainers unavailable: %s", e)

        proba = self._model.predict_proba(X)[0]
        j = int(proba.argmax())
        cls = int(self._model.classes_[j])
        name = self._types[cls] if (self._types and 0 <= cls < len(self._types)) else "Unknown"
        conf = float(proba[j])

        shap_feats = []
        try:
            sv = self._shap.shap_values(X)
            if isinstance(sv, list):
                arr = np.asarray(sv[j])[0]
            else:
                a = np.asarray(sv)
                arr = a[0, :, j] if a.ndim == 3 else a[0]
            pairs = sorted(zip(feature_names, arr), key=lambda t: abs(t[1]), reverse=True)
            for f, v in pairs[:8]:
                if abs(float(v)) < 1e-4:
                    continue
                shap_feats.append({"feature": f, "value": round(float(v), 4),
                                   "direction": "positive" if v > 0 else "negative"})
        except Exception as e:
            logger.debug("Type SHAP failed: %s", e)

        lime_rules = []
        if want_lime and self._lime is not None:
            try:
                exp = self._lime.explain_instance(X[0], self._model.predict_proba, num_features=8, labels=(j,))
                for desc, w in exp.as_list(label=j):
                    fn = next((n for n in feature_names if n in desc), desc.split()[0] if desc else "Unknown")
                    lime_rules.append({"feature": fn, "description": desc, "weight": round(float(w), 4),
                                       "direction": "positive" if w > 0 else "negative"})
            except Exception as e:
                logger.debug("Type LIME failed: %s", e)

        top = [f["feature"] for f in shap_feats if f["direction"] == "positive"][:3]
        narrative = f"The type classifier identified this attack as {name} with {conf * 100:.0f}% confidence. "
        if top:
            narrative += "The measurements most characteristic of " + name + " were " + ", ".join(top) + ". "
        narrative += "These are the patterns that separate " + name + " from the other attack types the model has seen."

        return {"predicted_type": name, "confidence": round(conf, 4),
                "shap": shap_feats, "lime": lime_rules, "narrative": narrative}

    def reset(self):
        self._model = None
        self._dataset = None
        self._shap = None
        self._lime = None


type_classifier_service = TypeClassifierService()
