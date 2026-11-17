"""
Train the secondary attack-type classifier for a dataset.

Reads the processed NPZ for the dataset, takes the attack rows only, and trains a
multi-class Random Forest that names the attack type (Port Scan, DoS Hulk, ...).
Saved as models/type_model_<dataset>.joblib alongside the binary detector, so the
two are always trained on the same features and stay in sync.

Run directly:  python src/type_trainer.py            (trains 2017 and 2018)
               python src/type_trainer.py 2018        (trains one)
"""
import collections
from pathlib import Path

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

BASE = Path(__file__).resolve().parent.parent


def train_type_model(dataset: str, min_per_class: int = 10) -> str:
    """Train and save the attack-type classifier for `dataset`. Returns the file path."""
    npz = BASE / "data" / "processed" / f"processed_data_{dataset}.npz"
    if not npz.exists():
        raise FileNotFoundError(f"No processed data for {dataset}: {npz}")

    data = np.load(npz, allow_pickle=True)
    if "split_version" not in data:
        raise ValueError("Processed data has no independent holdout; retrain from raw data first.")
    X, y = data["X_train"], data["y_train"]
    if "y_types" not in data or "attack_types" not in data:
        raise ValueError(f"{npz} has no attack-type labels (y_types / attack_types).")
    y_types = data["types_train"]
    attack_types = list(data["attack_types"])

    mask = y == 1                       # attack rows only -> "which attack is it?"
    Xa, ya = X[mask], y_types[mask]
    # Drop classes too small to learn from.
    counts = collections.Counter(ya.tolist())
    keep = np.array([counts[v] >= min_per_class for v in ya])
    Xa, ya = Xa[keep], ya[keep]
    if len(set(ya.tolist())) < 2:
        raise ValueError(f"Not enough attack-type variety in {dataset} to train a type classifier.")

    clf = RandomForestClassifier(
        n_estimators=120, max_depth=18, class_weight="balanced", n_jobs=-1, random_state=42)
    clf.fit(Xa, ya)

    out = BASE / "models" / f"type_model_{dataset}.joblib"
    out.parent.mkdir(parents=True, exist_ok=True)
    from src.preprocessor import Preprocessor
    from src.training_data import preprocessing_id
    prep = Preprocessor()
    prep.load(dataset)
    joblib.dump({"model": clf, "attack_types": attack_types, "schema_id": preprocessing_id(prep)}, out)
    return str(out)


if __name__ == "__main__":
    import sys
    for ds in (sys.argv[1:] or ["2017", "2018"]):
        path = train_type_model(ds)
        print(f"{ds}: saved {path}")
