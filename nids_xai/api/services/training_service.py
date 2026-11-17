import asyncio
import datetime
import json
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import WebSocket

logger = logging.getLogger(__name__)
_BASE = Path(__file__).parent.parent.parent
_METADATA_FILE = _BASE / "models" / "model_metadata.json"


def _write_model_metadata(filename: str, fields: Dict):
    """Merge fields into model_metadata.json under the given filename key."""
    try:
        _METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        all_meta = {}
        if _METADATA_FILE.exists():
            try:
                with open(_METADATA_FILE) as f:
                    all_meta = json.load(f)
            except Exception:
                all_meta = {}
        existing = all_meta.get(filename, {})
        existing.update(fields)
        existing.setdefault("filename",     filename)
        existing.setdefault("display_name", filename.replace(".joblib", ""))
        existing["last_used"] = datetime.datetime.now().isoformat()
        all_meta[filename] = existing
        with open(_METADATA_FILE, "w") as f:
            json.dump(all_meta, f, indent=2)
    except Exception as e:
        logger.warning("Could not write model metadata: %s", e)


class TrainingService:
    """Runs ModelTrainer in a background thread, streams progress over WebSocket."""

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stop_requested = False
        self._connections: List[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def configure(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    @property
    def is_running(self) -> bool:
        return self._running

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    def start(self, dataset: str, mode: str, model_service, source: str = "dataset") -> bool:
        if self._running:
            return False
        self._running = True
        self._stop_requested = False
        self._thread = threading.Thread(
            target=self._run, args=(dataset, mode, model_service, source), daemon=True
        )
        self._thread.start()
        return True

    def stop(self) -> bool:
        """Cooperative cancellation. Effective at progress checkpoints."""
        if not self._running:
            return False
        self._stop_requested = True
        return True

    def _emit(self, msg: dict):
        if not self._loop:
            return
        conns = list(self._connections)

        async def _send():
            dead = []
            for ws in conns:
                try:
                    await ws.send_json(msg)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws)

        asyncio.run_coroutine_threadsafe(_send(), self._loop)

    def _check_stop(self):
        if self._stop_requested:
            self._emit({"type": "error", "msg": "Training cancelled by user."})
            raise InterruptedError("training cancelled")

    def _run(self, dataset: str, mode: str, model_service, source: str = "dataset"):
        try:
            import numpy as np
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            from src.model_trainer import ModelTrainer

            self._emit({"type": "progress", "pct": 5, "msg": f"Loading {dataset} dataset…"})

            from src.data_loader import DataLoader
            from src.preprocessor import Preprocessor
            from src.training_data import prepare_holdout, save_holdout

            if source == "sample":
                import pandas as pd
                filenames = {"2017": "cicids2017_portscan_mixed_3000.csv",
                             "2018": "cicids2018_mixed_attacks.csv"}
                raw = pd.read_csv(_BASE / "examples" / "test_csvs" / filenames[dataset], low_memory=False)
                self._emit({"type": "progress", "pct": 8, "msg": "Using the bundled demonstration sample; results do not represent the full dataset."})
            else:
                loader = DataLoader(dataset=dataset)
                available, _ = loader.get_available_files()
                if not available:
                    self._emit({"type": "error", "msg": f"No raw CIC-IDS{dataset} CSVs found. Add the dataset to data/raw or choose the bundled sample."})
                    return
                raw = loader.load_all()
            if raw is None or len(raw) == 0:
                raise ValueError("Dataset contains no rows")
            preprocessor = Preprocessor()
            split = prepare_holdout(raw, preprocessor, dataset)
            save_holdout(split, preprocessor, dataset)
            del raw
            X_train, X_test = split["X_train"], split["X_test"]
            y_train, y_test = split["y_train"], split["y_test"]
            feature_names = split["feature_names"]
            self._check_stop()

            n_attack = int((y_train == 1).sum())
            n_benign = int((y_train == 0).sum())
            self._emit({
                "type": "progress", "pct": 15,
                "msg": f"Training on {len(X_train):,} samples ({n_attack:,} attacks, {n_benign:,} benign)…",
            })

            self._check_stop()
            trainer = ModelTrainer(mode=mode)

            self._emit({"type": "progress", "pct": 25,
                        "msg": f"Fitting Random Forest ({mode} mode) — this can take a minute…"})

            # Heartbeat thread so the UI doesn't appear frozen during fit
            stop = threading.Event()
            def _heartbeat():
                i = 0
                while not stop.wait(8.0):
                    i += 1
                    pct = min(75, 25 + i * 4)
                    self._emit({"type": "progress", "pct": pct,
                                "msg": f"Random Forest still fitting… ({i * 8}s elapsed)"})
            hb = threading.Thread(target=_heartbeat, daemon=True)
            hb.start()
            try:
                trainer.train(X_train, y_train, feature_names)
            finally:
                stop.set()

            self._check_stop()
            self._emit({"type": "progress", "pct": 80, "msg": "Evaluating on test set…"})
            y_pred = trainer.model.predict(X_test)
            acc  = float(accuracy_score(y_test, y_pred))
            prec = float(precision_score(y_test, y_pred, zero_division=0))
            rec  = float(recall_score(y_test, y_pred, zero_division=0))
            f1   = float(f1_score(y_test, y_pred, zero_division=0))

            importances = trainer.model.feature_importances_
            fi = sorted(
                [{"feature": f, "importance": round(float(imp), 5)}
                 for f, imp in zip(feature_names, importances)],
                key=lambda x: x["importance"], reverse=True,
            )[:15]

            saved_path = trainer.save(dataset=dataset)
            import joblib
            from src.training_data import preprocessing_id
            artifact = joblib.load(saved_path)
            artifact["schema_id"] = preprocessing_id(preprocessor)
            joblib.dump(artifact, saved_path)
            saved_filename = Path(saved_path).name
            _write_model_metadata(saved_filename, {
                "dataset":       dataset,
                "data_source":   source,
                "training_mode": mode,
                "accuracy":      round(acc, 4),
                "precision":     round(prec, 4),
                "recall":        round(rec, 4),
                "f1":            round(f1, 4),
                "train_samples": int(len(X_train)),
                "test_samples":  int(len(X_test)),
                "feature_count": len(feature_names),
                "created_date":  datetime.datetime.now().isoformat(),
            })

            self._emit({"type": "progress", "pct": 87, "msg": "Training benign-flow anomaly detector…"})
            from src.anomaly import train_anomaly_detector
            from src.training_data import preprocessing_id
            import joblib
            anomaly_model = train_anomaly_detector(X_train, y_train)
            joblib.dump({"model": anomaly_model, "schema_id": preprocessing_id(preprocessor)},
                        _BASE / "models" / f"anomaly_model_{dataset}.joblib")
            from api.services.anomaly_service import anomaly_service
            anomaly_service.reset()

            # Train the matching attack-type classifier so it stays in sync with the
            # binary model (same dataset, same features). Cross-dataset still works,
            # since each dataset keeps its own matched pair.
            self._emit({"type": "progress", "pct": 90, "msg": "Training attack-type classifier…"})
            try:
                from src.type_trainer import train_type_model
                train_type_model(dataset)
                from api.services.type_classifier_service import type_classifier_service
                type_classifier_service.reset()
            except Exception as e:
                logger.warning("Attack-type classifier training skipped: %s", e)

            self._emit({"type": "progress", "pct": 95, "msg": "Reloading model into API…"})
            model_service.load_latest()

            self._emit({
                "type": "done",
                "mode": mode,
                "dataset": dataset,
                "data_source": source,
                "train_samples": int(len(X_train)),
                "test_samples":  int(len(X_test)),
                "test_accuracy": round(acc, 4),
                "test_precision": round(prec, 4),
                "test_recall":    round(rec, 4),
                "test_f1":        round(f1, 4),
                "feature_importances": fi,
                "model_file": saved_filename,
            })

        except InterruptedError:
            pass  # message already emitted
        except Exception as e:
            logger.exception("Training failed")
            self._emit({"type": "error", "msg": str(e)})
        finally:
            self._running = False
            self._stop_requested = False


training_service = TrainingService()
