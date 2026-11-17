import logging
from typing import Optional
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
from api.services.model_service import model_service
from api.services.monitor_service import monitor_service
from api.services.explainer_service import explainer_service

logger = logging.getLogger(__name__)
router = APIRouter()

_BASE = Path(__file__).parent.parent.parent


class StartRequest(BaseModel):
    interface: Optional[str] = None
    threshold: float = 0.5


@router.get("/api/monitor/status")
def monitor_status():
    return monitor_service.status()


@router.post("/api/monitor/start")
def start_monitor(req: StartRequest):
    from api.services.training_service import training_service
    if training_service.is_running:
        raise HTTPException(status_code=409, detail="Wait for training to finish before monitoring.")
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded. Load a model first.")
    if monitor_service.is_running:
        raise HTTPException(status_code=400, detail="Monitor already running.")
    if model_service.preprocessor is None:
        raise HTTPException(status_code=400, detail="The loaded model has no matching preprocessor.")
    if not 0 <= req.threshold <= 1:
        raise HTTPException(status_code=400, detail="Threshold must be between 0 and 1.")

    # Build the SHAP/LIME explainer (shared with on-demand explanations).
    # If no processed data is available, monitoring still runs — alerts just
    # won't carry inline SHAP until processed data exists.
    explainer = None
    try:
        explainer = explainer_service.get_explainer(model_service)
    except Exception as e:
        logger.warning("Explainer unavailable, monitoring without inline SHAP: %s", e)

    monitor_service.start(
        model=model_service.model,
        preprocessor=model_service.preprocessor,
        explainer=explainer,
        mode="live",
        interface=req.interface,
        threshold=req.threshold,
    )
    return {"started": True, "mode": "live"}


def _pick_model_for_dataset(target: str) -> Optional[str]:
    """Best model file for a dataset: matching dataset, exists on disk, newest."""
    models = model_service.list_models()
    candidates = [
        (f, m) for f, m in models.items()
        if str(m.get("dataset")) == target and (_BASE / "models" / f).exists()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda fm: fm[1].get("last_used", ""))[0]


def _select_idx(X, y, n, full: bool, order: str):
    """
    Choose which row indices to replay and in what order.

    full=False : a balanced demo sample of ~n rows (about 70% attacks).
    full=True  : the entire dataset.
    order="random"     : shuffled.
    order="sequential" : kept in the dataset's stored order.
    """
    import numpy as np
    rng = np.random.default_rng()
    if full:
        idx = np.arange(len(X))
    elif y is not None and int((y == 1).sum()) > 0:
        atk = np.where(y == 1)[0]
        ben = np.where(y == 0)[0]
        n_attack = min(int(n * 0.7), len(atk))
        n_benign = min(n - n_attack, len(ben))
        n_attack = min(n - n_benign, len(atk))
        idx = np.concatenate([
            rng.choice(atk, n_attack, replace=False) if n_attack else np.array([], dtype=int),
            rng.choice(ben, n_benign, replace=False) if n_benign else np.array([], dtype=int),
        ]).astype(int)
    else:
        idx = rng.choice(len(X), min(n, len(X)), replace=False)

    if order == "sequential":
        idx = np.sort(idx)
    else:
        rng.shuffle(idx)
    return idx


def _type_labels(idx, y, y_types, attack_types):
    """True class name per selected row: the attack type (e.g. 'PortScan') or 'Benign'."""
    out = []
    for i in idx:
        i = int(i)
        name = None
        if y_types is not None and attack_types is not None:
            t = int(y_types[i])
            if 0 <= t < len(attack_types):
                name = str(attack_types[t])
        if not name:
            name = "Attack" if (y is not None and int(y[i]) == 1) else "Benign"
        out.append(name)
    return out


def _load_cross_sample(data_ds: str, n: int, full: bool, order: str):
    """
    Build a feature matrix for cross-dataset replay: read raw traffic of
    `data_ds` and transform it with the CURRENTLY LOADED model's preprocessor,
    so the rows land in that model's feature space (not data_ds's own).
    """
    import glob
    import pandas as pd

    if model_service.preprocessor is None:
        raise HTTPException(status_code=400,
            detail="Loaded model has no preprocessor; cannot run cross-dataset replay.")

    sub = "CIC-IDS-2018" if data_ds == "2018" else "CIC-IDS-2017"
    raw_dir = _BASE / "data" / "raw" / sub
    files = sorted(glob.glob(str(raw_dir / "*.csv")))
    if not files:
        raise HTTPException(status_code=404,
            detail=f"No raw CIC-IDS{data_ds} CSVs found in {raw_dir} for cross-dataset replay.")

    # Cap how much raw data we pull in: a small sample for the demo, a large but
    # bounded amount for a "whole dataset" run (to stay within memory).
    cap = 200000 if full else 15000
    frames, total = [], 0
    for f in files:
        try:
            frames.append(pd.read_csv(f, low_memory=False) if full
                          else pd.read_csv(f, nrows=6000, low_memory=False))
            total += len(frames[-1])
        except Exception as e:
            logger.warning("Skipping unreadable raw file %s: %s", f, e)
        if total >= cap:
            break
    if not frames:
        raise HTTPException(status_code=500, detail="Could not read raw CSV data for cross-dataset replay.")

    df = pd.concat(frames, ignore_index=True)
    if len(df) > cap:
        df = df.iloc[:cap]
    res = model_service.preprocessor.transform(df, include_labels=True)
    if isinstance(res, tuple):
        X, y = res[0], res[1]
        y_types = res[2] if len(res) > 2 else None
    else:
        X, y, y_types = res, None, None
    attack_types = getattr(model_service.preprocessor, "attack_types", None)
    idx = _select_idx(X, y, n, full, order)
    return X[idx], _type_labels(idx, y, y_types, attack_types)


@router.post("/api/monitor/replay")
def replay_dataset(n: int = 40, rate: float = 0.6,
                   dataset: Optional[str] = None, model: Optional[str] = None,
                   full: bool = False, order: str = "random"):
    """
    Demonstration mode: stream real CIC-IDS rows through the live pipeline so the
    dashboard shows real detections + SHAP/LIME.

    `dataset` ("2017"/"2018") picks which dataset's TRAFFIC to replay.
    `model`   ("2017"/"2018") picks which MODEL classifies it; defaults to the
    same dataset. When they differ this is a CROSS-DATASET test.
    `full`    streams the whole dataset instead of a small balanced sample.
    `order`   "random" shuffles the flows; "sequential" keeps dataset order.
    """
    from api.services.training_service import training_service
    if training_service.is_running:
        raise HTTPException(status_code=409, detail="Wait for training to finish before replay.")
    if monitor_service.is_running:
        raise HTTPException(status_code=400, detail="Monitor already running.")

    data_ds = dataset or model_service.dataset or "2017"
    model_ds = model or data_ds
    for d in (data_ds, model_ds):
        if d not in ("2017", "2018"):
            raise HTTPException(status_code=400, detail="dataset and model must be '2017' or '2018'.")
    if order not in ("random", "sequential"):
        raise HTTPException(status_code=400, detail="order must be 'random' or 'sequential'.")
    rate = max(0.0, float(rate))

    # Ensure the requested MODEL is loaded.
    if not model_service.is_loaded or (model_service.dataset or "2017") != model_ds:
        filename = _pick_model_for_dataset(model_ds)
        if not filename:
            raise HTTPException(status_code=404, detail=f"No model found for CIC-IDS{model_ds}.")
        try:
            model_service.load(filename)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load CIC-IDS{model_ds} model: {e}")

    cross = (model_ds != data_ds)
    if cross:
        X_subset, labels = _load_cross_sample(data_ds, n, full, order)
    else:
        import numpy as np
        npz_path = _BASE / "data" / "processed" / f"processed_data_{data_ds}.npz"
        if not npz_path.exists():
            raise HTTPException(status_code=404, detail=f"No processed data found for CIC-IDS{data_ds}.")
        data = np.load(npz_path, allow_pickle=True)
        idx = _select_idx(data["X"], data["y"], n, full, order)
        X_subset = data["X"][idx]
        y_types = data["y_types"] if "y_types" in data else None
        attack_types = list(data["attack_types"]) if "attack_types" in data else None
        labels = _type_labels(idx, data["y"], y_types, attack_types)

    explainer = None
    try:
        explainer = explainer_service.get_explainer(model_service)
    except Exception as e:
        logger.warning("Explainer unavailable for replay: %s", e)

    monitor_service.start_dataset_replay(
        model=model_service.model,
        explainer=explainer,
        X=X_subset,
        labels=labels,
        rate=rate,
    )
    return {"started": True, "mode": "replay", "dataset": data_ds, "model": model_ds,
            "cross_dataset": cross, "full": full, "order": order, "samples": int(len(X_subset))}


def _ensure_model(target: Optional[str]):
    target = target or model_service.dataset or "2017"
    if target not in ("2017", "2018"):
        raise HTTPException(status_code=400, detail="model must be '2017' or '2018'.")
    if not model_service.is_loaded or (model_service.dataset or "2017") != target:
        filename = _pick_model_for_dataset(target)
        if not filename:
            raise HTTPException(status_code=404, detail=f"No model found for CIC-IDS{target}.")
        model_service.load(filename)
    return target


@router.post("/api/monitor/remote/start")
def remote_start(model: Optional[str] = Query(None), rate: float = Query(0.6)):
    """Start a 'live' monitoring session that is fed by the VM over the host-only network.
    Shown on the dashboard exactly like live capture on a network interface."""
    from api.services.training_service import training_service
    if training_service.is_running:
        raise HTTPException(status_code=409, detail="Wait for training to finish before monitoring.")
    if monitor_service.is_running:
        raise HTTPException(status_code=400, detail="Monitor already running.")
    _ensure_model(model)
    explainer = None
    try:
        explainer = explainer_service.get_explainer(model_service)
    except Exception as e:
        logger.warning("Explainer unavailable for remote session: %s", e)
    monitor_service.start_remote(model_service.model, explainer,
                                 source_label="VMware Host-Only (Kali)", rate=rate)
    return {"started": True, "mode": "remote", "source": "VMware Host-Only (Kali)"}


@router.post("/api/monitor/ingest")
async def ingest_remote(file: UploadFile = File(...),
                        model: Optional[str] = Query(None), rate: float = Query(0.6)):
    """Receive a CIC-IDS CSV from the VM, transform it into the model's feature space,
    and stream the flows through the live pipeline (detection + SHAP + attack type)."""
    import io
    import pandas as pd
    from api.services.training_service import training_service
    if training_service.is_running:
        raise HTTPException(status_code=409, detail="Wait for training to finish before ingestion.")
    if monitor_service.is_running and monitor_service.mode != "remote":
        raise HTTPException(status_code=409, detail="Stop the current session before remote ingestion.")

    _ensure_model(model)
    if model_service.preprocessor is None:
        raise HTTPException(status_code=400, detail="Loaded model has no preprocessor.")
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty upload.")
    try:
        df = pd.read_csv(io.BytesIO(raw), low_memory=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {e}")

    res = model_service.preprocessor.transform(df, include_labels=True)
    if isinstance(res, tuple):
        X, yb = res[0], res[1]
        yt = res[2] if len(res) > 2 else None
    else:
        X, yb, yt = res, None, None
    attack_types = getattr(model_service.preprocessor, "attack_types", None)
    labels = _type_labels(range(len(X)), yb, yt, attack_types)

    # Auto-start the remote session if the dashboard 'Start' was not pressed first.
    if not monitor_service.is_running:
        explainer = None
        try:
            explainer = explainer_service.get_explainer(model_service)
        except Exception as e:
            logger.warning("Explainer unavailable for ingest: %s", e)
        monitor_service.start_remote(model_service.model, explainer,
                                     source_label="VMware Host-Only (Kali)", rate=rate)

    queued = monitor_service.feed_remote(X, labels)
    return {"queued": int(queued), "source": file.filename}


@router.post("/api/monitor/stop")
def stop_monitor():
    monitor_service.stop()
    return {"stopped": True}


@router.get("/api/monitor/interfaces")
def list_interfaces():
    """Return active network interfaces using psutil."""
    import psutil
    stats = psutil.net_if_stats()
    up = [name for name, s in stats.items() if s.isup]
    return {"interfaces": up if up else list(stats.keys())}
