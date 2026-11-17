from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.services.training_service import training_service, _write_model_metadata
from api.services.model_service import model_service

router = APIRouter()
_MODELS_DIR = Path(__file__).parent.parent.parent / "models"


class TrainRequest(BaseModel):
    dataset: str = "2017"
    mode: str = "standard"
    source: str = "dataset"


class LabelRequest(BaseModel):
    filename: str
    display_name: str


@router.post("/api/train")
def start_training(req: TrainRequest):
    from api.services.monitor_service import monitor_service
    if monitor_service.is_running:
        raise HTTPException(status_code=409, detail="Stop monitoring before training a model.")
    if training_service.is_running:
        raise HTTPException(status_code=400, detail="Training already in progress.")
    if req.dataset not in ("2017", "2018"):
        raise HTTPException(status_code=400, detail="dataset must be '2017' or '2018'.")
    if req.mode not in ("quick", "standard", "optimized", "auto"):
        raise HTTPException(status_code=400, detail="mode must be quick, standard, optimized, or auto.")
    if req.source not in ("dataset", "sample"):
        raise HTTPException(status_code=400, detail="source must be dataset or sample.")
    training_service.start(req.dataset, req.mode, model_service, req.source)
    return {"started": True, "dataset": req.dataset, "mode": req.mode}


@router.post("/api/train/stop")
def stop_training():
    """Cooperatively cancel an in-progress training run."""
    stopped = training_service.stop()
    if not stopped:
        raise HTTPException(status_code=400, detail="No training is running.")
    return {"stopping": True}


@router.get("/api/train/status")
def training_status():
    return {"running": training_service.is_running}


@router.post("/api/models/label")
def label_model(req: LabelRequest):
    """Give a saved model a friendly display name (shown in the model list).

    Sets display_name in model_metadata.json. The model file is NOT renamed, so
    dataset resolution (which reads the filename) keeps working.
    """
    name = req.display_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="display_name cannot be empty.")
    if not req.filename.endswith(".joblib") or "/" in req.filename or "\\" in req.filename:
        raise HTTPException(status_code=400, detail="Invalid model filename.")
    if not (_MODELS_DIR / req.filename).exists():
        raise HTTPException(status_code=404, detail=f"Model file not found: {req.filename}")

    _write_model_metadata(req.filename, {"display_name": name})
    return {"ok": True, "filename": req.filename, "display_name": name}
