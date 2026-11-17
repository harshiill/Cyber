from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from api.services.model_service import model_service

router = APIRouter()


class LoadRequest(BaseModel):
    filename: str


@router.get("/api/model")
def get_model():
    return model_service.status()


@router.get("/api/model/list")
def list_models():
    return model_service.list_models()


@router.post("/api/model/load")
def load_model(req: LoadRequest):
    from api.services.monitor_service import monitor_service
    if monitor_service.is_running:
        raise HTTPException(status_code=409, detail="Stop monitoring before switching models.")
    try:
        return model_service.load(req.filename)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/model/feature-importance")
def feature_importance():
    if not model_service.is_loaded:
        raise HTTPException(status_code=400, detail="No model loaded.")
    model = model_service.model
    names = model_service.feature_names
    if not hasattr(model, "feature_importances_") or len(names) == 0:
        raise HTTPException(status_code=503, detail="Feature importances not available.")
    fi = sorted(
        [{"feature": f, "importance": round(float(imp), 5)}
         for f, imp in zip(names, model.feature_importances_)],
        key=lambda x: x["importance"], reverse=True,
    )[:15]
    return {"feature_importances": fi}
