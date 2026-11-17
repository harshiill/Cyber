import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.routers import (
    status, model, monitor, alerts, explain, train, evaluate, classify,
    prevention, feedback,
)
from api.ws import alerts_ws, stats_ws, training_ws
from api.services.model_service import model_service
from api.services.monitor_service import monitor_service
from api.services.training_service import training_service
from api.services.alert_store import alert_store
from api.ws.manager import alerts_manager, stats_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_REACT_BUILD = Path(__file__).parent.parent.parent / "web" / "dist"


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path, scope):
        if path in {"alerts", "explain", "train", "evaluate", "classify", "settings"}:
            path = "index.html"
        return await super().get_response(path, scope)


@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_event_loop()
    monitor_service.configure(
        alert_store=alert_store,
        alerts_manager=alerts_manager,
        stats_manager=stats_manager,
        loop=loop,
    )
    training_service.configure(loop=loop)
    model_service.load_latest()
    logger.info("NIDS-XAI API started.")
    yield
    monitor_service.stop()


def create_app() -> FastAPI:
    app = FastAPI(title="NIDS-XAI API", lifespan=lifespan)

    # Local development: accept any origin. For production, replace with an
    # explicit allow_origins list and configure allow_credentials accordingly.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r".*",
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(status.router)
    app.include_router(model.router)
    app.include_router(monitor.router)
    app.include_router(alerts.router)
    app.include_router(explain.router)
    app.include_router(train.router)
    app.include_router(evaluate.router)
    app.include_router(classify.router)
    app.include_router(prevention.router)
    app.include_router(feedback.router)
    app.include_router(alerts_ws.router)
    app.include_router(stats_ws.router)
    app.include_router(training_ws.router)

    if _REACT_BUILD.exists():
        app.mount("/", SPAStaticFiles(directory=str(_REACT_BUILD), html=True), name="static")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
