from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routers import analytics, anomaly, auth, deep_scan, graph_intelligence, health, providers
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
  yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="CloudSecure API", version="2.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_origin_regex=settings.cors_origin_regex,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(providers.router)
    app.include_router(analytics.router)
    app.include_router(deep_scan.router)
    app.include_router(graph_intelligence.router)
    app.include_router(anomaly.router)
    return app


app = create_app()
