"""
Reconix Scan Engine - FastAPI application entrypoint.

This module wires together configuration, database initialization,
CORS, and logging. API routers (scans, findings, reports, audit, auth)
are added in a later module and included here via `include_router`
once implemented.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.logging_config import logger
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle handler."""
    logger.info("Starting %s (environment=%s)", settings.app_name, settings.environment)
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    """Application factory for Reconix Scan Engine."""
    app = FastAPI(
        title=settings.app_name,
        description=(
            "Reconix Scan Engine - an automated, defensive web application "
            "vulnerability scanner for authorized security testing and "
            "education. Never generates weaponized exploit code."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["system"])
    async def health_check() -> dict:
        """Simple liveness/readiness probe."""
        return {"status": "ok", "app": settings.app_name, "environment": settings.environment}

    # NOTE: API routers (scans, findings, reports, audit, auth) are
    # registered here once implemented. Example (added in a later module):
    #
    #   from app.api import auth, scans, findings, reports, audit
    #   app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    #   app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    #   app.include_router(findings.router, prefix="/api/findings", tags=["findings"])
    #   app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
    #   app.include_router(audit.router, prefix="/api/audit", tags=["audit"])

    return app


app = create_app()