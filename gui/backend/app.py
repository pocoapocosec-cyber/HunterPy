"""FastAPI application factory + uvicorn runner.

Run for local development:
    python -m gui.backend.app

Or with uvicorn directly:
    uvicorn gui.backend.app:app --reload --port 8000

Production-ish (single worker, behind a reverse proxy):
    uvicorn gui.backend.app:app --host 0.0.0.0 --port 8000 --workers 1
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gui.backend.routes import findings, misc, reports, scans


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("hunterpy.api")


# --------------------------------------------------------------------------
# App factory
# --------------------------------------------------------------------------
def create_app() -> FastAPI:
    app = FastAPI(
        title="HunterPy API",
        version="2.1.0",
        description=(
            "REST surface for the HunterPy security scanner. "
            "Pair with the React frontend in gui/frontend/ "
            "(set VITE_USE_MOCKS=false and point VITE_API_BASE_URL here)."
        ),
        # Hide /redoc to reduce surface; keep /docs for ops.
        redoc_url=None,
    )

    # CORS — dev only. In production put a reverse proxy in front and
    # remove the wildcard.
    origins = os.environ.get(
        "HUNTERPY_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in origins if o.strip()],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(misc.tools_router)
    app.include_router(misc.settings_router)
    app.include_router(misc.auth_router)
    app.include_router(misc.ua_router)

    @app.get("/", include_in_schema=False)
    def root() -> Dict[str, Any]:
        return {
            "name": "HunterPy API",
            "version": "2.1.0",
            "docs": "/docs",
            "endpoints": [
                "/api/scans", "/api/findings", "/api/reports",
                "/api/tools", "/api/settings", "/api/auth",
            ],
        }

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> Dict[str, str]:
        return {"status": "ok"}

    log.info("HunterPy API ready (CORS origins: %s)", origins)
    return app


# --------------------------------------------------------------------------
# Module-level app for `uvicorn gui.backend.app:app`
# --------------------------------------------------------------------------
app = create_app()


def main() -> None:
    import uvicorn
    uvicorn.run(
        "gui.backend.app:app",
        host=os.environ.get("HUNTERPY_HOST", "127.0.0.1"),
        port=int(os.environ.get("HUNTERPY_PORT", "8000")),
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
