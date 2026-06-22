from fastapi import APIRouter
from app.api.v1.endpoints import (
    upload,
    neural_lab,
    cases,
    evidence,
    ghidra,
    debug,
    neural_api,
    mcp_api,
    ai_api,
    device_lab,
    app_analysis,
)

api_router = APIRouter()

# Include endpoint routers
api_router.include_router(cases.router, tags=["cases"])
api_router.include_router(evidence.router, tags=["evidence"])
api_router.include_router(upload.router, tags=["upload"])
api_router.include_router(neural_lab.router, prefix="/neural-lab", tags=["neural-lab"])
api_router.include_router(neural_api.router, prefix="/neural", tags=["neural"])
api_router.include_router(ai_api.router, tags=["ai"])
api_router.include_router(mcp_api.router, tags=["mcp"])
api_router.include_router(ghidra.router, tags=["ghidra"])
api_router.include_router(debug.router, tags=["debug"])
api_router.include_router(device_lab.router, prefix="/device-lab", tags=["device-lab"])
api_router.include_router(app_analysis.router, prefix="/app-analysis", tags=["app-analysis"])
