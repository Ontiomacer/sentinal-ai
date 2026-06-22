from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import traceback
import logging
import sys
import asyncio

from app.config import settings
from app.database import init_db
from app.api.v1.router import api_router

# Fix for Windows: Set ProactorEventLoop for subprocess support
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# Configure logging - Disable verbose Androguard logs
logging.basicConfig(level=logging.INFO)
logging.getLogger('androguard').setLevel(logging.WARNING)
logging.getLogger('androguard.core.dex').setLevel(logging.ERROR)
logging.getLogger('androguard.core.apk').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    await init_db()
    
    # Print all registered routes
    logger.info("=" * 60)
    logger.info("REGISTERED ROUTES:")
    logger.info("=" * 60)
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            methods = ', '.join(route.methods) if route.methods else 'N/A'
            logger.info(f"{methods:10} {route.path}")
    logger.info("=" * 60)
    
    yield
    # Shutdown (if needed)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="A lightweight backend for APK malware analysis",
    lifespan=lifespan
)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Log all unhandled exceptions with full traceback."""
    error_msg = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.error(f"Unhandled Exception in {request.url.path}: {error_msg}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "traceback": error_msg if settings.DEBUG else None}
    )

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
