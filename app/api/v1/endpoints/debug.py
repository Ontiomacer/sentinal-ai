"""
Sentinel AI Debugging & Pipeline Diagnostics API

Provides step-by-step validation for the APK -> Ghidra -> MCP -> Frontend chain.
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, List, Any, Optional
from pathlib import Path
import os
import zipfile
import logging

from app.database import get_db
from app.models.case import Evidence
from app.models.scan import Scan
from app.services.ghidra_service import get_ghidra_service, GhidraService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/debug", tags=["debug"])

# ============================================================================
# PHASE 1: APK EXTRACTION DIAGNOSTICS
# ============================================================================

@router.get("/apk/{evidence_id}")
async def debug_apk_extraction(
    evidence_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify APK integrity and extraction status.
    """
    # 1. Resolve Evidence
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    item = result.scalar_one_or_none()
    
    if not item:
        result = await db.execute(select(Scan).where(Scan.id == evidence_id))
        item = result.scalar_one_or_none()
        
    if not item:
        raise HTTPException(status_code=404, detail="Evidence artifact not found")
        
    apk_path = Path(item.file_path)
    if not apk_path.exists():
        return {
            "evidence_id": evidence_id,
            "status": "ERROR",
            "error": f"Physical file missing at {apk_path}",
            "path": str(apk_path)
        }
        
    # 2. Inspect APK Content
    artifacts = {
        "dex_files": [],
        "native_libs": [],
        "manifest_found": False,
        "resources_found": False,
        "file_size_mb": round(os.path.getsize(apk_path) / (1024 * 1024), 2)
    }
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            namelist = z.namelist()
            artifacts["dex_files"] = [f for f in namelist if f.endswith('.dex')]
            artifacts["native_libs"] = [f for f in namelist if f.startswith('lib/')]
            artifacts["manifest_found"] = "AndroidManifest.xml" in namelist
            artifacts["resources_found"] = "resources.arsc" in namelist
            
        return {
            "evidence_id": evidence_id,
            "status": "HEALTHY" if artifacts["dex_files"] else "DEGRADED",
            "path": str(apk_path),
            "artifacts": artifacts
        }
    except Exception as e:
        return {
            "evidence_id": evidence_id,
            "status": "CORRUPT",
            "error": str(e),
            "path": str(apk_path)
        }

# ============================================================================
# PHASE 2: GHIDRA PROJECT DIAGNOSTICS
# ============================================================================

@router.get("/ghidra/project/{evidence_id}")
async def debug_ghidra_project(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """
    Verify Ghidra project state and analysis metrics.
    """
    # Resolve project name
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    item = result.scalar_one_or_none()
    project_name = f"case_{item.case_id}_evidence_{evidence_id}" if item else f"legacy_scan_{evidence_id}"
    
    try:
        # Check if project exists and is loaded
        diag = await ghidra.get_diagnostics()
        if not diag.connected:
            return {"status": "OFFLINE", "error": "Ghidra MCP not connected"}
            
        # Enumerate actual artifacts
        functions = await ghidra.list_functions(project_name)
        classes = await ghidra.list_classes(project_name)
        strings = await ghidra.extract_strings(project_name)
        
        return {
            "project_name": project_name,
            "status": "ACTIVE" if functions else "EMPTY",
            "mcp_diagnostics": diag.dict(),
            "metrics": {
                "total_functions": len(functions),
                "total_classes": len(classes),
                "total_strings": len(strings)
            },
            "sample_functions": [f.name for f in functions[:5]]
        }
    except Exception as e:
        return {"status": "ERROR", "error": str(e), "project_name": project_name}

# ============================================================================
# PHASE 3: MCP ENDPOINT DISCOVERY
# ============================================================================

@router.get("/mcp")
async def debug_mcp_endpoints(
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """
    Discover and test actual MCP tools and endpoints with verbose logging.
    """
    diag = await ghidra.get_diagnostics()
    
    return {
        "transport_online": diag.transport_online,
        "session_negotiated": diag.session_negotiated,
        "status": diag.status,
        "tools_discovered": diag.tools_discovered,
        "endpoints_available": diag.endpoints_available,
        "handshake_payload": diag.raw_handshake_response,
        "active_project": diag.active_project,
        "loaded_program": diag.loaded_program,
        "latency_ms": diag.latency_ms,
        "last_error": diag.last_error,
        "analyzers": diag.analyzers_loaded,
        "capabilities": {
            "decompiler": diag.decompiler_available,
            "debugger": diag.debugger_available
        }
    }

# ============================================================================
# PHASE 4: FUNCTION ENUMERATION TEST
# ============================================================================

@router.get("/functions/{evidence_id}")
async def debug_functions(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """
    Enumerate actual symbols discovered by Ghidra.
    """
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    item = result.scalar_one_or_none()
    project_name = f"case_{item.case_id}_evidence_{evidence_id}" if item else f"legacy_scan_{evidence_id}"
    
    functions = await ghidra.list_functions(project_name)
    return {
        "count": len(functions),
        "functions": [f.dict() for f in functions[:50]]
    }

# ============================================================================
# PHASE 5: DECOMPILER VALIDATION
# ============================================================================

@router.get("/decompile/{evidence_id}/{address}")
async def debug_decompile(
    evidence_id: str,
    address: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """
    Test decompiler output for a specific address.
    """
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    item = result.scalar_one_or_none()
    project_name = f"case_{item.case_id}_evidence_{evidence_id}" if item else f"legacy_scan_{evidence_id}"
    
    decompiled = await ghidra.decompile_function(project_name, address)
    if not decompiled:
        return {"status": "FAILED", "error": "Decompiler returned no output"}
        
    return {
        "status": "SUCCESS",
        "signature": decompiled.signature,
        "code_length": len(decompiled.c_code),
        "raw_output": decompiled.c_code[:500] + "..." if len(decompiled.c_code) > 500 else decompiled.c_code
    }
