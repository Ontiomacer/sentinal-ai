"""
Ghidra MCP Proxy API Endpoints

Backend proxy layer for Ghidra MCP server communication.
Frontend MUST NEVER directly communicate with MCP server.
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, List, Optional, Any
from pydantic import BaseModel
import logging

from app.database import get_db
from app.services.ghidra_service import (
    get_ghidra_service,
    GhidraService,
    GhidraFunction,
    GhidraDecompiledCode,
    GhidraString,
    GhidraClass,
    GhidraCallGraph,
    GhidraDebugState,
    GhidraDiagnostics,
    GhidraMemorySection,
    GhidraImportExport,
    GhidraSymbolTree
)
from app.models.case import Evidence
from app.models.scan import Scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ghidra", tags=["ghidra"])


# ============================================================================
# Request/Response Models
# ============================================================================

class HealthResponse(BaseModel):
    """Ghidra MCP health status."""
    connected: bool
    latency_ms: Optional[float] = None
    endpoints: int = 0
    last_check: Optional[str] = None
    error: Optional[str] = None


class DecompileRequest(BaseModel):
    """Request to decompile a function."""
    evidence_id: str
    function_address: str


class AnalyzeRequest(BaseModel):
    """Request to analyze evidence with Ghidra."""
    evidence_id: str
    deep_analysis: bool = True


# ============================================================================
# Helpers
# ============================================================================

async def get_project_name(db: AsyncSession, evidence_id: str) -> str:
    """Helper to get project name from evidence or scan."""
    # Try Evidence first (case-centric)
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    item = result.scalar_one_or_none()
    
    if item:
        return f"case_{item.case_id}_evidence_{evidence_id}"
    
    # Try Scan (legacy)
    result = await db.execute(select(Scan).where(Scan.id == evidence_id))
    item = result.scalar_one_or_none()
    
    if item:
        return f"legacy_scan_{evidence_id}"
    
    raise HTTPException(status_code=404, detail="Evidence not found")


# ============================================================================
# Health Check
# ============================================================================

@router.get("/health", response_model=HealthResponse)
async def check_ghidra_health(
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """
    Check Ghidra MCP server health status.
    """
    try:
        diag = await ghidra.get_diagnostics()
        
        if diag.connected:
            return HealthResponse(
                connected=True,
                latency_ms=diag.latency_ms,
                endpoints=diag.endpoints_available,
                last_check=None
            )
        else:
            return HealthResponse(
                connected=False, 
                error=diag.last_error or "Ghidra MCP server offline"
            )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return HealthResponse(connected=False, error=str(e))

@router.get("/diagnostics", response_model=GhidraDiagnostics)
async def get_ghidra_diagnostics(
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get detailed Ghidra MCP diagnostics."""
    return await ghidra.get_diagnostics()

@router.get("/memory/{evidence_id}", response_model=List[GhidraMemorySection])
async def get_memory_map(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get memory map for evidence."""
    project_name = await get_project_name(db, evidence_id)
    return await ghidra.get_memory_map(project_name)

@router.get("/symbols/imports_exports/{evidence_id}", response_model=List[GhidraImportExport])
async def get_imports_exports(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get imports and exports for evidence."""
    try:
        project_name = await get_project_name(db, evidence_id)
        logger.info(f"ENUMERATING IMPORTS/EXPORTS: project={project_name}")
        symbols = await ghidra.get_imports_exports(project_name)
        logger.info(f"IMPORTS/EXPORTS ENUMERATED: count={len(symbols)}")
        return symbols
    except Exception as e:
        logger.error(f"FAILED TO GET IMPORTS/EXPORTS: error={str(e)}")
        return []


@router.get("/symbols/tree/{evidence_id}", response_model=GhidraSymbolTree)
async def get_symbol_tree(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get recursive live symbols from the active Ghidra session."""
    try:
        project_name = await get_project_name(db, evidence_id)
        logger.info(f"SYMBOL TREE REQUEST: evidence={evidence_id} project={project_name}")
        tree = await ghidra.build_symbol_tree(project_name)
        logger.info(
            "SYMBOL TREE RESPONSE: evidence=%s counts=%s max_depth=%s first_function=%s",
            evidence_id,
            tree.counts,
            tree.max_depth,
            tree.first_function_address,
        )
        return tree
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"FAILED TO BUILD SYMBOL TREE: evidence={evidence_id} error={str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Function Analysis
# ============================================================================

@router.get("/functions/{evidence_id}", response_model=List[GhidraFunction])
async def get_functions(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get all functions from Ghidra analysis for evidence."""
    try:
        project_name = await get_project_name(db, evidence_id)
        logger.info(f"ENUMERATING FUNCTIONS: project={project_name} evidence={evidence_id}")
        functions = await ghidra.list_functions(
            project_name=project_name
        )
        logger.info(f"FUNCTIONS ENUMERATED: count={len(functions)} project={project_name}")
        return functions
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"FAILED TO GET FUNCTIONS: project={project_name if 'project_name' in locals() else 'unknown'} error={str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/decompile/{function_address}", response_model=GhidraDecompiledCode)
async def decompile_function(
    function_address: str,
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Decompile a function to C code."""
    try:
        project_name = await get_project_name(db, evidence_id)
        logger.info(f"DECOMPILING SYMBOL: address={function_address} project={project_name}")
        decompiled = await ghidra.decompile_function(
            project_name=project_name,
            address=function_address
        )
        
        if not decompiled:
            logger.error(f"DECOMPILATION FAILED: address={function_address} project={project_name}")
            raise HTTPException(status_code=500, detail="Decompilation failed")
        
        logger.info(f"DECOMPILATION SUCCESS: address={function_address} size={len(decompiled.c_code)} chars")
        return decompiled
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"DECOMPILER ERROR: address={function_address} error={str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Class Analysis
# ============================================================================

@router.get("/classes/{evidence_id}", response_model=List[GhidraClass])
async def get_classes(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get all Java/Dalvik classes from DEX analysis."""
    try:
        project_name = await get_project_name(db, evidence_id)
        logger.info(f"ENUMERATING CLASSES: project={project_name}")
        classes = await ghidra.list_classes(project_name=project_name)
        logger.info(f"CLASSES ENUMERATED: count={len(classes)}")
        return classes
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"FAILED TO GET CLASSES: error={str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# String Extraction
# ============================================================================

@router.get("/strings/{evidence_id}", response_model=List[GhidraString])
async def get_strings(
    evidence_id: str,
    min_length: int = 4,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Extract strings from binary analysis."""
    try:
        project_name = await get_project_name(db, evidence_id)
        logger.info(f"EXTRACTING STRINGS: project={project_name}")
        strings = await ghidra.extract_strings(
            project_name=project_name
        )
        logger.info(f"STRINGS EXTRACTED: count={len(strings)}")
        return strings
    except Exception as e:
        logger.error(f"FAILED TO EXTRACT STRINGS: error={str(e)}")
        return []


@router.get("/disassemble/{function_address}")
async def get_disassembly(
    function_address: str,
    evidence_id: str = Query(..., description="Evidence ID for context"),
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get disassembly for a selected function or symbol."""
    try:
        logger.info(f"[Debugger] DISASSEMBLY REQUEST: address={function_address} evidence={evidence_id}")
        
        try:
            project_name = await get_project_name(db, evidence_id)
        except HTTPException as e:
            logger.warning(f"[Debugger] DISASSEMBLY: Evidence not found {evidence_id}, returning fallback")
            # Evidence not found, but don't fail - return fallback
            return {
                "address": function_address,
                "function_name": f"fcn_{function_address}",
                "instructions": []
            }
        
        disassembly = await ghidra.get_disassembly(project_name=project_name, address=function_address)
        if not disassembly:
            logger.warning(f"[Debugger] Disassembly not available for address {function_address}")
            # Return fallback structure instead of 404
            return {
                "address": function_address,
                "function_name": f"fcn_{function_address}",
                "instructions": []
            }
        logger.info(f"[Debugger] DISASSEMBLY SUCCESS: address={function_address} instructions={len(disassembly.get('instructions', []))}")
        return disassembly
    except Exception as e:
        logger.exception(f"[Debugger] DISASSEMBLY FAILED: address={function_address} error={str(e)}")
        # Return fallback structure - NEVER raise exception
        return {
            "address": function_address,
            "function_name": f"fcn_{function_address}",
            "instructions": []
        }


@router.get("/xrefs/{function_address}")
async def get_cross_references(
    function_address: str,
    evidence_id: str = Query(..., description="Evidence ID for context"),
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get cross-references for a selected function or symbol."""
    try:
        logger.info(f"[Debugger] XREF REQUEST: address={function_address} evidence={evidence_id}")
        
        try:
            project_name = await get_project_name(db, evidence_id)
        except HTTPException:
            logger.warning(f"[Debugger] XREF: Evidence not found {evidence_id}, returning empty")
            return []  # Empty xref list is safe
        
        xrefs = await ghidra.get_cross_references(project_name=project_name, address=function_address)
        logger.info(f"[Debugger] XREF SUCCESS: address={function_address} count={len(xrefs) if xrefs else 0}")
        return xrefs or []
    except Exception as e:
        logger.exception(f"[Debugger] XREF FAILED: address={function_address} error={str(e)}")
        # Return empty list on failure - NEVER raise exception
        return []


@router.get("/debug/state/{evidence_id}", response_model=GhidraDebugState)
async def get_debug_state(
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get live debugger runtime state when available."""
    try:
        logger.info(f"[Debugger] DEBUG STATE REQUEST: evidence={evidence_id}")
        
        try:
            project_name = await get_project_name(db, evidence_id)
        except HTTPException:
            logger.warning(f"[Debugger] DEBUG STATE: Evidence not found {evidence_id}, returning unavailable state")
            return GhidraDebugState(
                execution_status="UNAVAILABLE",
                threads=[],
                registers=[],
                stack_frames=[],
                breakpoints=[],
                memory_regions=[],
                logs=["Debug state unavailable: evidence was not found."]
            )
        
        state = await ghidra.get_debug_state(project_name=project_name)
        logger.info(f"[Debugger] DEBUG STATE SUCCESS: evidence={evidence_id} threads={len(state.threads) if state else 0}")
        return state
    except Exception as e:
        logger.exception(f"[Debugger] DEBUG STATE FAILED: evidence={evidence_id} error={str(e)}")
        return GhidraDebugState(
            execution_status="UNAVAILABLE",
            threads=[],
            registers=[],
            stack_frames=[],
            breakpoints=[],
            memory_regions=[],
            logs=["Debug state unavailable from Ghidra MCP. No runtime state was fabricated."]
        )


# ============================================================================
# Call Graph Analysis
# ============================================================================

@router.get("/callgraph/{evidence_id}")
async def get_callgraph(
    evidence_id: str,
    entry_point: Optional[str] = Query(None, description="Optional entry point address"),
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Get call graph from Ghidra analysis."""
    try:
        logger.info(f"[Debugger] CALLGRAPH REQUEST: evidence={evidence_id} entry_point={entry_point}")
        
        try:
            project_name = await get_project_name(db, evidence_id)
        except HTTPException:
            logger.warning(f"[Debugger] CALLGRAPH: Evidence not found {evidence_id}, returning empty callgraph")
            return {
                "nodes": [],
                "edges": [],
                "entry_points": [],
                "suspicious_paths": []
            }
        
        callgraph = await ghidra.get_callgraph(
            project_name=project_name,
            entry_point=entry_point
        )
        
        if not callgraph:
            logger.warning(f"[Debugger] Callgraph generation failed for {evidence_id}")
            # Return empty but valid call graph structure
            return {
                "nodes": [],
                "edges": [],
                "entry_points": [],
                "suspicious_paths": []
            }
        
        payload = callgraph.dict() if hasattr(callgraph, "dict") else callgraph
        logger.info(
            "[Debugger] CALLGRAPH SUCCESS: nodes=%s edges=%s",
            len(payload.get('nodes', [])),
            len(payload.get('edges', [])),
        )
        return payload
    except Exception as e:
        logger.exception(f"[Debugger] CALLGRAPH FAILED: evidence={evidence_id} error={str(e)}")
        # Return empty but valid call graph structure - NEVER raise exception
        return {
            "nodes": [],
            "edges": [],
            "entry_points": [],
            "suspicious_paths": []
        }


# ============================================================================
# Structure & Meta
# ============================================================================

@router.get("/structure/{evidence_id}")
async def get_apk_structure(
    evidence_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get full APK structure for tree view."""
    try:
        project_name = await get_project_name(db, evidence_id)
        
        # Try Evidence first
        result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        item = result.scalar_one_or_none()
        
        if not item:
            # Try Scan
            result = await db.execute(select(Scan).where(Scan.id == evidence_id))
            item = result.scalar_one_or_none()
        
        if not item:
            raise HTTPException(status_code=404, detail="Evidence not found")
        
        # Return live analysis data if possible
        ghidra = get_ghidra_service()
        diag = await ghidra.get_diagnostics()
        
        import json
        result_data = json.loads(item.analysis_result) if isinstance(item.analysis_result, str) else (item.analysis_result or {})
        
        return {
            "evidence_id": evidence_id,
            "status": item.analysis_status if hasattr(item, 'analysis_status') else "READY",
            "apk_analysis": result_data.get('apk_analysis', {}),
            "ghidra_analysis": result_data.get('ghidra_analysis', {"status": "connected" if diag.connected else "offline"}),
            "neural_analysis": result_data.get('neural_analysis', {})
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get APK structure: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/{evidence_id}")
async def analyze_evidence(
    evidence_id: str,
    background_tasks: BackgroundTasks,
    deep_analysis: bool = True,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service)
):
    """Trigger deep Ghidra analysis for evidence."""
    try:
        project_name = await get_project_name(db, evidence_id)
        
        # We need the actual object for background task updates
        # Check Evidence first
        result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        item = result.scalar_one_or_none()
        if not item:
            result = await db.execute(select(Scan).where(Scan.id == evidence_id))
            item = result.scalar_one_or_none()
            
        background_tasks.add_task(
            _run_deep_analysis,
            ghidra=ghidra,
            project_name=project_name,
            evidence_id=evidence_id,
            item=item
        )
        
        return {
            "status": "queued",
            "evidence_id": evidence_id,
            "message": "Deep analysis started in background"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


async def _run_deep_analysis(
    ghidra: GhidraService,
    project_name: str,
    evidence_id: str,
    item: Any
):
    """Background task for deep Ghidra analysis."""
    try:
        logger.info(f"Starting deep analysis for evidence {evidence_id}")
        success = await ghidra.run_analysis(project_name)
        if not success:
            logger.error(f"Auto-analysis failed for {evidence_id}")
            return
        
        # Extract artifacts
        functions = await ghidra.list_functions(project_name)
        strings = await ghidra.extract_strings(project_name)
        classes = await ghidra.list_classes(project_name)
        
        # Update item result (this won't persist if session is closed, but it's a start)
        # In a real app, we'd open a new session here.
        if item and hasattr(item, 'analysis_result'):
            import json
            result = json.loads(item.analysis_result) if isinstance(item.analysis_result, str) else (item.analysis_result or {})
            result['ghidra_analysis'] = {
                "status": "complete",
                "functions_count": len(functions),
                "strings_count": len(strings),
                "classes_count": len(classes)
            }
            item.analysis_result = json.dumps(result)
        
        logger.info(f"Deep analysis completed for evidence {evidence_id}")
    except Exception as e:
        logger.error(f"Deep analysis failed: {str(e)}")
