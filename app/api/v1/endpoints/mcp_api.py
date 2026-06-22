"""
MCP marketplace and integration endpoints.

These endpoints expose the live Sentinel MCP surface without reintroducing the
old bridge process. Local tool calls are delegated to the active Ghidra service;
marketplace discovery reads from the official MCP Registry REST API.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.ghidra import get_project_name
from app.database import get_db
from app.services.ghidra_service import GhidraService, get_ghidra_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mcp", tags=["mcp"])

REGISTRY_BASE_URL = os.environ.get(
    "SENTINEL_MCP_REGISTRY_URL",
    "https://registry.modelcontextprotocol.io",
).rstrip("/")


class McpServerInfo(BaseModel):
    id: str
    name: str
    url: str
    transport: str
    status: str
    tools_count: int = 0
    latency_ms: Optional[float] = None
    last_heartbeat: Optional[str] = None
    capabilities: Dict[str, bool] = Field(default_factory=dict)
    description: Optional[str] = None
    source: str = "local"
    version: Optional[str] = None
    install: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class McpTool(BaseModel):
    name: str
    description: str
    input_schema: Dict[str, Any]
    category: str
    server_id: str


class McpInvocationRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class McpInvocationResult(BaseModel):
    tool: str
    success: bool
    result: Any = None
    duration_ms: float
    error: Optional[str] = None


LOCAL_GHIDRA_TOOLS: List[McpTool] = [
    McpTool(
        name="ghidra.diagnostics",
        description="Return live Ghidra MCP transport, program, and capability diagnostics.",
        input_schema={"type": "object", "properties": {}},
        category="diagnostics",
        server_id="ghidra-local",
    ),
    McpTool(
        name="ghidra.functions",
        description="Enumerate functions from a live Ghidra project or Sentinel evidence artifact.",
        input_schema={
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string"},
                "project_name": {"type": "string"},
            },
        },
        category="reverse-engineering",
        server_id="ghidra-local",
    ),
    McpTool(
        name="ghidra.classes",
        description="Enumerate classes from a live Ghidra project or Sentinel evidence artifact.",
        input_schema={
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string"},
                "project_name": {"type": "string"},
            },
        },
        category="reverse-engineering",
        server_id="ghidra-local",
    ),
    McpTool(
        name="ghidra.strings",
        description="Extract strings from the active analyzed program.",
        input_schema={
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string"},
                "project_name": {"type": "string"},
            },
        },
        category="forensics",
        server_id="ghidra-local",
    ),
    McpTool(
        name="ghidra.imports_exports",
        description="Enumerate import and export symbols from the live program.",
        input_schema={
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string"},
                "project_name": {"type": "string"},
            },
        },
        category="reverse-engineering",
        server_id="ghidra-local",
    ),
    McpTool(
        name="ghidra.symbol_tree",
        description="Build the recursive Ghidra explorer tree with namespaces, classes, methods, strings, imports, and exports.",
        input_schema={
            "type": "object",
            "properties": {
                "evidence_id": {"type": "string"},
                "project_name": {"type": "string"},
            },
        },
        category="reverse-engineering",
        server_id="ghidra-local",
    ),
    McpTool(
        name="ghidra.decompile",
        description="Decompile a selected function address through the active Ghidra session.",
        input_schema={
            "type": "object",
            "required": ["address"],
            "properties": {
                "evidence_id": {"type": "string"},
                "project_name": {"type": "string"},
                "address": {"type": "string"},
            },
        },
        category="decompiler",
        server_id="ghidra-local",
    ),
]


async def _resolve_project_name(
    arguments: Dict[str, Any],
    db: AsyncSession,
) -> str:
    if arguments.get("project_name"):
        return str(arguments["project_name"])
    evidence_id = arguments.get("evidence_id")
    if not evidence_id:
        raise HTTPException(
            status_code=400,
            detail="Tool requires either evidence_id or project_name.",
        )
    return await get_project_name(db, str(evidence_id))


def _server_url(server: Dict[str, Any]) -> str:
    remotes = server.get("remotes") or []
    if isinstance(remotes, list) and remotes:
        remote = remotes[0]
        if isinstance(remote, dict):
            return str(remote.get("url") or "")

    packages = server.get("packages") or []
    if isinstance(packages, list) and packages:
        package = packages[0]
        if isinstance(package, dict):
            registry = package.get("registry_name") or package.get("registry") or "package"
            name = package.get("name") or package.get("identifier") or server.get("name")
            return f"{registry}:{name}"

    repository = server.get("repository") or {}
    if isinstance(repository, dict) and repository.get("url"):
        return str(repository["url"])

    return f"{REGISTRY_BASE_URL}/v0.1/servers/{server.get('name', '')}"


def _transport(server: Dict[str, Any]) -> str:
    remotes = server.get("remotes") or []
    if isinstance(remotes, list) and remotes:
        remote = remotes[0]
        if isinstance(remote, dict) and remote.get("type"):
            return str(remote["type"])
    packages = server.get("packages") or []
    if isinstance(packages, list) and packages:
        return "stdio"
    return "registry"


def _registry_meta(item: Dict[str, Any]) -> Dict[str, Any]:
    meta = item.get("_meta") or {}
    if not isinstance(meta, dict):
        return {}
    official = meta.get("io.modelcontextprotocol.registry/official") or {}
    return official if isinstance(official, dict) else {}


async def _fetch_registry_servers(query: Optional[str], limit: int) -> List[McpServerInfo]:
    params: Dict[str, Any] = {"limit": max(1, min(limit, 100))}
    if query:
        params["search"] = query

    url = f"{REGISTRY_BASE_URL}/v0.1/servers"
    logger.info("MCP REGISTRY FETCH: url=%s params=%s", url, params)

    async with httpx.AsyncClient(timeout=12.0) as client:
        response = await client.get(url, params=params)
        response.raise_for_status()
        payload = response.json()

    servers: List[McpServerInfo] = []
    for item in payload.get("servers", []):
        server = item.get("server") or {}
        if not isinstance(server, dict):
            continue
        name = str(server.get("name") or "").strip()
        if not name:
            continue
        official = _registry_meta(item)
        install = {
            "packages": server.get("packages") or [],
            "remotes": server.get("remotes") or [],
            "repository": server.get("repository") or {},
        }
        servers.append(
            McpServerInfo(
                id=f"registry:{name}:{server.get('version') or 'latest'}",
                name=server.get("title") or name,
                url=_server_url(server),
                transport=_transport(server),
                status="disconnected",
                tools_count=0,
                latency_ms=None,
                last_heartbeat=official.get("updatedAt"),
                capabilities={},
                description=server.get("description"),
                source="official-registry",
                version=server.get("version"),
                install=install,
                metadata={
                    "registry_name": name,
                    "is_latest": official.get("isLatest"),
                    "status": official.get("status"),
                    "published_at": official.get("publishedAt"),
                },
            )
        )

    logger.info("MCP REGISTRY FETCH COMPLETE: count=%s query=%s", len(servers), query)
    return servers


@router.get("/registry", response_model=List[McpServerInfo])
async def list_mcp_registry(
    query: Optional[str] = Query(None, description="Optional registry search term."),
    limit: int = Query(25, ge=1, le=100),
    ghidra: GhidraService = Depends(get_ghidra_service),
) -> List[McpServerInfo]:
    """Return local connected MCP integrations plus live official registry entries."""
    diag = await ghidra.get_diagnostics()
    local = McpServerInfo(
        id="ghidra-local",
        name="Ghidra MCP Live Session",
        url=ghidra.base_url,
        transport="http-json-rpc",
        status="connected" if diag.connected else "disconnected",
        tools_count=len(LOCAL_GHIDRA_TOOLS),
        latency_ms=diag.latency_ms,
        last_heartbeat=datetime.utcnow().isoformat(),
        capabilities={
            "decompiler": diag.decompiler_available,
            "debugger": diag.debugger_available,
        },
        description="Sentinel's direct backend connection to the active GhidraMCP plugin on localhost:8089.",
        source="local",
        version=diag.version,
        install={
            "claude_desktop": {
                "name": "ghidra-local",
                "transport": "http",
                "url": ghidra.base_url,
            }
        },
        metadata={
            "active_project": diag.active_project,
            "loaded_program": diag.loaded_program,
            "endpoints_available": diag.endpoints_available,
        },
    )

    registry_servers: List[McpServerInfo] = []
    try:
        registry_servers = await _fetch_registry_servers(query, limit)
    except Exception as exc:
        logger.warning("MCP REGISTRY FETCH FAILED: %s", exc)
        local.metadata["registry_error"] = str(exc)

    return [local, *registry_servers]


@router.get("/tools", response_model=List[McpTool])
async def list_mcp_tools() -> List[McpTool]:
    """Return the live MCP tools Sentinel exposes through the backend."""
    logger.info("MCP TOOL LIST REQUEST: count=%s", len(LOCAL_GHIDRA_TOOLS))
    return LOCAL_GHIDRA_TOOLS


@router.post("/invoke", response_model=McpInvocationResult)
async def invoke_mcp_tool(
    request: McpInvocationRequest,
    db: AsyncSession = Depends(get_db),
    ghidra: GhidraService = Depends(get_ghidra_service),
) -> McpInvocationResult:
    """Invoke an explicitly exposed live MCP tool."""
    started = time.perf_counter()
    tool_name = request.tool_name.strip()
    arguments = request.arguments or {}
    logger.info("MCP TOOL INVOKE START: tool=%s args=%s", tool_name, arguments)

    try:
        if tool_name == "ghidra.diagnostics":
            result = (await ghidra.get_diagnostics()).dict()
        elif tool_name == "ghidra.functions":
            project_name = await _resolve_project_name(arguments, db)
            result = [item.dict() for item in await ghidra.list_functions(project_name)]
        elif tool_name == "ghidra.classes":
            project_name = await _resolve_project_name(arguments, db)
            result = [item.dict() for item in await ghidra.list_classes(project_name)]
        elif tool_name == "ghidra.strings":
            project_name = await _resolve_project_name(arguments, db)
            result = [item.dict() for item in await ghidra.extract_strings(project_name)]
        elif tool_name == "ghidra.imports_exports":
            project_name = await _resolve_project_name(arguments, db)
            result = [item.dict() for item in await ghidra.get_imports_exports(project_name)]
        elif tool_name == "ghidra.symbol_tree":
            project_name = await _resolve_project_name(arguments, db)
            result = (await ghidra.build_symbol_tree(project_name)).dict()
        elif tool_name == "ghidra.decompile":
            project_name = await _resolve_project_name(arguments, db)
            address = arguments.get("address") or arguments.get("function_address")
            if not address:
                raise HTTPException(status_code=400, detail="ghidra.decompile requires address.")
            decompiled = await ghidra.decompile_function(project_name, str(address))
            if not decompiled:
                raise HTTPException(status_code=502, detail="Ghidra returned no decompiler output.")
            result = decompiled.dict()
        else:
            raise HTTPException(
                status_code=400,
                detail=f"MCP tool is not exposed by Sentinel backend: {tool_name}",
            )

        duration_ms = (time.perf_counter() - started) * 1000
        logger.info("MCP TOOL INVOKE COMPLETE: tool=%s duration_ms=%.1f", tool_name, duration_ms)
        return McpInvocationResult(
            tool=tool_name,
            success=True,
            result=result,
            duration_ms=duration_ms,
        )
    except HTTPException:
        raise
    except Exception as exc:
        duration_ms = (time.perf_counter() - started) * 1000
        logger.exception("MCP TOOL INVOKE FAILED: tool=%s", tool_name)
        return McpInvocationResult(
            tool=tool_name,
            success=False,
            duration_ms=duration_ms,
            error=str(exc),
        )
