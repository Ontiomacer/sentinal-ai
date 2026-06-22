"""
Production-grade Ghidra MCP Integration Service

Integrates Sentinel AI directly with the Ghidra MCP Server (localhost:8089)
using a direct TCP/JSON-RPC client architecture.
"""

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import json
import re
import time

import httpx
from pydantic import BaseModel, Field
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

logger = logging.getLogger(__name__)

# ============================================================================
# Pydantic Schemas
# ============================================================================

class GhidraFunction(BaseModel):
    name: str
    address: str
    size: int
    signature: Optional[str] = None
    stable_id: Optional[str] = None
    namespace: Optional[str] = None
    class_name: Optional[str] = None
    symbol_type: str = "function"
    is_external: bool = False
    is_thunk: bool = False
    calling_convention: Optional[str] = None
    xrefs_from: List[str] = Field(default_factory=list)
    xrefs_to: List[str] = Field(default_factory=list)

class GhidraImportExport(BaseModel):
    name: str
    address: Optional[str] = None
    library: Optional[str] = None
    type: str
    stable_id: Optional[str] = None
    namespace: Optional[str] = None
    class_name: Optional[str] = None

class GhidraMemorySection(BaseModel):
    name: str
    start: str
    end: str
    size: int
    permissions: str
    type: str

class GhidraDiagnostics(BaseModel):
    connected: bool
    status: str
    transport_online: bool = False
    session_negotiated: bool = False
    tools_discovered: int = 0
    version: Optional[str] = None
    active_project: Optional[str] = None
    loaded_program: Optional[str] = None
    uptime_seconds: int = 0
    endpoints_available: int = 0
    analyzers_loaded: List[str] = []
    decompiler_available: bool = False
    debugger_available: bool = False
    last_error: Optional[str] = None
    latency_ms: float = 0.0
    raw_handshake_response: Optional[str] = None

class GhidraDecompiledCode(BaseModel):
    function_name: str
    address: str
    c_code: str
    signature: str
    variables: List[Dict[str, Any]] = Field(default_factory=list)
    calls_to: List[str] = Field(default_factory=list)
    called_by: List[str] = Field(default_factory=list)

class GhidraString(BaseModel):
    address: str
    value: str
    length: int
    encoding: str = "utf-8"
    stable_id: Optional[str] = None
    references: List[str] = Field(default_factory=list)

class GhidraClass(BaseModel):
    name: str
    package: str
    stable_id: Optional[str] = None
    methods: List[str] = Field(default_factory=list)
    fields: List[str] = Field(default_factory=list)
    super_class: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)

class GhidraCallGraph(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    entry_points: List[str]

class GhidraDebugState(BaseModel):
    execution_status: str = "PAUSED"
    active_thread: Optional[str] = None
    program_counter: Optional[str] = None
    loaded_module: Optional[str] = None
    threads: List[Dict[str, Any]] = Field(default_factory=list)
    registers: List[Dict[str, Any]] = Field(default_factory=list)
    stack_frames: List[Dict[str, Any]] = Field(default_factory=list)
    breakpoints: List[Dict[str, Any]] = Field(default_factory=list)
    memory_regions: List[Dict[str, Any]] = Field(default_factory=list)
    logs: List[str] = Field(default_factory=list)

class GhidraSymbolNode(BaseModel):
    id: str
    name: str
    type: str
    address: Optional[str] = None
    depth: int = 0
    symbol_type: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    children: List["GhidraSymbolNode"] = Field(default_factory=list)

class GhidraSymbolTree(BaseModel):
    roots: List[GhidraSymbolNode]
    counts: Dict[str, int] = Field(default_factory=dict)
    first_function_id: Optional[str] = None
    first_function_address: Optional[str] = None
    max_depth: int = 0
    generated_at: datetime = Field(default_factory=datetime.utcnow)

GhidraSymbolNode.update_forward_refs()

class GhidraAnalysisResult(BaseModel):
    project_name: str
    file_path: str
    analysis_time: datetime
    functions_count: int
    strings_count: int
    classes_count: int
    entry_points: List[str]
    imports: List[str]
    exports: List[str]
    metadata: Dict[str, Any] = {}

class MCPResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# ============================================================================
# Ghidra Service (Direct MCP Client)
# ============================================================================

class GhidraService:
    """
    Direct MCP Client for Ghidra.
    Communicates directly with the Ghidra MCP Server plugin.
    """
    
    def __init__(
        self,
        mcp_host: str = "localhost",
        mcp_port: int = 8089,
        timeout: float = 300.0
    ):
        self.base_url = f"http://{mcp_host}:{mcp_port}"
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
        )
        self._tools_cache: List[Dict[str, Any]] = []
        self._function_cache: Dict[str, GhidraFunction] = {}
        logger.info(f"Ghidra Direct MCP Client initialized: {self.base_url}")

    async def close(self):
        await self.client.aclose()

    def _stable_id(self, kind: str, *parts: Any) -> str:
        raw = "|".join(str(part or "") for part in parts)
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        slug = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw).strip("_")[:48] or kind
        return f"{kind}:{slug}:{digest}"

    def _split_qualified_name(self, name: str) -> Dict[str, Optional[str]]:
        cleaned = name.strip().strip(";")
        cleaned = cleaned[1:] if cleaned.startswith("L") and "/" in cleaned else cleaned
        cleaned = cleaned.replace("/", "::").replace(".", "::")
        parts = [part for part in cleaned.split("::") if part]

        if len(parts) >= 2:
            return {
                "namespace": "::".join(parts[:-2]) if len(parts) > 2 else None,
                "class_name": parts[-2] if len(parts) > 1 else None,
                "member_name": parts[-1],
            }

        return {
            "namespace": None,
            "class_name": None,
            "member_name": cleaned,
        }

    def _class_parts(self, raw_name: str) -> Dict[str, str]:
        cleaned = raw_name.strip().strip(";")
        cleaned = cleaned[1:] if cleaned.startswith("L") and "/" in cleaned else cleaned
        cleaned = cleaned.replace("/", "::").replace(".", "::")
        parts = [part for part in cleaned.split("::") if part]

        if len(parts) >= 2:
            return {
                "package": "::".join(parts[:-1]),
                "name": parts[-1],
            }

        return {
            "package": "unknown",
            "name": cleaned,
        }

    def _parse_function_records(self, text: str) -> List[Dict[str, Any]]:
        functions: List[Dict[str, Any]] = []
        seen_addresses: set[str] = set()

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.match(r"^(?P<name>.+?)\s+(?:at|->)\s+(?P<address>[A-Za-z0-9_:.-]+)$", line)
            if not match:
                logger.debug("FUNCTION PARSE SKIP: line=%s", line[:160])
                continue

            name = match.group("name").strip()
            address = match.group("address").strip()
            if address in seen_addresses:
                continue
            seen_addresses.add(address)

            parts = self._split_qualified_name(name)
            stable_id = self._stable_id("function", address, name)
            functions.append({
                "name": parts["member_name"] or name,
                "address": address,
                "size": 0,
                "stable_id": stable_id,
                "namespace": parts["namespace"],
                "class_name": parts["class_name"],
                "symbol_type": "function",
                "is_external": address.upper().startswith("EXTERNAL:"),
            })

        logger.info("FUNCTION PARSER COMPLETE: parsed=%s", len(functions))
        return functions

    def _parse_symbol_records(self, text: str, symbol_type: str) -> List[Dict[str, Any]]:
        symbols: List[Dict[str, Any]] = []
        seen: set[str] = set()

        try:
            decoded = json.loads(text)
            if isinstance(decoded, list):
                for item in decoded:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name") or "").strip()
                    address = str(item.get("address") or "").strip() or None
                    if not name:
                        continue
                    key = f"{symbol_type}:{name}:{address}"
                    if key in seen:
                        continue
                    seen.add(key)
                    parts = self._split_qualified_name(name)
                    symbols.append({
                        "name": name,
                        "address": address,
                        "library": item.get("library"),
                        "type": symbol_type,
                        "stable_id": self._stable_id(symbol_type, address, name),
                        "namespace": parts["namespace"],
                        "class_name": parts["class_name"],
                    })
                logger.info("SYMBOL JSON PARSER COMPLETE: type=%s parsed=%s", symbol_type, len(symbols))
                return symbols
        except json.JSONDecodeError:
            pass

        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^(?P<name>.+?)\s+(?:->|at)\s+(?P<address>[A-Za-z0-9_:.-]+)$", line)
            if match:
                name = match.group("name").strip()
                address = match.group("address").strip()
            else:
                name = line
                address = None

            key = f"{symbol_type}:{name}:{address}"
            if key in seen:
                continue
            seen.add(key)
            parts = self._split_qualified_name(name)
            symbols.append({
                "name": name,
                "address": address,
                "type": symbol_type,
                "stable_id": self._stable_id(symbol_type, address, name),
                "namespace": parts["namespace"],
                "class_name": parts["class_name"],
            })

        logger.info("SYMBOL TEXT PARSER COMPLETE: type=%s parsed=%s", symbol_type, len(symbols))
        return symbols

    def _parse_string_records(self, text: str) -> List[Dict[str, Any]]:
        if "No quality strings found" in text:
            logger.info("STRING PARSER COMPLETE: parsed=0 reason=no_quality_strings")
            return []

        strings: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            if ": " in line:
                address, value = line.split(": ", 1)
                address = address.strip()
            else:
                address = f"string_{len(strings)}"
                value = line

            value = value.strip().strip('"')
            key = f"{address}:{value}"
            if key in seen:
                continue
            seen.add(key)
            strings.append({
                "address": address,
                "value": value,
                "length": len(value),
                "stable_id": self._stable_id("string", address, value),
            })

        logger.info("STRING PARSER COMPLETE: parsed=%s", len(strings))
        return strings

    def _parse_class_records(self, text: str) -> List[Dict[str, Any]]:
        classes: List[Dict[str, Any]] = []
        seen: set[str] = set()

        for line in text.strip().splitlines():
            raw_name = line.strip()
            if not raw_name or raw_name.startswith("No "):
                continue
            parts = self._class_parts(raw_name)
            key = f"{parts['package']}::{parts['name']}"
            if key in seen:
                continue
            seen.add(key)
            classes.append({
                "name": parts["name"],
                "package": parts["package"],
                "stable_id": self._stable_id("class", key),
                "methods": [],
                "fields": [],
            })

        logger.info("CLASS PARSER COMPLETE: parsed=%s", len(classes))
        return classes

    def _find_or_create_child(
        self,
        parent: GhidraSymbolNode,
        name: str,
        node_type: str,
        depth: int,
        *id_parts: Any,
    ) -> GhidraSymbolNode:
        node_id = self._stable_id(node_type, *id_parts)
        for child in parent.children:
            if child.id == node_id:
                return child

        child = GhidraSymbolNode(
            id=node_id,
            name=name,
            type=node_type,
            depth=depth,
            symbol_type=node_type,
            data={"stable_id": node_id},
            children=[],
        )
        parent.children.append(child)
        logger.debug(
            "SYMBOL TREE NODE CREATE: parent=%s type=%s name=%s depth=%s",
            parent.name,
            node_type,
            name,
            depth,
        )
        return child

    def _qualified_parts(self, name: str) -> List[str]:
        cleaned = name.strip().strip(";")
        cleaned = cleaned[1:] if cleaned.startswith("L") and "/" in cleaned else cleaned
        cleaned = cleaned.replace("/", "::").replace(".", "::")
        return [part for part in cleaned.split("::") if part]

    def _insert_qualified_leaf(
        self,
        root: GhidraSymbolNode,
        qualified_name: str,
        leaf_type: str,
        address: Optional[str],
        data: Dict[str, Any],
        fallback_name: Optional[str] = None,
    ) -> GhidraSymbolNode:
        parts = self._qualified_parts(qualified_name)
        if not parts:
            parts = [fallback_name or qualified_name or address or leaf_type]

        parent = root
        path: List[str] = []
        for index, part in enumerate(parts[:-1]):
            path.append(part)
            container_type = "class" if index == len(parts[:-1]) - 1 and leaf_type in {"method", "function", "import", "export"} else "namespace"
            parent = self._find_or_create_child(
                parent,
                part,
                container_type,
                parent.depth + 1,
                root.id,
                "::".join(path),
            )

        leaf_name = fallback_name or parts[-1]
        leaf_id = data.get("stable_id") or self._stable_id(leaf_type, address, qualified_name)
        leaf = GhidraSymbolNode(
            id=leaf_id,
            name=leaf_name,
            type=leaf_type,
            address=address,
            depth=parent.depth + 1,
            symbol_type=leaf_type,
            data={**data, "stable_id": leaf_id},
            children=[],
        )
        parent.children.append(leaf)
        return leaf

    def _sort_symbol_nodes(self, nodes: List[GhidraSymbolNode]) -> None:
        nodes.sort(key=lambda n: (0 if n.children else 1, n.name.lower(), n.address or ""))
        for node in nodes:
            self._sort_symbol_nodes(node.children)

    def _set_depths_and_count(self, node: GhidraSymbolNode, depth: int = 0) -> Dict[str, int]:
        node.depth = depth
        max_depth = depth
        total = 1
        for child in node.children:
            stats = self._set_depths_and_count(child, depth + 1)
            total += stats["total"]
            max_depth = max(max_depth, stats["max_depth"])
        return {"total": total, "max_depth": max_depth}

    # ========================================================================
    # Core MCP Protocol Layer
    # ========================================================================

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> MCPResponse:
        """Invokes a tool on the Ghidra REST server with verbose logging."""
        request_id = int(time.time() * 1000)
        try:
            # Map tool names to REST endpoints
            endpoint_map = {
                "get_functions": "/list_functions",
                "get_methods": "/list_methods",
                "decompile": "/decompile_function",
                "get_strings": "/list_strings",
                "get_memory_map": "/list_segments",
                "get_classes": "/list_classes",
                "get_imports": "/list_imports",
                "get_exports": "/list_exports",
                "get_symbols": "/list_imports",
                "get_active_project": "/get_current_function",
                "get_disassembly": "/disassemble",
                "get_xrefs": "/xrefs",
                "get_callgraph": "/get_callgraph",
                "get_debug_state": "/debug_state"
            }
            
            endpoint = endpoint_map.get(tool_name, f"/{tool_name}")
            
            # Specialized mapping for symbols
            if tool_name == "get_symbols" and arguments:
                if arguments.get("type") == "exports":
                    endpoint = "/list_exports"
                else:
                    endpoint = "/list_imports"
            
            logger.info(f"REST SEND [{request_id}] endpoint={endpoint} args={arguments}")
            
            # The plugin expects address as a query parameter for some endpoints
            # and other params as query params for GET
            response = await self.client.get(endpoint, params=arguments or {})
            
            logger.info(f"REST RECV [{request_id}] status={response.status_code}")
            
            if response.status_code != 200:
                logger.error(f"REST HTTP ERROR [{request_id}]: {response.status_code} - {response.text}")
                return MCPResponse(success=False, error=f"HTTP {response.status_code}: {response.text}")
                
            text = response.text
            
            # For REST bridge, we return the raw text or parsed data
            # The individual methods will handle specific parsing if needed,
            # but we'll do some basic parsing here to keep them clean.
            
            if endpoint == "/list_functions":
                return MCPResponse(success=True, data=self._parse_function_records(text))
                
            elif endpoint == "/list_methods":
                methods = [
                    {"name": line.strip(), "address": None}
                    for line in text.strip().splitlines()
                    if line.strip()
                ]
                logger.info("METHOD PARSER COMPLETE: parsed=%s", len(methods))
                return MCPResponse(success=True, data=methods)
                
            elif endpoint == "/list_strings":
                return MCPResponse(success=True, data=self._parse_string_records(text))
                
            elif endpoint == "/list_segments":
                lines = text.strip().split("\n")
                sections = []
                for line in lines:
                    if ": " in line and " - " in line:
                        name, range_part = line.split(": ", 1)
                        start, end = range_part.split(" - ", 1)
                        sections.append({
                            "name": name.strip(),
                            "start": start.strip(),
                            "end": end.strip(),
                            "size": 0,
                            "permissions": "rwx",
                            "type": "segment"
                        })
                return MCPResponse(success=True, data=sections)
                
            elif endpoint == "/list_classes":
                return MCPResponse(success=True, data=self._parse_class_records(text))
                
            elif endpoint == "/list_imports":
                return MCPResponse(success=True, data=self._parse_symbol_records(text, "import"))
                
            elif endpoint == "/list_exports":
                return MCPResponse(success=True, data=self._parse_symbol_records(text, "export"))
                
            elif endpoint == "/decompile_function":
                return MCPResponse(success=True, data={"code": text, "name": "unknown", "signature": ""})
            
            return MCPResponse(success=True, data=text)
            
        except Exception as e:
            logger.error(f"REST TRANSPORT FAILURE [{request_id}] ({tool_name}): {str(e)}")
            return MCPResponse(success=False, error=str(e))

    async def connect(self) -> bool:
        """Verify Ghidra REST transport and perform handshake."""
        try:
            # Check a simple endpoint
            resp = await self.client.get("/list_functions")
            if resp.status_code == 200:
                logger.info("Ghidra REST Plugin Connected Successfully")
                return True
            else:
                logger.warning(f"Ghidra REST Plugin Handshake Failed (HTTP {resp.status_code}): {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Ghidra REST Connection Error: {str(e)}")
            return False

    async def discover_tools(self) -> List[Dict[str, Any]]:
        """Mock tool discovery for REST plugin."""
        # The REST plugin doesn't have tools/list, so we return a hardcoded list of supported endpoints
        tools = [
            {"name": "list_functions", "description": "List all functions"},
            {"name": "list_methods", "description": "List methods"},
            {"name": "decompile_function", "description": "Decompile function by address"},
            {"name": "list_strings", "description": "Extract strings"},
            {"name": "list_segments", "description": "Get memory map"},
            {"name": "list_classes", "description": "List classes"},
            {"name": "list_imports", "description": "List imports"},
            {"name": "list_exports", "description": "List exports"},
            {"name": "disassemble", "description": "Get instruction listing"},
            {"name": "xrefs", "description": "Get cross-references"},
            {"name": "get_callgraph", "description": "Generate call graph"},
            {"name": "debug_state", "description": "Query debugger runtime state"}
        ]
        self._tools_cache = tools
        return tools

    async def get_diagnostics(self) -> GhidraDiagnostics:
        """Get deep diagnostics via REST."""
        start_time = time.time()
        
        diag = GhidraDiagnostics(
            connected=False,
            status="INITIALIZING",
            latency_ms=0
        )
        
        try:
            # Check transport
            try:
                t_resp = await self.client.get("/list_functions")
                diag.latency_ms = (time.time() - start_time) * 1000
                if t_resp.status_code == 200:
                    diag.transport_online = True
                    diag.session_negotiated = True # REST is stateless, so transport OK = session OK
                    diag.connected = True
                    diag.status = "READY"
                    diag.raw_handshake_response = t_resp.text[:500]
                    
                    tools = await self.discover_tools()
                    diag.tools_discovered = len(tools)
                    diag.endpoints_available = len(tools)
                    
                    # Try to get active info
                    curr_resp = await self.client.get("/get_current_function")
                    if curr_resp.status_code == 200:
                        diag.loaded_program = "Active in Ghidra"
                        
                    diag.analyzers_loaded = ["REST Bridge"]
                    diag.decompiler_available = True
                    diag.debugger_available = False
                else:
                    diag.transport_online = True
                    diag.status = "UNEXPECTED_RESPONSE"
                    diag.last_error = f"HTTP {t_resp.status_code}"
            except Exception as e:
                diag.transport_online = False
                diag.status = "OFFLINE"
                diag.last_error = str(e)
                
            return diag
            
        except Exception as e:
            diag.connected = False
            diag.status = "FAILED"
            diag.last_error = str(e)
            diag.latency_ms = (time.time() - start_time) * 1000
            return diag

    # ========================================================================
    # Artifact Extraction Layer
    # ========================================================================

    async def import_program(self, file_path: Path, project_name: str) -> bool:
        """Import a binary into Ghidra via MCP."""
        resp = await self._call_tool("import_file", {
            "path": str(file_path),
            "project_name": project_name
        })
        return resp.success

    async def run_analysis(self, project_name: str) -> bool:
        """Trigger auto-analysis and wait for completion."""
        resp = await self._call_tool("analyze_all", {"project_name": project_name})
        if not resp.success: return False
        
        # Poll for completion
        for _ in range(30): # 5 min max
            status = await self._call_tool("get_analysis_status", {"project_name": project_name})
            if status.success and status.data.get("status") == "COMPLETED":
                return True
            await asyncio.sleep(10)
        return False

    async def list_functions(self, project_name: str) -> List[GhidraFunction]:
        """List functions via direct MCP tool."""
        logger.info("FUNCTION ENUMERATION START: project=%s", project_name)
        resp = await self._call_tool("get_functions", {"project_name": project_name})
        if not resp.success or not resp.data:
            logger.warning("FUNCTION ENUMERATION EMPTY: project=%s error=%s", project_name, resp.error)
            return []
        
        functions = [GhidraFunction(**f) for f in resp.data]
        self._function_cache = {f.address: f for f in functions if f.address}
        logger.info("FUNCTION ENUMERATION COMPLETE: project=%s count=%s", project_name, len(functions))
        return functions

    async def decompile_function(self, project_name: str, address: str) -> Optional[GhidraDecompiledCode]:
        """Decompile function via direct MCP tool."""
        logger.info("DECOMPILE MCP CALL START: project=%s address=%s", project_name, address)
        resp = await self._call_tool("decompile", {
            "project_name": project_name,
            "address": address
        })
        if not resp.success or not resp.data:
            logger.error("DECOMPILE MCP CALL FAILED: project=%s address=%s error=%s", project_name, address, resp.error)
            return None
        
        data = resp.data
        cached_function = self._function_cache.get(address)
        code = data.get("code", "")
        function_name = cached_function.name if cached_function else data.get("name", "unknown")
        if function_name == "unknown" and code:
            match = re.search(r"::([A-Za-z_$][A-Za-z0-9_$<>-]*)\s*\(", code)
            if match:
                function_name = match.group(1)
        logger.info(
            "DECOMPILE MCP CALL COMPLETE: project=%s address=%s chars=%s function=%s",
            project_name,
            address,
            len(code),
            function_name,
        )
        return GhidraDecompiledCode(
            function_name=function_name,
            address=address,
            c_code=code,
            signature=data.get("signature", "")
        )

    async def extract_strings(self, project_name: str) -> List[GhidraString]:
        """Extract strings via direct MCP tool."""
        logger.info("STRING ENUMERATION START: project=%s", project_name)
        resp = await self._call_tool("get_strings", {"project_name": project_name})
        if not resp.success:
            logger.warning("STRING ENUMERATION EMPTY: project=%s error=%s", project_name, resp.error)
            return []
        
        strings = [GhidraString(**s) for s in (resp.data or [])]
        logger.info("STRING ENUMERATION COMPLETE: project=%s count=%s", project_name, len(strings))
        return strings

    async def get_memory_map(self, project_name: str) -> List[GhidraMemorySection]:
        """Get memory map via direct MCP tool."""
        logger.info("MEMORY MAP ENUMERATION START: project=%s", project_name)
        resp = await self._call_tool("get_memory_map", {"project_name": project_name})
        if not resp.success or not resp.data:
            logger.warning("MEMORY MAP ENUMERATION EMPTY: project=%s error=%s", project_name, resp.error)
            return []
        
        sections = [GhidraMemorySection(**s) for s in resp.data]
        logger.info("MEMORY MAP ENUMERATION COMPLETE: project=%s count=%s", project_name, len(sections))
        return sections

    async def get_disassembly(self, project_name: str, address: str) -> Optional[Dict[str, Any]]:
        """Get disassembly for a function or address."""
        logger.info("DISASSEMBLY REQUEST: project=%s address=%s", project_name, address)
        resp = await self._call_tool("get_disassembly", {
            "project_name": project_name,
            "address": address
        })
        if not resp.success or resp.data is None:
            logger.warning("DISASSEMBLY FAILED: project=%s address=%s error=%s", project_name, address, resp.error)
            return None

        instructions: List[Dict[str, Any]] = []
        text = resp.data if isinstance(resp.data, str) else str(resp.data)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^(?P<address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+):?\s*(?P<bytes>(?:[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*))?\s*(?P<mnemonic>[A-Za-z_\.][A-Za-z0-9_\.]*)\s*(?P<opcode>.*)$", line)
            if match:
                instructions.append({
                    "address": match.group("address"),
                    "bytes": match.group("bytes") or "",
                    "mnemonic": match.group("mnemonic"),
                    "opcode": match.group("opcode") or "",
                    "comment": None
                })
            else:
                instructions.append({
                    "address": address,
                    "bytes": "",
                    "mnemonic": line,
                    "opcode": "",
                    "comment": None
                })

        logger.info("DISASSEMBLY PARSE COMPLETE: project=%s address=%s instructions=%s", project_name, address, len(instructions))
        return {
            "address": address,
            "function_name": address,
            "instructions": instructions
        }

    async def get_cross_references(self, project_name: str, address: str) -> List[Dict[str, Any]]:
        """Get cross-references for a function or symbol."""
        logger.info("CROSS-REFERENCE REQUEST: project=%s address=%s", project_name, address)
        resp = await self._call_tool("get_xrefs", {
            "project_name": project_name,
            "address": address
        })
        if not resp.success or resp.data is None:
            logger.warning("CROSS-REFERENCE FAILED: project=%s address=%s error=%s", project_name, address, resp.error)
            return []

        xrefs: List[Dict[str, Any]] = []
        data = resp.data
        if isinstance(data, str):
            for line in data.splitlines():
                if not line.strip():
                    continue
                parts = [part.strip() for part in re.split(r"\s*->\s*|\s+", line) if part.strip()]
                xrefs.append({
                    "from_address": parts[0] if len(parts) > 0 else address,
                    "from_name": parts[1] if len(parts) > 1 else "unknown",
                    "to_address": parts[2] if len(parts) > 2 else address,
                    "to_name": parts[3] if len(parts) > 3 else "unknown",
                    "type": "call"
                })
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    xrefs.append({
                        "from_address": item.get("from_address") or item.get("source") or address,
                        "from_name": item.get("from_name") or item.get("source_name") or "unknown",
                        "to_address": item.get("to_address") or item.get("target") or address,
                        "to_name": item.get("to_name") or item.get("target_name") or "unknown",
                        "type": item.get("type") or "call"
                    })
        logger.info("CROSS-REFERENCE PARSE COMPLETE: project=%s address=%s refs=%s", project_name, address, len(xrefs))
        return xrefs

    async def get_callgraph(self, project_name: str, entry_point: Optional[str] = None) -> Optional[GhidraCallGraph]:
        """Get call graph from Ghidra."""
        logger.info("CALLGRAPH REQUEST: project=%s entry_point=%s", project_name, entry_point)
        args: Dict[str, Any] = {"project_name": project_name}
        if entry_point:
            args["entry_point"] = entry_point
        resp = await self._call_tool("get_callgraph", args)
        if not resp.success or resp.data is None:
            logger.warning("CALLGRAPH FAILED: project=%s entry_point=%s error=%s", project_name, entry_point, resp.error)
            return None

        data = resp.data
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                logger.warning("CALLGRAPH PARSE JSON FAILED: %s", data)
                return None

        if isinstance(data, dict):
            return GhidraCallGraph(
                nodes=data.get("nodes", []),
                edges=data.get("edges", []),
                entry_points=data.get("entry_points", [])
            )

        return None

    async def get_debug_state(self, project_name: str) -> GhidraDebugState:
        """Get live debugger state or return an unavailable runtime state."""
        logger.info("DEBUG STATE REQUEST: project=%s", project_name)
        resp = await self._call_tool("get_debug_state", {"project_name": project_name})
        if resp.success and resp.data is not None:
            data = resp.data
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    logger.warning("DEBUG STATE JSON PARSE FAILED: %s", data)
                    data = None
            if isinstance(data, dict):
                return GhidraDebugState(**data)

        # Fallback: Live debug state is not available for static analysis
        logger.info("DEBUG STATE UNINTEGRATED/OFFLINE: project=%s", project_name)
        return GhidraDebugState(
            execution_status="UNAVAILABLE",
            active_thread=None,
            program_counter=None,
            loaded_module=None,
            threads=[],
            registers=[],
            stack_frames=[],
            breakpoints=[],
            memory_regions=[],
            logs=["Live debugger session is offline or unavailable for static analysis."]
        )


    async def list_classes(self, project_name: str) -> List[GhidraClass]:
        """List classes via direct MCP tool."""
        logger.info("CLASS ENUMERATION START: project=%s", project_name)
        resp = await self._call_tool("get_classes", {"project_name": project_name})
        if not resp.success or not resp.data:
            logger.warning("CLASS ENUMERATION EMPTY: project=%s error=%s", project_name, resp.error)
            return []
        
        classes = [GhidraClass(**c) for c in resp.data]
        logger.info("CLASS ENUMERATION COMPLETE: project=%s count=%s", project_name, len(classes))
        return classes

    async def get_imports_exports(self, project_name: str) -> List[GhidraImportExport]:
        """Get imports and exports via direct MCP tool."""
        logger.info("IMPORT/EXPORT ENUMERATION START: project=%s", project_name)
        imports_resp, exports_resp = await asyncio.gather(
            self._call_tool("get_imports", {"project_name": project_name}),
            self._call_tool("get_exports", {"project_name": project_name}),
        )

        symbols: List[GhidraImportExport] = []
        if imports_resp.success and imports_resp.data:
            symbols.extend(GhidraImportExport(**s) for s in imports_resp.data)
        elif imports_resp.error:
            logger.warning("IMPORT ENUMERATION FAILED: project=%s error=%s", project_name, imports_resp.error)
        
        if exports_resp.success and exports_resp.data:
            symbols.extend(GhidraImportExport(**s) for s in exports_resp.data)
        elif exports_resp.error:
            logger.warning("EXPORT ENUMERATION FAILED: project=%s error=%s", project_name, exports_resp.error)

        logger.info(
            "IMPORT/EXPORT ENUMERATION COMPLETE: project=%s imports=%s exports=%s total=%s",
            project_name,
            len([s for s in symbols if s.type == "import"]),
            len([s for s in symbols if s.type == "export"]),
            len(symbols),
        )
        return symbols

    async def build_symbol_tree(self, project_name: str) -> GhidraSymbolTree:
        """Build a recursive explorer tree from the active live Ghidra session."""
        start_time = time.time()
        logger.info("SYMBOL TREE BUILD START: project=%s", project_name)

        functions, classes, strings, symbols = await asyncio.gather(
            self.list_functions(project_name),
            self.list_classes(project_name),
            self.extract_strings(project_name),
            self.get_imports_exports(project_name),
        )

        imports = [symbol for symbol in symbols if symbol.type == "import"]
        exports = [symbol for symbol in symbols if symbol.type == "export"]

        imports_root = GhidraSymbolNode(
            id=self._stable_id("folder", project_name, "imports"),
            name="Imports",
            type="folder",
            symbol_type="imports",
            data={"category": "imports"},
            children=[],
        )
        exports_root = GhidraSymbolNode(
            id=self._stable_id("folder", project_name, "exports"),
            name="Exports",
            type="folder",
            symbol_type="exports",
            data={"category": "exports"},
            children=[],
        )
        classes_root = GhidraSymbolNode(
            id=self._stable_id("folder", project_name, "classes_methods"),
            name="Classes & Methods",
            type="folder",
            symbol_type="classes_methods",
            data={"category": "classes_methods"},
            children=[],
        )
        strings_root = GhidraSymbolNode(
            id=self._stable_id("folder", project_name, "strings"),
            name="Strings",
            type="folder",
            symbol_type="strings",
            data={"category": "strings"},
            children=[],
        )

        for symbol in imports:
            data = symbol.dict()
            data["decompilable"] = False
            self._insert_qualified_leaf(
                imports_root,
                symbol.name,
                "import",
                symbol.address,
                data,
            )

        for symbol in exports:
            data = symbol.dict()
            data["decompilable"] = bool(symbol.address and not symbol.address.upper().startswith("EXTERNAL:"))
            self._insert_qualified_leaf(
                exports_root,
                symbol.name,
                "export",
                symbol.address,
                data,
            )

        class_index_root = GhidraSymbolNode(
            id=self._stable_id("folder", project_name, "class_index"),
            name="Class Index",
            type="folder",
            symbol_type="class_index",
            data={"category": "class_index"},
            children=[],
        )
        classes_root.children.append(class_index_root)

        for ghidra_class in classes:
            qualified = (
                f"{ghidra_class.package}::{ghidra_class.name}"
                if ghidra_class.package and ghidra_class.package != "unknown"
                else ghidra_class.name
            )
            class_data = ghidra_class.dict()
            self._insert_qualified_leaf(
                class_index_root,
                qualified,
                "class",
                None,
                class_data,
                fallback_name=ghidra_class.name,
            )

        all_methods_root = GhidraSymbolNode(
            id=self._stable_id("folder", project_name, "all_methods"),
            name="All Methods",
            type="folder",
            symbol_type="methods",
            data={"category": "all_methods"},
            children=[],
        )
        classes_root.children.append(all_methods_root)

        first_function_id: Optional[str] = None
        first_function_address: Optional[str] = None

        for function in functions:
            data = function.dict()
            data["decompilable"] = not function.is_external
            leaf_type = "method" if function.class_name else "function"

            if function.namespace or function.class_name:
                qualified_parts = [
                    part for part in [function.namespace, function.class_name, function.name] if part
                ]
                leaf = self._insert_qualified_leaf(
                    all_methods_root,
                    "::".join(qualified_parts),
                    leaf_type,
                    function.address,
                    data,
                    fallback_name=function.name,
                )
            else:
                bucket_name = (function.name[:1] or "#").upper()
                if not bucket_name.isalnum():
                    bucket_name = "#"
                bucket = self._find_or_create_child(
                    all_methods_root,
                    bucket_name,
                    "namespace",
                    all_methods_root.depth + 1,
                    all_methods_root.id,
                    bucket_name,
                )
                leaf = GhidraSymbolNode(
                    id=function.stable_id or self._stable_id("function", function.address, function.name),
                    name=function.name,
                    type=leaf_type,
                    address=function.address,
                    symbol_type=leaf_type,
                    data=data,
                    children=[],
                )
                bucket.children.append(leaf)

            if not first_function_id and not function.is_external:
                first_function_id = leaf.id
                first_function_address = function.address

        for string in strings:
            display = string.value if len(string.value) <= 80 else f"{string.value[:77]}..."
            data = string.dict()
            bucket_name = (display[:1] or "#").upper()
            if not bucket_name.isalnum():
                bucket_name = "#"
            bucket = self._find_or_create_child(
                strings_root,
                bucket_name,
                "namespace",
                strings_root.depth + 1,
                strings_root.id,
                bucket_name,
            )
            bucket.children.append(GhidraSymbolNode(
                id=string.stable_id or self._stable_id("string", string.address, string.value),
                name=display,
                type="string",
                address=string.address,
                symbol_type="string",
                data=data,
                children=[],
            ))

        roots = [imports_root, exports_root, classes_root, strings_root]
        for root in roots:
            self._sort_symbol_nodes(root.children)

        total_nodes = 0
        max_depth = 0
        for root in roots:
            stats = self._set_depths_and_count(root)
            total_nodes += stats["total"]
            max_depth = max(max_depth, stats["max_depth"])

        counts = {
            "functions": len(functions),
            "methods": len(functions),
            "classes": len(classes),
            "imports": len(imports),
            "exports": len(exports),
            "strings": len(strings),
            "nodes": total_nodes,
        }

        logger.info(
            "SYMBOL TREE BUILD COMPLETE: project=%s counts=%s max_depth=%s elapsed_ms=%.1f first_function=%s",
            project_name,
            counts,
            max_depth,
            (time.time() - start_time) * 1000,
            first_function_address,
        )

        return GhidraSymbolTree(
            roots=roots,
            counts=counts,
            first_function_id=first_function_id,
            first_function_address=first_function_address,
            max_depth=max_depth,
        )

# ============================================================================
# Singleton Instance
# ============================================================================

_ghidra_service: Optional[GhidraService] = None

def get_ghidra_service() -> GhidraService:
    global _ghidra_service
    if _ghidra_service is None:
        _ghidra_service = GhidraService()
    return _ghidra_service
