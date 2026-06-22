from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from services.auth import auth_headers
from services.config import SpecterConfig, load_config


class SpecterError(Exception):
    """Base Specter CLI exception."""


class SpecterConnectionError(SpecterError):
    """Raised when the Sentinel backend cannot be reached."""


class SpecterAPIError(SpecterError):
    def __init__(self, message: str, status_code: Optional[int] = None, payload: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class SpecterAPIClient:
    def __init__(self, config: Optional[SpecterConfig] = None):
        self.config = config or load_config()
        self.base_url = self.config.backend_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.client = httpx.Client(timeout=self.config.timeout_seconds, headers=auth_headers(self.config))

    def close(self) -> None:
        self.client.close()

    def _url(self, path: str, api: bool = True) -> str:
        root = self.api_url if api else self.base_url
        return f"{root}/{path.lstrip('/')}"

    def request(self, method: str, path: str, *, api: bool = True, **kwargs: Any) -> Any:
        last_error: Optional[Exception] = None
        for attempt in range(self.config.retries + 1):
            try:
                response = self.client.request(method, self._url(path, api=api), **kwargs)
                if response.status_code >= 400:
                    payload: Any
                    try:
                        payload = response.json()
                    except ValueError:
                        payload = response.text
                    detail = payload.get("detail") if isinstance(payload, dict) else payload
                    raise SpecterAPIError(str(detail or response.reason_phrase), response.status_code, payload)
                if response.status_code == 204:
                    return None
                return response.json()
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < self.config.retries:
                    time.sleep(0.35 * (attempt + 1))
                    continue
                raise SpecterConnectionError(
                    f"Sentinel backend offline at {self.base_url}. Start FastAPI and retry."
                ) from exc
        if last_error:
            raise SpecterConnectionError(str(last_error)) from last_error
        raise SpecterConnectionError("Unknown backend connection failure")

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs)

    def health(self) -> Dict[str, Any]:
        return self.get("/health", api=False)

    def list_cases(self, status: Optional[str] = None) -> Any:
        params = {"status": status} if status else None
        return self.get("/cases", params=params)

    def create_case(self, payload: Dict[str, Any]) -> Any:
        return self.post("/cases", json=payload)

    def get_case(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}")

    def delete_case(self, case_id: str) -> None:
        return self.delete(f"/cases/{case_id}")

    def list_evidence(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}/evidence")

    def get_evidence(self, case_id: str, evidence_id: str) -> Any:
        return self.get(f"/cases/{case_id}/evidence/{evidence_id}")

    def upload_evidence(self, case_id: str, file_path: Path, notes: Optional[str] = None) -> Any:
        with file_path.open("rb") as handle:
            files = {"file": (file_path.name, handle, "application/octet-stream")}
            data = {"notes": notes or ""}
            return self.post(f"/cases/{case_id}/evidence", files=files, data=data)

    def analyze_evidence(self, case_id: str, evidence_id: str, pipeline: str) -> Any:
        return self.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze", data={"pipeline": pipeline})

    def timeline(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}/timeline")

    def entities(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}/entities")

    def filesystem(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}/filesystem")

    def triage(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}/triage")

    def report_inventory(self, case_id: str) -> Any:
        return self.get(f"/cases/{case_id}/reports/inventory")

    def generate_report(self, case_id: str, report_type: str) -> Any:
        return self.post(f"/cases/{case_id}/reports/generate", json={"report_type": report_type})

    def upload_legacy_apk(self, file_path: Path) -> Any:
        with file_path.open("rb") as handle:
            files = {"file": (file_path.name, handle, "application/vnd.android.package-archive")}
            return self.post("/upload", files=files)

    def get_scan(self, scan_id: str) -> Any:
        return self.get(f"/scan/{scan_id}")

    def neural_scan(self, scan_id: str) -> Any:
        return self.post(f"/neural-lab/scans/{scan_id}/neural-analysis")

    def ghidra_health(self) -> Any:
        return self.get("/ghidra/health")

    def ghidra_diagnostics(self) -> Any:
        return self.get("/ghidra/diagnostics")

    def ghidra_functions(self, evidence_id: str) -> Any:
        return self.get(f"/ghidra/functions/{evidence_id}")

    def ghidra_classes(self, evidence_id: str) -> Any:
        return self.get(f"/ghidra/classes/{evidence_id}")

    def ghidra_strings(self, evidence_id: str) -> Any:
        return self.get(f"/ghidra/strings/{evidence_id}")

    def ghidra_imports_exports(self, evidence_id: str) -> Any:
        return self.get(f"/ghidra/symbols/imports_exports/{evidence_id}")

    def ghidra_symbol_tree(self, evidence_id: str) -> Any:
        return self.get(f"/ghidra/symbols/tree/{evidence_id}")

    def ghidra_decompile(self, evidence_id: str, address: str) -> Any:
        return self.get(f"/ghidra/decompile/{address}", params={"evidence_id": evidence_id})

    def mcp_registry(self, query: Optional[str] = None, limit: int = 25) -> Any:
        params: Dict[str, Any] = {"limit": limit}
        if query:
            params["query"] = query
        return self.get("/mcp/registry", params=params)

    def mcp_tools(self) -> Any:
        return self.get("/mcp/tools")

    def mcp_invoke(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        return self.post("/mcp/invoke", json={
            "tool_name": tool_name,
            "arguments": arguments or {},
        })

    def ai_health(self) -> Any:
        return self.get("/ai/health")

    def ai_suggestions(
        self,
        case_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        use_ai: bool = True,
    ) -> Any:
        return self.post("/ai/suggestions", json={
            "case_id": case_id,
            "evidence_id": evidence_id,
            "scan_id": scan_id,
            "context": context or {},
            "use_ai": use_ai,
        })


class AsyncSpecterAPIClient:
    """Future-ready async client for live automation and streaming workflows."""

    def __init__(self, config: Optional[SpecterConfig] = None):
        self.config = config or load_config()
        self.base_url = self.config.backend_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.client = httpx.AsyncClient(timeout=self.config.timeout_seconds, headers=auth_headers(self.config))

    async def close(self) -> None:
        await self.client.aclose()

    async def get(self, path: str) -> Any:
        try:
            response = await self.client.get(f"{self.api_url}/{path.lstrip('/')}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise SpecterConnectionError(str(exc)) from exc
