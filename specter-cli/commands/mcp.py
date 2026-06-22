from __future__ import annotations

import json
from typing import Optional

import typer

from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="MCP marketplace and integration controls.")


@app.command("registry")
def registry(
    query: Optional[str] = typer.Option(None, "--query", "-q", help="Search official MCP registry."),
    limit: int = typer.Option(25, "--limit", "-n", min=1, max=100),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List local and official MCP registry servers."""
    client = SpecterAPIClient()
    try:
        data = client.mcp_registry(query=query, limit=limit)
        if json_output:
            formatter.print_json(data)
            return

        for server in data:
            formatter.kv_panel(
                server.get("name", "MCP SERVER"),
                {
                    "id": server.get("id", ""),
                    "source": server.get("source", ""),
                    "status": server.get("status", ""),
                    "transport": server.get("transport", ""),
                    "tools": server.get("tools_count", 0),
                    "url": server.get("url", ""),
                    "description": server.get("description", ""),
                },
            )
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("tools")
def tools(json_output: bool = typer.Option(False, "--json")) -> None:
    """List MCP tools exposed through Sentinel."""
    client = SpecterAPIClient()
    try:
        data = client.mcp_tools()
        if json_output:
            formatter.print_json(data)
            return
        formatter.symbol_table("SENTINEL MCP TOOLS", [
            {
                "name": item.get("name"),
                "type": item.get("category"),
                "namespace": item.get("server_id"),
                "address": "",
                "size": "",
            }
            for item in data
        ])
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("invoke")
def invoke(
    tool_name: str,
    args_json: str = typer.Option("{}", "--args", "-a", help="JSON object passed to the MCP tool."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Invoke a Sentinel-exposed MCP tool."""
    client = SpecterAPIClient()
    try:
        try:
            args = json.loads(args_json)
            if not isinstance(args, dict):
                raise ValueError("MCP arguments must be a JSON object.")
        except ValueError as exc:
            raise ValueError(f"Invalid --args JSON: {exc}") from exc

        data = client.mcp_invoke(tool_name, args)
        if json_output:
            formatter.print_json(data)
        elif data.get("success"):
            formatter.kv_panel(
                "MCP INVOCATION",
                {
                    "tool": data.get("tool", tool_name),
                    "success": data.get("success"),
                    "duration_ms": round(float(data.get("duration_ms", 0)), 2),
                    "result_type": type(data.get("result")).__name__,
                },
            )
        else:
            formatter.error(data.get("error") or "MCP invocation failed")
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()
