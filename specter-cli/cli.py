from __future__ import annotations

import typer

from commands import ai, cases, ghidra, iocs, mcp, neural, reports, triage
from commands.analyze import analyze_command
from commands.live import live_command
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(
    name="specter",
    help="Sentinel AI forensic operations terminal.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(cases.app, name="cases")
app.add_typer(ai.app, name="ai")
app.add_typer(ghidra.app, name="ghidra")
app.add_typer(mcp.app, name="mcp")
app.add_typer(neural.app, name="neural")
app.add_typer(reports.app, name="report")
app.add_typer(reports.app, name="reports")
app.add_typer(iocs.app, name="iocs")
app.add_typer(triage.app, name="triage")
app.command("analyze")(analyze_command)
app.command("live")(live_command)


@app.command("status")
def status(json_output: bool = typer.Option(False, "--json", help="Emit raw JSON.")) -> None:
    """Show backend and Ghidra operational status."""
    client = SpecterAPIClient()
    try:
        payload = {
            "backend": client.health(),
            "ghidra": client.ghidra_health(),
            "mcp_tools": client.mcp_tools(),
            "ai": client.ai_health(),
            "active_case": client.config.active_case,
        }
        if json_output:
            formatter.print_json(payload)
        else:
            formatter.banner()
            formatter.kv_panel("SENTINEL BACKEND", payload["backend"])
            formatter.kv_panel("GHIDRA MCP", payload["ghidra"])
            formatter.kv_panel("MCP SURFACE", {"tools": len(payload["mcp_tools"])})
            formatter.kv_panel("AI ENGINE", payload["ai"])
            formatter.kv_panel("WORKSPACE", {"active_case": payload["active_case"] or "none"})
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


if __name__ == "__main__":
    app()
