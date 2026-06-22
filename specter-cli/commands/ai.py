from __future__ import annotations

from typing import Optional

import typer

from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="AI integration health and investigation suggestions.")


@app.command("health")
def health(json_output: bool = typer.Option(False, "--json")) -> None:
    """Show local AI model health."""
    client = SpecterAPIClient()
    try:
        data = client.ai_health()
        formatter.print_json(data) if json_output else formatter.kv_panel("AI ENGINE", data)
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("suggest")
def suggest(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Case ID or active case context."),
    evidence_id: Optional[str] = typer.Option(None, "--evidence", "-e", help="Optional evidence ID."),
    scan_id: Optional[str] = typer.Option(None, "--scan", "-s", help="Optional legacy scan ID."),
    rules_only: bool = typer.Option(False, "--rules-only", help="Skip Ollama summary generation."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Generate case-aware investigation suggestions."""
    client = SpecterAPIClient()
    try:
        target_case = case_id or client.config.active_case
        data = client.ai_suggestions(
            case_id=target_case,
            evidence_id=evidence_id,
            scan_id=scan_id,
            use_ai=not rules_only,
        )
        if json_output:
            formatter.print_json(data)
            return

        formatter.kv_panel(
            "AI SUGGESTIONS",
            {
                "case": data.get("scope", {}).get("case_id") or "none",
                "ai_powered": data.get("ai_powered"),
                "evidence": data.get("evidence_count"),
                "suggestions": len(data.get("suggestions", [])),
            },
        )
        for item in data.get("suggestions", []):
            formatter.kv_panel(
                item.get("title", "SUGGESTION"),
                {
                    "severity": item.get("severity"),
                    "source": item.get("source"),
                    "action": item.get("action") or "",
                    "detail": item.get("detail", ""),
                },
            )
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()
