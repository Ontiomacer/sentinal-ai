from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from commands.common import write_json_file
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="Forensic report generation and inventory.")


@app.command("inventory")
def inventory(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        data = client.report_inventory(case_id)
        formatter.print_json(data) if json_output else formatter.report_table(data.get("reports", []))
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("generate")
def generate(
    case_id: str,
    report_type: str = typer.Option("executive", "--type", "-t", help="executive, technical, timeline, or ioc."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        data = client.generate_report(case_id, report_type)
        formatter.print_json(data) if json_output else formatter.kv_panel("REPORT GENERATED", data)
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("export")
def export(
    case_id: str,
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write inventory JSON to this file."),
    export_format: str = typer.Option("markdown", "--format", "-f", help="markdown, json, or pdf."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        inventory_data = client.report_inventory(case_id)
        if export_format == "pdf":
            payload = {"status": "backend_capability_unavailable", "detail": "PDF export is future-ready but not exposed by the backend yet."}
            formatter.print_json(payload) if json_output else formatter.warning(payload["detail"])
            return
        if export_format == "json" and output:
            write_json_file(output, inventory_data)
            formatter.success(f"Report inventory exported: {output}")
            return
        formatter.print_json(inventory_data) if json_output or export_format == "json" else formatter.report_table(inventory_data.get("reports", []))
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()
