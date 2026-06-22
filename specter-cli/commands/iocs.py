from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from commands.common import collect_case_iocs, write_json_file
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="IOC extraction and export.")


@app.command("list")
def list_iocs(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        grouped = collect_case_iocs(client, case_id)
        formatter.print_json(grouped) if json_output else formatter.ioc_table(grouped)
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("domains")
def domains(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        data = collect_case_iocs(client, case_id).get("domains", [])
        formatter.print_json(data) if json_output else formatter.ioc_table({"domains": data})
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("ips")
def ips(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        data = collect_case_iocs(client, case_id).get("ips", [])
        formatter.print_json(data) if json_output else formatter.ioc_table({"ips": data})
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("export")
def export_iocs(
    case_id: str,
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        grouped = collect_case_iocs(client, case_id)
        if output:
            write_json_file(output, grouped)
            formatter.success(f"IOC export written: {output}")
        elif json_output:
            formatter.print_json(grouped)
        else:
            formatter.ioc_table(grouped)
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()
