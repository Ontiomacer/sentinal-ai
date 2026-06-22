from __future__ import annotations

from typing import Optional

import typer

from commands.common import resolve_case
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError
from services.config import set_active_case


app = typer.Typer(help="Case vault operations.")


@app.command("list")
def list_cases(
    status: Optional[str] = typer.Option("active", "--status", "-s", help="Filter by active, archived, closed, or pending."),
    all_cases: bool = typer.Option(False, "--all", help="Show all cases."),
    json_output: bool = typer.Option(False, "--json", help="Emit raw JSON."),
) -> None:
    client = SpecterAPIClient()
    try:
        data = client.list_cases(None if all_cases else status)
        formatter.print_json(data) if json_output else formatter.case_table(data)
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("create")
def create_case(
    name: str = typer.Argument(..., help="Case name."),
    investigator: str = typer.Option("Analyst", "--investigator", "-i"),
    client_name: Optional[str] = typer.Option(None, "--client"),
    severity: str = typer.Option("medium", "--severity", "-s"),
    description: Optional[str] = typer.Option(None, "--description", "-d"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags."),
    open_case: bool = typer.Option(True, "--open/--no-open", help="Make this the active case."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        payload = {
            "name": name,
            "investigator": investigator,
            "client_name": client_name,
            "description": description,
            "severity": severity,
            "tags": [tag.strip() for tag in tags.split(",")] if tags else None,
        }
        data = client.create_case(payload)
        if open_case:
            set_active_case(data["id"])
        if json_output:
            formatter.print_json(data)
        else:
            formatter.success(f"Case created: {data['id']} ({data['name']})")
            formatter.kv_panel("ACTIVE CASE", {"case": data["id"], "name": data["name"]})
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("open")
def open_case(
    reference: str = typer.Argument(..., help="Case ID or name."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        case = resolve_case(client, reference)
        set_active_case(case["id"])
        formatter.print_json(case) if json_output else formatter.kv_panel(
            "ACTIVE CASE",
            {"case": case["id"], "name": case["name"], "severity": case["severity"], "status": case["status"]},
        )
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("status")
def case_status(
    reference: Optional[str] = typer.Argument(None, help="Case ID/name. Defaults to active case."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        case = resolve_case(client, reference)
        evidence = client.list_evidence(case["id"])
        timeline = client.timeline(case["id"])
        reports = client.report_inventory(case["id"])
        payload = {"case": case, "evidence": evidence, "timeline_count": len(timeline), "reports": reports}
        if json_output:
            formatter.print_json(payload)
        else:
            formatter.kv_panel("CASE STATUS", {
                "case": case["id"],
                "name": case["name"],
                "status": case["status"],
                "severity": case["severity"],
                "evidence": len(evidence),
                "timeline": len(timeline),
                "reports": reports.get("count", 0),
            })
            formatter.evidence_table(evidence)
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("delete")
def delete_case(
    reference: str = typer.Argument(..., help="Case ID or name."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        case = resolve_case(client, reference)
        if not yes and not typer.confirm(f"Delete case {case['id']} ({case['name']})?"):
            formatter.warning("Delete aborted.")
            return
        client.delete_case(case["id"])
        formatter.print_json({"deleted": case["id"]}) if json_output else formatter.success(f"Deleted case {case['id']}")
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()
