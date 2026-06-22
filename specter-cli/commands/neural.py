from __future__ import annotations

from typing import Any, Dict, List

import typer

from commands.common import extract_risk
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="Neural Engine case intelligence.")


def _case_risks(client: SpecterAPIClient, case_id: str) -> List[Dict[str, Any]]:
    rows = []
    for evidence in client.list_evidence(case_id):
        risk = extract_risk(evidence)
        rows.append({"evidence": evidence, **risk})
    return rows


@app.command("summary")
def summary(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        case = client.get_case(case_id)
        risks = _case_risks(client, case_id)
        payload = {"case": case, "risks": risks, "timeline": client.timeline(case_id)}
        if json_output:
            formatter.print_json(payload)
            return
        formatter.kv_panel("NEURAL SUMMARY", {
            "case": case_id,
            "evidence": len(risks),
            "max score": max([item["risk_score"] for item in risks] or [0]),
            "events": len(payload["timeline"]),
        })
        formatter.evidence_table([item["evidence"] for item in risks])
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("score")
def score(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        risks = _case_risks(client, case_id)
        max_score = max([item["risk_score"] for item in risks] or [0])
        avg_score = round(sum(item["risk_score"] for item in risks) / len(risks), 2) if risks else 0
        payload = {"case_id": case_id, "max_score": max_score, "average_score": avg_score, "evidence": risks}
        if json_output:
            formatter.print_json(payload)
        else:
            formatter.kv_panel("THREAT SCORE", {"case": case_id, "max": max_score, "average": avg_score})
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("explain")
def explain(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        risks = _case_risks(client, case_id)
        insights = [item for item in risks if item.get("neural_insights")]
        payload = {"case_id": case_id, "neural_insights": insights}
        if json_output:
            formatter.print_json(payload)
        elif not insights:
            formatter.warning("No Neural Engine cognition is present in current case evidence yet.")
        else:
            for item in insights:
                formatter.kv_panel("NEURAL COGNITION", {
                    "evidence": item["evidence"].get("original_filename", ""),
                    "score": item["risk_score"],
                    "level": item["threat_level"],
                    "insights": item["neural_insights"],
                })
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("attack-map")
def attack_map(case_id: str, json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        mappings = []
        for item in _case_risks(client, case_id):
            if item.get("attack_mapping"):
                mappings.append({
                    "evidence_id": item["evidence"].get("id"),
                    "file": item["evidence"].get("original_filename"),
                    "attack_mapping": item["attack_mapping"],
                })
        if json_output:
            formatter.print_json({"case_id": case_id, "mappings": mappings})
        elif not mappings:
            formatter.warning("No ATT&CK mapping data is present in current case evidence yet.")
        else:
            formatter.print_json({"case_id": case_id, "mappings": mappings})
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()
