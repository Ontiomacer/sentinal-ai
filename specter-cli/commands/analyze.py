from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

import typer

from commands.common import extract_risk, resolve_case
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


def _pipelines(deep: bool, ai: bool) -> List[str]:
    if deep and ai:
        return ["neural_ai", "deep_reverse_engineering"]
    if deep:
        return ["deep_reverse_engineering"]
    return ["neural_ai"]


def _show_analysis_result(evidence: dict) -> None:
    risk = extract_risk(evidence)
    formatter.kv_panel("ANALYSIS TELEMETRY", {
        "evidence": evidence.get("id", ""),
        "file": evidence.get("original_filename", ""),
        "status": evidence.get("analysis_status", ""),
        "risk score": risk["risk_score"],
        "threat level": risk["threat_level"],
        "sha256": evidence.get("sha256", ""),
    })


def analyze_command(
    apk_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, help="APK or forensic artifact."),
    case_ref: Optional[str] = typer.Option(None, "--case", "-c", help="Case ID/name. Defaults to active case if set."),
    deep: bool = typer.Option(False, "--deep", help="Run deep reverse engineering pipeline."),
    ai: bool = typer.Option(False, "--ai", help="Run neural AI pipeline."),
    watch: bool = typer.Option(False, "--watch", "-w", help="Poll until analysis completes or times out."),
    watch_seconds: int = typer.Option(180, "--watch-seconds", help="Maximum watch duration."),
    headless: bool = typer.Option(False, "--headless", help="Suppress banner and progress decoration."),
    json_output: bool = typer.Option(False, "--json", help="Emit raw JSON."),
) -> None:
    client = SpecterAPIClient()
    try:
        if not headless and not json_output:
            formatter.banner()

        active_case = None
        try:
            active_case = resolve_case(client, case_ref) if (case_ref or client.config.active_case) else None
        except ValueError:
            if case_ref:
                raise

        if active_case:
            with formatter.spinner(f"Uploading evidence to {active_case['id']}") as progress:
                task = progress.add_task("upload", total=None)
                evidence = client.upload_evidence(active_case["id"], apk_file, notes="Uploaded via Specter CLI")
                progress.update(task, description="evidence uploaded")

            responses = []
            for pipeline in _pipelines(deep, ai):
                responses.append(client.analyze_evidence(active_case["id"], evidence["id"], pipeline))

            if watch:
                deadline = time.monotonic() + watch_seconds
                while time.monotonic() < deadline:
                    evidence = client.get_evidence(active_case["id"], evidence["id"])
                    status = str(evidence.get("analysis_status", "")).lower()
                    if status in {"complete", "ready", "failed"}:
                        break
                    time.sleep(3)

            evidence = client.get_evidence(active_case["id"], evidence["id"])
            payload = {"case": active_case, "evidence": evidence, "analysis_requests": responses}
            if json_output:
                formatter.print_json(payload)
            else:
                _show_analysis_result(evidence)
            return

        if deep:
            formatter.warning("No case selected. Deep/Ghidra analysis requires case evidence; falling back to legacy static APK upload.")

        scan = client.upload_legacy_apk(apk_file)
        neural_response = None
        if ai:
            try:
                neural_response = client.neural_scan(scan["scan_id"])
            except SpecterError as exc:
                neural_response = {"status": "unavailable", "detail": str(exc)}

        payload = {"scan": scan, "neural": neural_response}
        if json_output:
            formatter.print_json(payload)
        else:
            formatter.kv_panel("LEGACY APK ANALYSIS", {
                "scan": scan.get("scan_id"),
                "file": scan.get("filename"),
                "status": scan.get("status"),
                "sha256": scan.get("sha256"),
            })
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()
