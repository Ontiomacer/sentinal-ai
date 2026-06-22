from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Iterable, Optional

import typer

from commands.common import resolve_case
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="Forensic triage and drive intake.")


def _hash_file(path: Path) -> Dict[str, str | int]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"path": str(path), "size": size, "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _files(path: Path, recursive: bool) -> Iterable[Path]:
    if path.is_file():
        yield path
    elif recursive:
        for item in path.rglob("*"):
            if item.is_file():
                yield item
    else:
        for item in path.iterdir():
            if item.is_file():
                yield item


@app.command("drives")
def drives(
    case_ref: Optional[str] = typer.Option(None, "--case", "-c", help="Case ID/name. Defaults to active case."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        case = resolve_case(client, case_ref)
        data = client.triage(case["id"])
        formatter.print_json(data) if json_output else formatter.kv_panel("TRIAGE DRIVES", {
            "case": case["id"],
            "drives": len(data.get("drives", [])),
            "configured env": data.get("configured_roots_env", ""),
        })
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("inventory")
def inventory(
    case_ref: Optional[str] = typer.Option(None, "--case", "-c"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        case = resolve_case(client, case_ref)
        data = client.filesystem(case["id"])
        formatter.print_json(data) if json_output else formatter.kv_panel("CASE FILESYSTEM", {
            "case": case["id"],
            "directories": data.get("totals", {}).get("directories", 0),
            "files": data.get("totals", {}).get("files", 0),
            "bytes": data.get("totals", {}).get("bytes", 0),
            "evidence": data.get("totals", {}).get("evidence_items", 0),
        })
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("hash")
def hash_path(path: Path = typer.Argument(..., exists=True, readable=True), json_output: bool = typer.Option(False, "--json")) -> None:
    if path.is_dir():
        formatter.error("Hash target must be a file. Use triage ingest for recursive evidence intake.")
        return
    data = _hash_file(path)
    formatter.print_json(data) if json_output else formatter.kv_panel("FORENSIC HASH", data)


@app.command("ingest")
def ingest(
    path: Path = typer.Argument(..., exists=True, readable=True),
    case_ref: Optional[str] = typer.Option(None, "--case", "-c"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        case = resolve_case(client, case_ref)
        uploaded = []
        failed = []
        for item in _files(path, recursive):
            try:
                uploaded.append(client.upload_evidence(case["id"], item, notes=f"Triage ingest from {path}"))
            except SpecterError as exc:
                failed.append({"path": str(item), "error": str(exc)})
        payload = {"case_id": case["id"], "uploaded": uploaded, "failed": failed}
        if json_output:
            formatter.print_json(payload)
        else:
            formatter.kv_panel("TRIAGE INGEST", {"case": case["id"], "uploaded": len(uploaded), "failed": len(failed)})
            if uploaded:
                formatter.evidence_table(uploaded)
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()
