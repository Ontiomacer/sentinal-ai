from __future__ import annotations

from typing import Optional

import typer

from commands.common import find_symbol, resolve_evidence
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError


app = typer.Typer(help="Ghidra MCP operations through Sentinel backend.")


def _evidence_id(client: SpecterAPIClient, case_id: str, evidence: Optional[str]) -> str:
    return resolve_evidence(client, case_id, evidence)["id"]


@app.command("health")
def health(json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        data = client.ghidra_diagnostics()
        formatter.print_json(data) if json_output else formatter.kv_panel("GHIDRA MCP", data)
    except SpecterError as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("functions")
def functions(
    case_id: str,
    evidence: Optional[str] = typer.Option(None, "--evidence", "-e"),
    limit: int = typer.Option(100, "--limit", "-n"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        data = client.ghidra_functions(_evidence_id(client, case_id, evidence))
        limited = data[:limit] if limit else data
        formatter.print_json(limited) if json_output else formatter.symbol_table("GHIDRA FUNCTIONS", data, limit)
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("imports")
def imports(case_id: str, evidence: Optional[str] = typer.Option(None, "--evidence", "-e"), json_output: bool = typer.Option(False, "--json")) -> None:
    _imports_exports(case_id, evidence, "import", json_output)


@app.command("exports")
def exports(case_id: str, evidence: Optional[str] = typer.Option(None, "--evidence", "-e"), json_output: bool = typer.Option(False, "--json")) -> None:
    _imports_exports(case_id, evidence, "export", json_output)


def _imports_exports(case_id: str, evidence: Optional[str], kind: str, json_output: bool) -> None:
    client = SpecterAPIClient()
    try:
        data = client.ghidra_imports_exports(_evidence_id(client, case_id, evidence))
        filtered = [item for item in data if str(item.get("type", "")).lower() == kind]
        formatter.print_json(filtered) if json_output else formatter.symbol_table(f"GHIDRA {kind.upper()}S", filtered)
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("classes")
def classes(case_id: str, evidence: Optional[str] = typer.Option(None, "--evidence", "-e"), json_output: bool = typer.Option(False, "--json")) -> None:
    client = SpecterAPIClient()
    try:
        data = client.ghidra_classes(_evidence_id(client, case_id, evidence))
        formatter.print_json(data) if json_output else formatter.symbol_table("GHIDRA CLASSES", data)
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("strings")
def strings(
    case_id: str,
    evidence: Optional[str] = typer.Option(None, "--evidence", "-e"),
    limit: int = typer.Option(100, "--limit", "-n"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        data = client.ghidra_strings(_evidence_id(client, case_id, evidence))
        limited = data[:limit] if limit else data
        formatter.print_json(limited) if json_output else formatter.symbol_table("GHIDRA STRINGS", data, limit)
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("decompile")
def decompile(
    case_id: str,
    symbol: str,
    evidence: Optional[str] = typer.Option(None, "--evidence", "-e"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    client = SpecterAPIClient()
    try:
        evidence_id = _evidence_id(client, case_id, evidence)
        tree = client.ghidra_symbol_tree(evidence_id)
        node, score = find_symbol(tree, symbol)
        address = node.get("address")
        if not address:
            raise ValueError(f"Symbol has no decompilable address: {node.get('name')}")
        data = client.ghidra_decompile(evidence_id, address)
        if json_output:
            formatter.print_json({"match_score": score, "symbol": node, "decompile": data})
        else:
            formatter.kv_panel("SYMBOL MATCH", {"name": node.get("name"), "address": address, "confidence": f"{score:.2f}"})
            formatter.syntax(data.get("c_code", ""), "c", title=data.get("function_name", "DECOMPILATION"))
    except (SpecterError, ValueError) as exc:
        formatter.error(str(exc))
    finally:
        client.close()


@app.command("disasm")
def disasm(case_id: str, symbol: str, evidence: Optional[str] = typer.Option(None, "--evidence", "-e"), json_output: bool = typer.Option(False, "--json")) -> None:
    payload = {
        "case_id": case_id,
        "symbol": symbol,
        "evidence": evidence,
        "status": "backend_capability_unavailable",
        "detail": "The Sentinel backend does not currently expose a raw disassembly endpoint. Use `specter ghidra decompile` for live decompiler output.",
    }
    formatter.print_json(payload) if json_output else formatter.warning(payload["detail"])
