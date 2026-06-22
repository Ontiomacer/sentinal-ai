from __future__ import annotations

import shlex

import typer
from rich.prompt import Prompt

from commands.common import resolve_case
from services import formatter
from services.api_client import SpecterAPIClient, SpecterError
from services.config import load_config, set_active_case


def live_command() -> None:
    formatter.banner()
    formatter.success("Interactive forensic shell ready. Type `help` for commands, `exit` to leave.")
    client = SpecterAPIClient()
    try:
        while True:
            active = load_config().active_case or "no-case"
            try:
                raw = Prompt.ask(f"[white]specter[/white]({active})")
            except (EOFError, KeyboardInterrupt):
                formatter.success("Session closed.")
                return

            parts = shlex.split(raw)
            if not parts:
                continue
            command = parts[0].lower()

            try:
                if command in {"exit", "quit"}:
                    formatter.success("Session closed.")
                    return
                if command == "help":
                    formatter.kv_panel("LIVE COMMANDS", {
                        "cases": "List active cases",
                        "use <case>": "Set active case by ID/name",
                        "status": "Show active case status",
                        "evidence": "List active case evidence",
                        "reports": "List active case reports",
                        "ghidra": "Show Ghidra MCP health",
                        "exit": "Close shell",
                    })
                elif command == "cases":
                    formatter.case_table(client.list_cases("active"))
                elif command == "use" and len(parts) > 1:
                    case = resolve_case(client, " ".join(parts[1:]))
                    set_active_case(case["id"])
                    formatter.success(f"Active case set: {case['id']} ({case['name']})")
                elif command == "status":
                    case = resolve_case(client)
                    formatter.kv_panel("ACTIVE CASE", case)
                elif command == "evidence":
                    case = resolve_case(client)
                    formatter.evidence_table(client.list_evidence(case["id"]))
                elif command == "reports":
                    case = resolve_case(client)
                    formatter.report_table(client.report_inventory(case["id"]).get("reports", []))
                elif command == "ghidra":
                    formatter.kv_panel("GHIDRA MCP", client.ghidra_diagnostics())
                else:
                    formatter.warning(f"Unknown live command: {raw}")
            except (SpecterError, ValueError) as exc:
                formatter.error(str(exc))
    finally:
        client.close()
