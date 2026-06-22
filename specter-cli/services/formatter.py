from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from rich import box
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.theme import Theme


console = Console(theme=Theme({
    "specter": "bold white",
    "muted": "dim white",
    "danger": "bold white on black",
    "ok": "white",
    "warn": "bold white",
}))


def banner() -> None:
    console.print(Panel(
        "[specter]SPECTER[/specter]\n[muted]Sentinel AI forensic operations terminal[/muted]",
        border_style="white",
        box=box.SQUARE,
    ))


def print_json(data: Any) -> None:
    console.print(JSON(json.dumps(data, default=str)))


def error(message: str) -> None:
    console.print(Panel(message, title="OPERATION FAILED", border_style="white", box=box.SQUARE))


def warning(message: str) -> None:
    console.print(Panel(message, title="NOTICE", border_style="white", box=box.SQUARE))


def success(message: str) -> None:
    console.print(f"[ok]{message}[/ok]")


def kv_panel(title: str, values: Dict[str, Any]) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="muted")
    table.add_column(style="white")
    for key, value in values.items():
        table.add_row(str(key).upper(), str(value))
    console.print(Panel(table, title=title, border_style="white", box=box.SQUARE))


def case_table(cases: Iterable[Dict[str, Any]]) -> None:
    table = Table(title="CASE VAULT", box=box.SIMPLE_HEAVY, border_style="white")
    for column in ["CASE", "NAME", "SEV", "STATUS", "EVID", "EVENTS", "UPDATED"]:
        table.add_column(column, overflow="fold")
    for item in cases:
        table.add_row(
            item.get("id", ""),
            item.get("name", ""),
            item.get("severity", ""),
            item.get("status", ""),
            str(item.get("evidence_count", 0)),
            str(item.get("timeline_count", 0)),
            str(item.get("updated_at") or item.get("created_at") or ""),
        )
    console.print(table)


def evidence_table(evidence: Iterable[Dict[str, Any]]) -> None:
    table = Table(title="EVIDENCE INVENTORY", box=box.SIMPLE_HEAVY, border_style="white")
    for column in ["ID", "FILE", "TYPE", "SIZE", "STATUS", "SHA256"]:
        table.add_column(column, overflow="fold")
    for item in evidence:
        sha = item.get("sha256") or ""
        table.add_row(
            item.get("id", "")[:12],
            item.get("original_filename", item.get("filename", "")),
            item.get("evidence_type", ""),
            str(item.get("file_size", 0)),
            item.get("analysis_status", ""),
            sha[:18],
        )
    console.print(table)


def symbol_table(title: str, rows: Iterable[Dict[str, Any]], limit: Optional[int] = None) -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY, border_style="white")
    for column in ["NAME", "ADDRESS", "TYPE", "NAMESPACE", "SIZE"]:
        table.add_column(column, overflow="fold")
    count = 0
    for item in rows:
        if limit is not None and count >= limit:
            break
        table.add_row(
            str(item.get("name", "")),
            str(item.get("address") or ""),
            str(item.get("type") or item.get("symbol_type") or ""),
            str(item.get("namespace") or item.get("library") or item.get("package") or ""),
            str(item.get("size") or ""),
        )
        count += 1
    console.print(table)


def report_table(reports: Iterable[Dict[str, Any]]) -> None:
    table = Table(title="REPORT INVENTORY", box=box.SIMPLE_HEAVY, border_style="white")
    for column in ["REPORT", "TYPE", "SIZE", "PATH", "MODIFIED"]:
        table.add_column(column, overflow="fold")
    for item in reports:
        table.add_row(
            item.get("name", ""),
            item.get("report_type", ""),
            str(item.get("size", 0)),
            item.get("relative_path", ""),
            item.get("modified_at", ""),
        )
    console.print(table)


def ioc_table(grouped: Dict[str, List[str]]) -> None:
    table = Table(title="INDICATORS OF COMPROMISE", box=box.SIMPLE_HEAVY, border_style="white")
    table.add_column("TYPE")
    table.add_column("VALUE", overflow="fold")
    for ioc_type, values in grouped.items():
        for value in sorted(set(values)):
            table.add_row(ioc_type.upper(), value)
    console.print(table)


def syntax(code: str, lexer: str = "c", title: str = "DECOMPILATION") -> None:
    console.print(Panel(Syntax(code, lexer, theme="ansi_dark", line_numbers=True), title=title, border_style="white"))


def spinner(description: str) -> Progress:
    return Progress(SpinnerColumn(), TextColumn("[white]{task.description}"), TimeElapsedColumn(), console=console)
