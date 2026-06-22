from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "specter.toml"


@dataclass
class SpecterConfig:
    backend_url: str = "http://localhost:8000"
    timeout_seconds: float = 30.0
    retries: int = 2
    token: str = "user_dev"
    active_case: str = ""
    theme: str = "monochrome"
    default_format: str = "table"


def _read_toml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def load_config() -> SpecterConfig:
    data = _read_toml(CONFIG_PATH)
    backend = data.get("backend", {})
    auth = data.get("auth", {})
    workspace = data.get("workspace", {})
    output = data.get("output", {})

    return SpecterConfig(
        backend_url=os.getenv("SPECTER_BACKEND_URL", backend.get("url", "http://localhost:8000")),
        timeout_seconds=float(os.getenv("SPECTER_TIMEOUT", backend.get("timeout_seconds", 30))),
        retries=int(os.getenv("SPECTER_RETRIES", backend.get("retries", 2))),
        token=os.getenv("SPECTER_TOKEN", auth.get("token", "user_dev")),
        active_case=os.getenv("SPECTER_ACTIVE_CASE", workspace.get("active_case", "")),
        theme=output.get("theme", "monochrome"),
        default_format=output.get("default_format", "table"),
    )


def save_config(config: SpecterConfig) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join([
        "[backend]",
        f'url = "{config.backend_url}"',
        f"timeout_seconds = {int(config.timeout_seconds)}",
        f"retries = {int(config.retries)}",
        "",
        "[auth]",
        f'token = "{config.token}"',
        "",
        "[workspace]",
        f'active_case = "{config.active_case}"',
        "",
        "[output]",
        f'default_format = "{config.default_format}"',
        f'theme = "{config.theme}"',
        "",
    ])
    CONFIG_PATH.write_text(content, encoding="utf-8")


def set_active_case(case_id: str) -> None:
    config = load_config()
    config.active_case = case_id
    save_config(config)
