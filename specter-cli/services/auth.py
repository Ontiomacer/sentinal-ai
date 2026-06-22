from __future__ import annotations

from typing import Dict

from services.config import SpecterConfig


def auth_headers(config: SpecterConfig) -> Dict[str, str]:
    if not config.token:
        return {}
    token = config.token
    if token.startswith("Bearer "):
        return {"Authorization": token}
    return {"Authorization": f"Bearer {token}"}
