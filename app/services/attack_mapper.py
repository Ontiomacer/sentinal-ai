import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackMapper:
    """Maps APK artifacts and heuristic signals to ATT&CK techniques."""

    def __init__(self, mapping_path: Optional[Path] = None):
        self.mapping_path = mapping_path or Path(__file__).resolve().parent / "attack_mappings.json"
        self.mappings = self._load_mappings()

    def _load_mappings(self) -> Dict[str, Any]:
        if not self.mapping_path.exists():
            logger.warning("ATT&CK mapping file missing: %s", self.mapping_path)
            return {}

        try:
            with open(self.mapping_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception as exc:
            logger.error("Failed to load ATT&CK mappings: %s", exc)
            return {}

    def map_artifacts(self, analysis_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map artifacts, permissions, and indicators to ATT&CK techniques."""
        mapped: List[Dict[str, Any]] = []

        evidence_text = " ".join(
            str(value)
            for value in [
                analysis_context.get("package_name"),
                analysis_context.get("app_name"),
                analysis_context.get("permissions"),
                analysis_context.get("activities"),
                analysis_context.get("services"),
                analysis_context.get("receivers"),
                analysis_context.get("providers"),
                analysis_context.get("urls"),
                analysis_context.get("domains"),
                analysis_context.get("heuristic_indicators", []),
            ]
            if value
        ).lower()

        for category, definition in self.mappings.items():
            if not isinstance(definition, dict):
                continue

            matches = []
            tokens = definition.get("match_tokens", [])
            for token in tokens:
                if token.lower() in evidence_text:
                    matches.append(token)

            if matches:
                mapped.append({
                    "category": category,
                    "technique_id": definition.get("technique_id", "UNKNOWN"),
                    "technique_name": definition.get("technique_name", category),
                    "description": definition.get("description", ""),
                    "matched_tokens": sorted(set(matches)),
                    "confidence": min(100, 20 + len(matches) * 10)
                })

        if not mapped:
            mapped.append({
                "category": "unknown",
                "technique_id": "T0000",
                "technique_name": "No mapped ATT&CK technique",
                "description": "No reliable ATT&CK mapping could be derived from the available artifacts.",
                "matched_tokens": [],
                "confidence": 0
            })

        return mapped

    def summarize_mappings(self, mapped_techniques: List[Dict[str, Any]]) -> str:
        if not mapped_techniques:
            return "No ATT&CK techniques were confidently identified from the available artifacts."

        summaries = []
        for item in mapped_techniques:
            summaries.append(
                f"{item.get('technique_id')} ({item.get('technique_name')}): {item.get('description')}"
            )

        return " | ".join(summaries)
