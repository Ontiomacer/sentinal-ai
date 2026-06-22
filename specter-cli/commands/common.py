from __future__ import annotations

import ipaddress
import json
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from services.api_client import SpecterAPIClient
from services.config import load_config


IOC_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IOC_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IOC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def resolve_case(client: SpecterAPIClient, reference: Optional[str] = None) -> Dict[str, Any]:
    target = reference or load_config().active_case
    if not target:
        raise ValueError("No case selected. Use `specter cases open <case>` or pass --case.")

    cases = client.list_cases(status=None)
    lowered = target.lower()
    matches = [
        item for item in cases
        if item.get("id", "").lower() == lowered or item.get("name", "").lower() == lowered
    ]
    if not matches:
        partial = [item for item in cases if lowered in item.get("name", "").lower()]
        if len(partial) == 1:
            return partial[0]
        raise ValueError(f"Case not found: {target}")
    if len(matches) > 1:
        raise ValueError(f"Case reference is ambiguous: {target}")
    return matches[0]


def resolve_evidence(
    client: SpecterAPIClient,
    case_id: str,
    evidence_reference: Optional[str] = None,
) -> Dict[str, Any]:
    evidence = client.list_evidence(case_id)
    if not evidence:
        raise ValueError(f"No evidence exists in case {case_id}")

    if evidence_reference:
        lowered = evidence_reference.lower()
        matches = [
            item for item in evidence
            if item.get("id", "").lower().startswith(lowered)
            or item.get("original_filename", "").lower() == lowered
            or lowered in item.get("original_filename", "").lower()
        ]
        if not matches:
            raise ValueError(f"Evidence not found: {evidence_reference}")
        return sorted(matches, key=lambda item: item.get("created_at", ""), reverse=True)[0]

    return sorted(evidence, key=lambda item: item.get("created_at", ""), reverse=True)[0]


def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    urls = IOC_URL_RE.findall(text)
    domains = []
    for url in urls:
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
        if host:
            domains.append(host)
    ips: List[str] = []
    for match in IOC_IP_RE.findall(text):
        try:
            ipaddress.ip_address(match)
            ips.append(match)
        except ValueError:
            continue
    return {"urls": urls, "domains": domains, "ips": ips}


def collect_iocs_from_analysis(value: Any, grouped: Dict[str, List[str]], parent_key: str = "") -> None:
    key = parent_key.lower()
    if isinstance(value, dict):
        for nested_key, nested_value in value.items():
            collect_iocs_from_analysis(nested_value, grouped, nested_key)
    elif isinstance(value, list):
        for nested in value:
            collect_iocs_from_analysis(nested, grouped, parent_key)
    elif isinstance(value, str):
        found = extract_iocs_from_text(value)
        grouped["urls"].extend(found["urls"])
        grouped["ips"].extend(found["ips"])
        grouped["domains"].extend(found["domains"])
        if key in {"domain", "domains", "host", "hosts", "hostname", "hostnames"}:
            if IOC_DOMAIN_RE.fullmatch(value):
                grouped["domains"].append(value)


def collect_case_iocs(client: SpecterAPIClient, case_id: str) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {"urls": [], "domains": [], "ips": [], "emails": [], "hashes": []}

    for entity in client.entities(case_id):
        entity_type = entity.get("entity_type", "")
        value = entity.get("value", "")
        if entity_type == "url":
            grouped["urls"].append(value)
        elif entity_type == "domain":
            grouped["domains"].append(value)
        elif entity_type == "ip_address":
            grouped["ips"].append(value)
        elif entity_type == "email":
            grouped["emails"].append(value)

    for evidence in client.list_evidence(case_id):
        for key in ("md5", "sha1", "sha256"):
            if evidence.get(key):
                grouped["hashes"].append(evidence[key])
        analysis = evidence.get("analysis_result") or {}
        collect_iocs_from_analysis(analysis, grouped)

    return {key: sorted(set(value for value in values if value)) for key, values in grouped.items()}


def flatten_symbol_nodes(nodes: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    flat: List[Dict[str, Any]] = []
    for node in nodes:
        flat.append(node)
        flat.extend(flatten_symbol_nodes(node.get("children", [])))
    return flat


def find_symbol(tree: Dict[str, Any], query: str) -> Tuple[Dict[str, Any], float]:
    nodes = flatten_symbol_nodes(tree.get("roots", []))
    lowered = query.lower()
    candidates: List[Tuple[Dict[str, Any], float]] = []

    for node in nodes:
        name = str(node.get("name", ""))
        address = str(node.get("address") or "")
        stable_id = str(node.get("id") or "")
        if lowered in {name.lower(), address.lower(), stable_id.lower()}:
            return node, 1.0
        score = max(
            SequenceMatcher(None, lowered, name.lower()).ratio(),
            0.85 if lowered and lowered in name.lower() else 0,
            0.8 if lowered and lowered in address.lower() else 0,
        )
        if score > 0.45:
            candidates.append((node, score))

    if not candidates:
        raise ValueError(f"Symbol not found: {query}")

    candidates.sort(key=lambda item: item[1], reverse=True)
    return candidates[0]


def extract_risk(evidence: Dict[str, Any]) -> Dict[str, Any]:
    result = evidence.get("analysis_result") or {}
    risk_score = result.get("risk_score")
    threat_level = result.get("threat_level")

    ai_analysis = result.get("ai_analysis") or {}
    threat = ai_analysis.get("threat_assessment") or result.get("threat_assessment") or {}
    risk_assessment = result.get("risk_assessment") or {}

    if risk_score is None:
        risk_score = threat.get("risk_score", risk_assessment.get("risk_score", 0))
    if not threat_level:
        threat_level = threat.get("severity", risk_assessment.get("severity", "unknown"))

    return {
        "risk_score": risk_score or 0,
        "threat_level": str(threat_level or "unknown"),
        "attack_mapping": ai_analysis.get("attack_mapping") or result.get("attack_mapping") or {},
        "neural_insights": ai_analysis.get("neural_insights") or result.get("neural_analysis") or {},
    }


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
