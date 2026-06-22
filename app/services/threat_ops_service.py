"""Persisted, resumable Threat-Ops APK investigation pipeline."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import traceback
import uuid
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.case import Evidence
from app.models.investigation import ThreatOpsInvestigation
from app.services.apk_analyzer import APKAnalyzer
from app.services.threat_scoring import ThreatScoring

logger = logging.getLogger(__name__)


STAGE_DEFINITIONS: List[Dict[str, str]] = [
    {"id": "apk_selected", "label": "APK Selected"},
    {"id": "manifest", "label": "Manifest Analysis"},
    {"id": "permissions", "label": "Permission Analysis"},
    {"id": "components", "label": "Component Analysis"},
    {"id": "certificates", "label": "Certificate Analysis"},
    {"id": "network", "label": "Network Analysis"},
    {"id": "strings", "label": "String Analysis"},
    {"id": "correlation", "label": "IOC Correlation"},
    {"id": "risk", "label": "Risk Assessment"},
    {"id": "executive_summary", "label": "Executive Summary"},
]


def _utcnow() -> datetime:
    return datetime.utcnow()


def _iso(value: Optional[datetime] = None) -> str:
    return (value or _utcnow()).isoformat(timespec="milliseconds") + "Z"


def _loads(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return deepcopy(fallback)
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return deepcopy(fallback)


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def _new_stages() -> List[Dict[str, Any]]:
    return [
        {
            **definition,
            "status": "pending",
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "output_summary": None,
            "error": None,
        }
        for definition in STAGE_DEFINITIONS
    ]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_apk_analyzer(path: Path) -> Dict[str, Any]:
    # APKAnalyzer is async for API compatibility but performs CPU-bound static
    # parsing. Running it in a worker keeps polling/API requests responsive.
    return asyncio.run(APKAnalyzer.analyze(path))


def _unique_strings(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    seen = set()
    result = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _component_values(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for key in ("activities", "services", "receivers", "providers"):
        for component in analysis.get(key, []) or []:
            if isinstance(component, dict):
                result.append(component)
    return result


def _certificate_label(certificate: Dict[str, Any]) -> str:
    return str(
        certificate.get("sha256")
        or certificate.get("subject")
        or certificate.get("serial_number")
        or ""
    )


class ThreatOpsService:
    """Owns Threat-Ops state transitions and real APK-derived outputs."""

    @staticmethod
    def serialize(investigation: ThreatOpsInvestigation) -> Dict[str, Any]:
        result = _loads(investigation.result_json, {})
        result.pop("_source_analysis", None)
        return {
            "id": investigation.id,
            "case_id": investigation.case_id,
            "evidence_id": investigation.evidence_id,
            "status": investigation.status,
            "current_stage": investigation.current_stage,
            "stages": _loads(investigation.stages_json, _new_stages()),
            "result": result,
            "error": _loads(investigation.error_json, None),
            "resume_count": investigation.resume_count,
            "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
            "updated_at": investigation.updated_at.isoformat() if investigation.updated_at else None,
            "started_at": investigation.started_at.isoformat() if investigation.started_at else None,
            "finished_at": investigation.finished_at.isoformat() if investigation.finished_at else None,
        }

    @staticmethod
    async def get_for_evidence(
        db: AsyncSession,
        case_id: str,
        evidence_id: str,
    ) -> Optional[ThreatOpsInvestigation]:
        result = await db.execute(
            select(ThreatOpsInvestigation).where(
                ThreatOpsInvestigation.case_id == case_id,
                ThreatOpsInvestigation.evidence_id == evidence_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def prepare(
        db: AsyncSession,
        evidence: Evidence,
        user_id: str,
        resume: bool = False,
    ) -> Tuple[ThreatOpsInvestigation, bool]:
        investigation = await ThreatOpsService.get_for_evidence(db, evidence.case_id, evidence.id)
        now = _utcnow()

        if investigation is None:
            investigation = ThreatOpsInvestigation(
                id=str(uuid.uuid4()),
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                user_id=user_id,
                status="running",
                current_stage=STAGE_DEFINITIONS[0]["id"],
                stages_json=_dumps(_new_stages()),
                result_json=_dumps({}),
                started_at=now,
                updated_at=now,
            )
            db.add(investigation)
            should_start = True
        elif investigation.status == "completed":
            should_start = False
        elif investigation.status == "running" and not resume:
            should_start = False
        else:
            stages = _loads(investigation.stages_json, _new_stages())
            restart_index = next(
                (index for index, stage in enumerate(stages) if stage.get("status") != "completed"),
                len(stages) - 1,
            )
            for index in range(restart_index, len(stages)):
                if stages[index].get("status") != "completed":
                    stages[index]["status"] = "pending"
                    stages[index]["started_at"] = None
                    stages[index]["finished_at"] = None
                    stages[index]["duration_ms"] = None
                    stages[index]["output_summary"] = None
                    # Keep the previous exact error until this stage starts again.
            investigation.stages_json = _dumps(stages)
            investigation.status = "running"
            investigation.current_stage = stages[restart_index]["id"]
            investigation.error_json = None
            investigation.finished_at = None
            investigation.updated_at = now
            investigation.user_id = user_id
            investigation.resume_count = int(investigation.resume_count or 0) + 1
            should_start = True

        evidence.analysis_status = "running"
        await db.commit()
        await db.refresh(investigation)
        return investigation, should_start

    @staticmethod
    async def run_task(investigation_id: str) -> None:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ThreatOpsInvestigation).where(ThreatOpsInvestigation.id == investigation_id)
            )
            investigation = result.scalar_one_or_none()
            if not investigation:
                logger.error("Threat-Ops investigation %s no longer exists", investigation_id)
                return

            evidence_result = await db.execute(
                select(Evidence).where(Evidence.id == investigation.evidence_id)
            )
            evidence = evidence_result.scalar_one_or_none()
            if not evidence:
                await ThreatOpsService._fail_without_stage(
                    db,
                    investigation,
                    "LookupError",
                    "Evidence no longer exists",
                )
                return

            await ThreatOpsService._run(db, investigation, evidence)

    @staticmethod
    async def _run(
        db: AsyncSession,
        investigation: ThreatOpsInvestigation,
        evidence: Evidence,
    ) -> None:
        stages = _loads(investigation.stages_json, _new_stages())
        result = _loads(investigation.result_json, {})

        for index, stage in enumerate(stages):
            if stage.get("status") == "completed":
                continue

            stage_id = stage["id"]
            started_at = _utcnow()
            started_perf = time.perf_counter()
            stage.update({
                "status": "running",
                "started_at": _iso(started_at),
                "finished_at": None,
                "duration_ms": None,
                "output_summary": None,
                "error": None,
            })
            investigation.status = "running"
            investigation.current_stage = stage_id
            investigation.stages_json = _dumps(stages)
            investigation.updated_at = started_at
            await db.commit()

            logger.info(
                "START_STAGE investigation_id=%s stage=%s timestamp=%s",
                investigation.id,
                stage_id,
                stage["started_at"],
            )

            try:
                output_summary = await ThreatOpsService._execute_stage(stage_id, result, evidence)
                ThreatOpsService._refresh_persisted_views(result, evidence)
                finished_at = _utcnow()
                duration_ms = int((time.perf_counter() - started_perf) * 1000)
                stage.update({
                    "status": "completed",
                    "finished_at": _iso(finished_at),
                    "duration_ms": duration_ms,
                    "output_summary": output_summary,
                    "error": None,
                })
                investigation.result_json = _dumps(result)
                investigation.stages_json = _dumps(stages)
                investigation.updated_at = finished_at
                await db.commit()

                logger.info(
                    "END_STAGE investigation_id=%s stage=%s status=complete timestamp=%s",
                    investigation.id,
                    stage_id,
                    stage["finished_at"],
                )
                logger.info(
                    "DURATION_MS investigation_id=%s stage=%s value=%d",
                    investigation.id,
                    stage_id,
                    duration_ms,
                )
            except Exception as exc:
                finished_at = _utcnow()
                duration_ms = int((time.perf_counter() - started_perf) * 1000)
                traceback_text = traceback.format_exc()
                exact_error = {
                    "stage": stage_id,
                    "exception_type": type(exc).__name__,
                    "exception_message": str(exc),
                    "traceback": traceback_text,
                }
                stage.update({
                    "status": "failed",
                    "finished_at": _iso(finished_at),
                    "duration_ms": duration_ms,
                    "error": exact_error,
                })
                investigation.status = "failed"
                investigation.current_stage = stage_id
                investigation.stages_json = _dumps(stages)
                investigation.result_json = _dumps(result)
                investigation.error_json = _dumps(exact_error)
                investigation.finished_at = finished_at
                investigation.updated_at = finished_at
                evidence.analysis_status = "failed"
                await db.commit()

                logger.error(
                    "EXCEPTION_TYPE investigation_id=%s stage=%s value=%s",
                    investigation.id,
                    stage_id,
                    type(exc).__name__,
                )
                logger.error(
                    "EXCEPTION_MESSAGE investigation_id=%s stage=%s value=%s",
                    investigation.id,
                    stage_id,
                    str(exc),
                )
                logger.error(
                    "TRACEBACK investigation_id=%s stage=%s\n%s",
                    investigation.id,
                    stage_id,
                    traceback_text,
                )
                logger.error(
                    "END_STAGE investigation_id=%s stage=%s status=failed timestamp=%s",
                    investigation.id,
                    stage_id,
                    stage["finished_at"],
                )
                logger.error(
                    "DURATION_MS investigation_id=%s stage=%s value=%d",
                    investigation.id,
                    stage_id,
                    duration_ms,
                )
                return

        finished_at = _utcnow()
        investigation.status = "completed"
        investigation.current_stage = None
        investigation.error_json = None
        investigation.finished_at = finished_at
        investigation.updated_at = finished_at

        public_result = deepcopy(result)
        public_result.pop("_source_analysis", None)
        public_result["pipeline"] = "threat_ops"
        public_result["investigation_id"] = investigation.id
        public_result["investigation_stages"] = stages
        evidence.analysis_result = _dumps(public_result)
        evidence.analysis_status = "complete"
        evidence.analyzed_at = finished_at
        await db.commit()

    @staticmethod
    async def _execute_stage(
        stage_id: str,
        result: Dict[str, Any],
        evidence: Evidence,
    ) -> str:
        path = Path(evidence.file_path)
        analysis = result.setdefault("apk_analysis", {})

        if stage_id == "apk_selected":
            if evidence.evidence_type.lower() != "apk":
                raise ValueError(f"Evidence type is {evidence.evidence_type!r}; Threat-Ops requires APK evidence")
            if path.suffix.lower() != ".apk":
                raise ValueError(f"Selected evidence is not an APK: {path.name}")
            if not path.is_file():
                raise FileNotFoundError(f"APK file does not exist: {path}")
            actual_sha256 = await asyncio.to_thread(_sha256_file, path)
            if actual_sha256.lower() != evidence.sha256.lower():
                raise ValueError(
                    f"SHA-256 mismatch: evidence={evidence.sha256}, file={actual_sha256}"
                )
            result["apk_evidence"] = {
                "filename": evidence.original_filename,
                "file_size": evidence.file_size,
                "file_path": evidence.file_path,
                "sha256": actual_sha256,
            }
            return f"Selected {evidence.original_filename}; SHA-256 verified"

        if stage_id == "manifest":
            source = await asyncio.to_thread(_run_apk_analyzer, path)
            if source.get("analysis_failed") or source.get("error"):
                raise RuntimeError(str(source.get("error") or "Static APK analysis failed"))
            if not source.get("is_apk", True):
                raise ValueError("Selected file did not parse as an APK")
            result["_source_analysis"] = source
            analysis.update({
                key: source.get(key)
                for key in (
                    "package_name",
                    "app_name",
                    "version_name",
                    "version_code",
                    "min_sdk_version",
                    "target_sdk_version",
                    "max_sdk_version",
                    "main_activity",
                    "manifest",
                    "is_valid_apk",
                )
            })
            analysis["sdks"] = [
                {"name": label, "value": source.get(key)}
                for key, label in (
                    ("min_sdk_version", "Minimum SDK"),
                    ("target_sdk_version", "Target SDK"),
                    ("max_sdk_version", "Maximum SDK"),
                )
                if source.get(key) not in (None, "")
            ]
            package_name = str(source.get("package_name") or path.name)
            return f"Parsed manifest for {package_name}"

        source = result.get("_source_analysis")
        if not isinstance(source, dict):
            raise RuntimeError("Persisted APK source analysis is unavailable; resume from Manifest Analysis")

        if stage_id == "permissions":
            permissions = source.get("permissions", []) or []
            analysis["permissions"] = permissions
            dangerous = [item for item in permissions if isinstance(item, dict) and item.get("category") == "dangerous"]
            return f"Analyzed {len(permissions)} permissions; {len(dangerous)} dangerous"

        if stage_id == "components":
            for key in ("activities", "services", "receivers", "providers", "exported_components"):
                analysis[key] = source.get(key, []) or []
            analysis["native_libraries"] = source.get("native_libraries", []) or []
            analysis["files"] = source.get("files", {}) or {}
            components = _component_values(analysis)
            exported = [item for item in components if item.get("is_exported")]
            return f"Mapped {len(components)} components; {len(exported)} exported"

        if stage_id == "certificates":
            certificates = source.get("certificates", []) or []
            analysis["certificates"] = certificates
            analysis["is_signed"] = source.get("is_signed")
            return f"Extracted {len(certificates)} signing certificates"

        if stage_id == "network":
            network = source.get("network_artifacts", {}) or {}
            analysis["urls"] = _unique_strings(source.get("urls", []))
            analysis["domains"] = _unique_strings(source.get("domains", []))
            analysis["ip_addresses"] = _unique_strings(network.get("ip_addresses", []))
            manifest = analysis.get("manifest", {}) or {}
            analysis["uses_cleartext_traffic"] = manifest.get("uses_cleartext_traffic")
            return (
                f"Extracted {len(analysis['urls'])} URLs, {len(analysis['domains'])} domains, "
                f"and {len(analysis['ip_addresses'])} IPs"
            )

        if stage_id == "strings":
            suspicious_strings = ThreatOpsService._suspicious_strings(source)
            analysis["suspicious_strings"] = suspicious_strings
            analysis["api_usage"] = source.get("api_usage", []) or []
            analysis["suspicious_functions"] = source.get("suspicious_functions", []) or []
            return f"Matched {len(suspicious_strings)} suspicious strings from extracted APK strings"

        if stage_id == "correlation":
            correlations = ThreatOpsService._correlate_iocs(analysis)
            result["ioc_correlations"] = correlations
            result["iocs"] = correlations["iocs"]
            return f"Created {len(correlations['relationships'])} IOC relationships"

        if stage_id == "risk":
            risk = ThreatOpsService._calculate_risk(analysis)
            result["risk_assessment"] = risk
            result["threat_assessment"] = risk
            result["risk_score"] = risk["risk_score"]
            result["threat_level"] = risk["severity"]
            return f"Calculated exact static risk score: {risk['risk_score']}/100"

        if stage_id == "executive_summary":
            narrative = ThreatOpsService._build_narrative(analysis, result.get("risk_assessment", {}))
            result["investigation_narrative"] = narrative
            result["executive_summary"] = narrative["executive_summary"]
            result["key_findings"] = narrative["key_findings"]
            result["recommendations"] = narrative["recommendations"]
            return "Generated evidence-grounded executive summary"

        raise ValueError(f"Unknown Threat-Ops stage: {stage_id}")

    @staticmethod
    def _suspicious_strings(source: Dict[str, Any]) -> List[Dict[str, Any]]:
        strings = _unique_strings(source.get("strings", []))
        tokens = {
            token.lower()
            for pattern in ThreatScoring.BEHAVIORAL_PATTERNS.values()
            for token in pattern.get("tokens", [])
        }
        tokens.update(token.lower() for token in ThreatScoring.URL_SUSPICION_TOKENS)
        matches: List[Dict[str, Any]] = []
        for value in strings:
            lowered = value.lower()
            matched = sorted(token for token in tokens if token and token in lowered)
            if matched:
                matches.append({"value": value, "matched_tokens": matched})
            if len(matches) >= 100:
                break
        return matches

    @staticmethod
    def _correlate_iocs(analysis: Dict[str, Any]) -> Dict[str, Any]:
        package_name = str(analysis.get("package_name") or "").strip()
        urls = _unique_strings(analysis.get("urls", []))
        domains = _unique_strings(analysis.get("domains", []))
        ips = _unique_strings(analysis.get("ip_addresses", []))
        certificates = [
            _certificate_label(item)
            for item in analysis.get("certificates", []) or []
            if isinstance(item, dict) and _certificate_label(item)
        ]
        relationships: List[Dict[str, str]] = []

        def relate(source_type: str, source_value: str, target_type: str, target_value: str, relation: str) -> None:
            relationships.append({
                "source_type": source_type,
                "source_value": source_value,
                "target_type": target_type,
                "target_value": target_value,
                "relation": relation,
            })

        root_type = "package" if package_name else "apk"
        root_value = package_name
        for target_type, values, relation in (
            ("domain", domains, "references domain"),
            ("url", urls, "references URL"),
            ("ip", ips, "references IP"),
            ("certificate", certificates, "signed by"),
        ):
            for value in values:
                relate(root_type, root_value, target_type, value, relation)

        domain_lookup = {value.lower(): value for value in domains}
        for url in urls:
            try:
                hostname = (urlparse(url).hostname or "").lower()
            except ValueError:
                hostname = ""
            if hostname and hostname in domain_lookup:
                relate("url", url, "domain", domain_lookup[hostname], "resolves host")
            for ip in ips:
                if ip in url:
                    relate("url", url, "ip", ip, "contains address")

        return {
            "iocs": {
                "package_names": [package_name] if package_name else [],
                "domains": domains,
                "urls": urls,
                "ips": ips,
                "certificates": certificates,
            },
            "relationships": relationships,
        }

    @staticmethod
    def _calculate_risk(analysis: Dict[str, Any]) -> Dict[str, Any]:
        permissions = [item for item in analysis.get("permissions", []) or [] if isinstance(item, dict)]
        dangerous_permissions = [
            str(item.get("name"))
            for item in permissions
            if item.get("category") == "dangerous"
            or str(item.get("name", "")).split(".")[-1].upper() in ThreatScoring.PERMISSION_WEIGHTS
        ]
        exported_components = [
            str(item.get("name"))
            for item in _component_values(analysis)
            if item.get("is_exported")
        ]
        cleartext = analysis.get("uses_cleartext_traffic") is True
        suspicious_domains = [
            domain
            for domain in _unique_strings(analysis.get("domains", []))
            if any(token in domain.lower() for token in ThreatScoring.URL_SUSPICION_TOKENS)
        ]
        certificates = [item for item in analysis.get("certificates", []) or [] if isinstance(item, dict)]
        certificate_issues: List[str] = []
        if analysis.get("is_signed") is False:
            certificate_issues.append("APK is not signed")
        for certificate in certificates:
            subject = str(certificate.get("subject") or "").strip()
            issuer = str(certificate.get("issuer") or "").strip()
            if subject and issuer and subject == issuer:
                certificate_issues.append(f"Self-signed certificate: {_certificate_label(certificate)}")

        source_strings = [
            str(item.get("value"))
            for item in analysis.get("suspicious_strings", []) or []
            if isinstance(item, dict)
        ]
        obfuscation_tokens = {
            token
            for token in ThreatScoring.BEHAVIORAL_PATTERNS["obfuscation"]["tokens"]
            if any(token.lower() in value.lower() for value in source_strings)
        }

        breakdown = {
            "dangerous_permissions": min(24, len(dangerous_permissions) * 3),
            "exported_components": min(18, len(exported_components) * 3),
            "cleartext_traffic": 12 if cleartext else 0,
            "suspicious_domains": min(20, len(suspicious_domains) * 5),
            "certificates": min(20, (15 if analysis.get("is_signed") is False else 0) + max(0, len(certificate_issues) - (1 if analysis.get("is_signed") is False else 0)) * 4),
            "obfuscation_indicators": min(12, len(obfuscation_tokens) * 3),
        }
        score = min(100, sum(breakdown.values()))
        severity = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 25 else "LOW"
        calculations = [
            {
                "factor": "Dangerous permissions",
                "formula": "min(24, count × 3)",
                "count": len(dangerous_permissions),
                "points": breakdown["dangerous_permissions"],
                "evidence": dangerous_permissions,
            },
            {
                "factor": "Exported components",
                "formula": "min(18, count × 3)",
                "count": len(exported_components),
                "points": breakdown["exported_components"],
                "evidence": exported_components,
            },
            {
                "factor": "Cleartext traffic",
                "formula": "12 when usesCleartextTraffic=true",
                "count": 1 if cleartext else 0,
                "points": breakdown["cleartext_traffic"],
                "evidence": ["android:usesCleartextTraffic=true"] if cleartext else [],
            },
            {
                "factor": "Suspicious domains",
                "formula": "min(20, count × 5)",
                "count": len(suspicious_domains),
                "points": breakdown["suspicious_domains"],
                "evidence": suspicious_domains,
            },
            {
                "factor": "Certificate issues",
                "formula": "unsigned=15; each self-signed certificate=4; capped at 20",
                "count": len(certificate_issues),
                "points": breakdown["certificates"],
                "evidence": certificate_issues,
            },
            {
                "factor": "Obfuscation indicators",
                "formula": "min(12, unique matched tokens × 3)",
                "count": len(obfuscation_tokens),
                "points": breakdown["obfuscation_indicators"],
                "evidence": sorted(obfuscation_tokens),
            },
        ]
        findings = [
            f"{item['factor']}: {item['points']} points from {item['count']} observed item(s)."
            for item in calculations
            if item["points"] > 0
        ]
        return {
            "risk_score": score,
            "severity": severity,
            "score_breakdown": breakdown,
            "score_calculation": calculations,
            "findings": findings,
            "summary": f"Exact static risk calculation: {' + '.join(str(value) for value in breakdown.values())} = {score}/100 ({severity}).",
            "indicators": [
                {"type": item["factor"], "matched_values": item["evidence"], "score": item["points"]}
                for item in calculations
                if item["points"] > 0
            ],
        }

    @staticmethod
    def _build_narrative(analysis: Dict[str, Any], risk: Dict[str, Any]) -> Dict[str, Any]:
        package_name = str(analysis.get("package_name") or "Unknown package")
        permissions = analysis.get("permissions", []) or []
        components = _component_values(analysis)
        domains = _unique_strings(analysis.get("domains", []))
        urls = _unique_strings(analysis.get("urls", []))
        ips = _unique_strings(analysis.get("ip_addresses", []))
        score = int(risk.get("risk_score") or 0)
        severity = str(risk.get("severity") or "LOW")
        breakdown = risk.get("score_breakdown", {}) or {}
        recommendations: List[str] = []
        if breakdown.get("dangerous_permissions", 0):
            recommendations.append("Validate every scored dangerous permission against required application functionality.")
        if breakdown.get("exported_components", 0):
            recommendations.append("Restrict or permission-protect the exported components identified in this investigation.")
        if breakdown.get("cleartext_traffic", 0):
            recommendations.append("Disable cleartext traffic and enforce TLS through Android network security configuration.")
        if breakdown.get("suspicious_domains", 0):
            recommendations.append("Block and investigate the scored domains and their associated extracted URLs.")
        if breakdown.get("certificates", 0):
            recommendations.append("Verify the APK signing identity and certificate provenance before deployment.")
        if breakdown.get("obfuscation_indicators", 0):
            recommendations.append("Perform focused reverse engineering on the matched obfuscation indicators.")

        return {
            "executive_summary": (
                f"{package_name} received a {severity} static risk score of {score}/100. "
                f"The APK declared {len(permissions)} permissions and {len(components)} components; "
                f"analysis extracted {len(urls)} URLs, {len(domains)} domains, and {len(ips)} IP addresses."
            ),
            "key_findings": list(risk.get("findings", []) or []),
            "threat_assessment": str(risk.get("summary") or ""),
            "recommendations": recommendations,
            "risk_score": score,
            "severity": severity,
        }

    @staticmethod
    def _refresh_persisted_views(result: Dict[str, Any], evidence: Evidence) -> None:
        analysis = result.get("apk_analysis", {}) or {}
        risk = result.get("risk_assessment", {}) or {}
        suspicious_indicators: List[Any] = []
        suspicious_indicators.extend(analysis.get("suspicious_strings", []) or [])
        suspicious_indicators.extend(analysis.get("suspicious_functions", []) or [])
        suspicious_indicators.extend(risk.get("indicators", []) or [])
        result["investigation_evidence"] = {
            "package_name": analysis.get("package_name"),
            "sha256": evidence.sha256,
            "permissions": analysis.get("permissions", []) or [],
            "certificates": analysis.get("certificates", []) or [],
            "suspicious_indicators": suspicious_indicators,
            "urls": analysis.get("urls", []) or [],
            "domains": analysis.get("domains", []) or [],
            "ips": analysis.get("ip_addresses", []) or [],
        }
        result["investigation_graph"] = ThreatOpsService._build_graph(result, evidence)

    @staticmethod
    def _build_graph(result: Dict[str, Any], evidence: Evidence) -> Dict[str, Any]:
        analysis = result.get("apk_analysis", {}) or {}
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        root_id = f"apk:{evidence.id}"
        nodes.append({
            "id": root_id,
            "type": "apk",
            "label": analysis.get("package_name") or evidence.original_filename,
            "value": evidence.sha256,
        })

        def add(kind: str, value: str, metadata: Any, relation: str) -> str:
            node_id = f"{kind}:{hashlib.sha1((kind + ':' + value).encode('utf-8')).hexdigest()[:16]}"
            if not any(node["id"] == node_id for node in nodes):
                nodes.append({"id": node_id, "type": kind, "label": value, "value": value, "metadata": metadata})
                edges.append({"source": root_id, "target": node_id, "relation": relation})
            return node_id

        for permission in analysis.get("permissions", []) or []:
            if isinstance(permission, dict) and permission.get("name"):
                add("permission", str(permission["name"]), permission, "declares")
        for key, kind in (("activities", "activity"), ("services", "service"), ("receivers", "receiver"), ("providers", "provider")):
            for component in analysis.get(key, []) or []:
                if isinstance(component, dict) and component.get("name"):
                    add(kind, str(component["name"]), component, "declares")
        for certificate in analysis.get("certificates", []) or []:
            if isinstance(certificate, dict) and _certificate_label(certificate):
                add("certificate", _certificate_label(certificate), certificate, "signed by")
        for key, kind in (("domains", "domain"), ("urls", "url"), ("ip_addresses", "ip")):
            for value in _unique_strings(analysis.get(key, [])):
                add(kind, value, value, "references")
        for item in analysis.get("suspicious_strings", []) or []:
            if isinstance(item, dict) and item.get("value"):
                add("string", str(item["value"]), item, "contains")
        for sdk in analysis.get("sdks", []) or []:
            if isinstance(sdk, dict) and sdk.get("name"):
                add("sdk", f"{sdk['name']}: {sdk.get('value')}", sdk, "targets")
        for finding in (result.get("risk_assessment", {}) or {}).get("findings", []) or []:
            add("finding", str(finding), finding, "produced")

        id_by_type_value = {
            (node["type"], str(node.get("value") or node.get("label") or "")): node["id"]
            for node in nodes
        }
        package_name = str(analysis.get("package_name") or "")
        for relation in (result.get("ioc_correlations", {}) or {}).get("relationships", []) or []:
            source_id = root_id if relation.get("source_type") in {"package", "apk"} and relation.get("source_value") in {"", package_name} else id_by_type_value.get((str(relation.get("source_type")), str(relation.get("source_value"))))
            target_id = id_by_type_value.get((str(relation.get("target_type")), str(relation.get("target_value"))))
            if source_id and target_id and not any(edge["source"] == source_id and edge["target"] == target_id and edge["relation"] == relation.get("relation") for edge in edges):
                edges.append({"source": source_id, "target": target_id, "relation": relation.get("relation")})

        return {"nodes": nodes, "edges": edges}

    @staticmethod
    async def _fail_without_stage(
        db: AsyncSession,
        investigation: ThreatOpsInvestigation,
        exception_type: str,
        exception_message: str,
    ) -> None:
        error = {
            "stage": investigation.current_stage,
            "exception_type": exception_type,
            "exception_message": exception_message,
            "traceback": "",
        }
        investigation.status = "failed"
        investigation.error_json = _dumps(error)
        investigation.finished_at = _utcnow()
        investigation.updated_at = investigation.finished_at
        await db.commit()
