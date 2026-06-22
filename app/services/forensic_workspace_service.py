import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.case import Case, CaseNote, Entity, Evidence, TimelineEvent
from app.services.timeline_service import TimelineService

logger = logging.getLogger(__name__)


class ForensicWorkspaceService:
    """Real filesystem and report services for the case workstation."""

    CSI_DIRECTORIES = [
        "evidence",
        "extracted",
        "reports",
        "timeline",
        "intelligence",
        "memory",
        "network",
        "ai_findings",
        "logs",
        "triage",
    ]

    @staticmethod
    def ensure_case_layout(case: Case) -> Path:
        case_dir = Path(case.case_directory or (Path(settings.storage_dir) / "cases" / case.id))
        case_dir.mkdir(parents=True, exist_ok=True)

        for dirname in ForensicWorkspaceService.CSI_DIRECTORIES:
            (case_dir / dirname).mkdir(parents=True, exist_ok=True)

        metadata_file = case_dir / "case_metadata.json"
        if not metadata_file.exists():
            metadata = {
                "case_id": case.id,
                "name": case.name,
                "investigator": case.investigator,
                "client": case.client_name,
                "severity": getattr(case.severity, "value", case.severity),
                "status": getattr(case.status, "value", case.status),
                "created_at": case.created_at.isoformat() if case.created_at else None,
            }
            metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        return case_dir

    @staticmethod
    def _safe_relative(root: Path, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            return path.name

    @staticmethod
    def _file_sha256(path: Path) -> Optional[str]:
        if not path.is_file():
            return None

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _build_tree(
        root: Path,
        path: Path,
        evidence_by_path: Dict[str, Evidence],
        depth: int = 0,
        max_depth: int = 6,
    ) -> Dict[str, Any]:
        stat = path.stat()
        relative_path = ForensicWorkspaceService._safe_relative(root, path)
        evidence = evidence_by_path.get(str(path.resolve()))

        node: Dict[str, Any] = {
            "id": hashlib.sha1(f"{relative_path}:{stat.st_mtime_ns}".encode("utf-8")).hexdigest()[:16],
            "name": path.name if depth else root.name,
            "relative_path": "." if depth == 0 else relative_path,
            "kind": "directory" if path.is_dir() else "file",
            "size": stat.st_size if path.is_file() else 0,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "evidence_id": evidence.id if evidence else None,
            "evidence_type": evidence.evidence_type if evidence else None,
            "sha256": evidence.sha256 if evidence else None,
            "children": [],
        }

        if path.is_dir() and depth < max_depth:
            children: List[Dict[str, Any]] = []
            for child in sorted(path.iterdir(), key=lambda item: (item.is_file(), item.name.lower())):
                children.append(
                    ForensicWorkspaceService._build_tree(root, child, evidence_by_path, depth + 1, max_depth)
                )
            node["children"] = children

        return node

    @staticmethod
    async def get_filesystem(db: AsyncSession, case: Case) -> Dict[str, Any]:
        case_dir = ForensicWorkspaceService.ensure_case_layout(case)

        result = await db.execute(select(Evidence).where(Evidence.case_id == case.id))
        evidence_items = result.scalars().all()
        evidence_by_path = {
            str(Path(item.file_path).resolve()): item
            for item in evidence_items
            if item.file_path
        }

        tree = ForensicWorkspaceService._build_tree(case_dir, case_dir, evidence_by_path)
        expected_dirs = []
        for dirname in ForensicWorkspaceService.CSI_DIRECTORIES:
            directory = case_dir / dirname
            files = [entry for entry in directory.rglob("*") if entry.is_file()] if directory.exists() else []
            expected_dirs.append({
                "name": dirname,
                "relative_path": dirname,
                "exists": directory.exists(),
                "file_count": len(files),
                "size": sum(file.stat().st_size for file in files),
            })

        all_files = [entry for entry in case_dir.rglob("*") if entry.is_file()]
        directory_count = sum(1 for entry in case_dir.rglob("*") if entry.is_dir()) + 1
        logger.info(
            "Loaded case filesystem case_id=%s directories=%s files=%s evidence_items=%s",
            case.id,
            directory_count,
            len(all_files),
            len(evidence_items),
        )
        return {
            "case_id": case.id,
            "root_path": str(case_dir),
            "tree": tree,
            "expected_directories": expected_dirs,
            "totals": {
                "directories": directory_count,
                "files": len(all_files),
                "bytes": sum(file.stat().st_size for file in all_files),
                "evidence_items": len(evidence_items),
            },
        }

    @staticmethod
    async def get_triage_drives(case: Case) -> Dict[str, Any]:
        case_dir = ForensicWorkspaceService.ensure_case_layout(case)
        roots = [case_dir / "triage"]

        configured = os.environ.get("SENTINEL_TRIAGE_ROOTS", "")
        for value in configured.replace(";", os.pathsep).split(os.pathsep):
            if value.strip():
                roots.append(Path(value.strip()))

        drives = []
        for root in roots:
            exists = root.exists()
            is_dir = root.is_dir() if exists else False
            files = [entry for entry in root.rglob("*") if entry.is_file()] if is_dir else []
            drives.append({
                "name": root.name or str(root),
                "path": str(root),
                "status": "ready" if is_dir else "missing",
                "is_case_triage": root == case_dir / "triage",
                "file_count": len(files),
                "size": sum(file.stat().st_size for file in files),
                "last_seen": datetime.utcnow().isoformat(),
                "files": [
                    {
                        "name": f.name,
                        "path": str(f.resolve()).replace("\\", "/"),
                        "size": f.stat().st_size,
                        "modified_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                    }
                    for f in files
                ]
            })

        logger.info("Loaded triage drives case_id=%s drives=%s configured=%s", case.id, len(drives), bool(configured))
        return {
            "case_id": case.id,
            "drives": drives,
            "configured_roots_env": "SENTINEL_TRIAGE_ROOTS",
        }

    @staticmethod
    async def list_reports(case: Case) -> Dict[str, Any]:
        case_dir = ForensicWorkspaceService.ensure_case_layout(case)
        reports_dir = case_dir / "reports"
        reports = []

        for path in sorted(reports_dir.glob("*"), key=lambda item: item.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            stat = path.stat()
            stem_parts = path.stem.split("_")
            report_type = stem_parts[-2] if len(stem_parts) >= 3 and stem_parts[-1] == "report" else path.stem
            reports.append({
                "id": hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()[:16],
                "name": path.name,
                "report_type": report_type,
                "relative_path": ForensicWorkspaceService._safe_relative(case_dir, path),
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "sha256": ForensicWorkspaceService._file_sha256(path),
            })

        logger.info("Listed case reports case_id=%s reports=%s", case.id, len(reports))
        return {
            "case_id": case.id,
            "reports": reports,
            "count": len(reports),
        }

    @staticmethod
    def _safe_json(value: Optional[str]) -> Dict[str, Any]:
        if not value:
            return {}
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _collect_iocs(value: Any, found: Dict[str, set]) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                lowered = key.lower()
                if lowered in {"url", "urls"}:
                    targets = nested if isinstance(nested, list) else [nested]
                    found["urls"].update(str(item) for item in targets if item)
                elif lowered in {"domain", "domains"}:
                    targets = nested if isinstance(nested, list) else [nested]
                    found["domains"].update(str(item) for item in targets if item)
                elif lowered in {"ip", "ips", "ip_address", "ip_addresses"}:
                    targets = nested if isinstance(nested, list) else [nested]
                    found["ip_addresses"].update(str(item) for item in targets if item)
                else:
                    ForensicWorkspaceService._collect_iocs(nested, found)
        elif isinstance(value, list):
            for item in value:
                ForensicWorkspaceService._collect_iocs(item, found)

    @staticmethod
    def _analysis_sections(item: Evidence, analysis: Dict[str, Any]) -> List[str]:
        risk = analysis.get("risk_assessment") or analysis.get("threat_assessment") or {}
        classification = analysis.get("threat_classification") or {}
        fraud = analysis.get("fraud_intent") or {}
        attack_flow = analysis.get("attack_flow") or {}
        recommendations = analysis.get("recommendations") or []
        apk = analysis.get("apk_analysis") if isinstance(analysis.get("apk_analysis"), dict) else analysis

        lines = [
            f"### {item.original_filename}",
            f"- Analysis status: {item.analysis_status}",
            f"- SHA256: {item.sha256}",
            f"- Package: {apk.get('package_name', 'N/A')}",
            f"- App name: {apk.get('app_name', 'N/A')}",
            f"- Risk score: {risk.get('risk_score', 0)}/100",
            f"- Severity: {risk.get('severity', 'UNKNOWN')}",
            f"- Technical risk: {risk.get('technical_risk_score', risk.get('risk_score', 0))}/100",
            f"- Fraud risk: {risk.get('fraud_risk_score', 0)}/100",
            f"- Threat type: {classification.get('threat_type', 'Unknown')}",
            f"- Threat family: {classification.get('threat_family', 'No high-confidence family identified')}",
            f"- Classification confidence: {classification.get('confidence', 0)}%",
        ]

        if classification.get("evidence"):
            lines.append("- Classification evidence:")
            lines.extend(f"  - {evidence}" for evidence in classification.get("evidence", [])[:8])

        objectives = fraud.get("objectives", [])
        lines.append("- Fraud intent:")
        if objectives:
            for objective in objectives[:6]:
                lines.append(
                    f"  - {objective.get('objective')} ({objective.get('confidence', 0)}%): "
                    f"{objective.get('fraud_impact', '')}"
                )
                for evidence in objective.get("evidence", [])[:4]:
                    lines.append(f"    - Evidence: {evidence}")
        else:
            lines.append("  - Insufficient evidence for a specific fraud objective.")

        steps = attack_flow.get("steps", [])
        lines.append("- Attack flow reconstruction:")
        if steps:
            for step in steps[:10]:
                lines.append(f"  - {step.get('order')}. {step.get('title')} ({step.get('confidence', 0)}%)")
                for evidence in step.get("evidence", [])[:4]:
                    lines.append(f"    - Evidence: {evidence}")
        else:
            lines.append("  - Insufficient evidence to reconstruct an attack flow.")

        if recommendations:
            lines.append("- Recommendations:")
            for rec in recommendations[:8]:
                lines.append(f"  - [{rec.get('priority', 'info')}] {rec.get('action')}")

        lines.append("")
        return lines

    @staticmethod
    async def generate_report(
        db: AsyncSession,
        case: Case,
        user_id: str,
        report_type: str,
    ) -> Dict[str, Any]:
        case_dir = ForensicWorkspaceService.ensure_case_layout(case)
        reports_dir = case_dir / "reports"

        evidence = (await db.execute(select(Evidence).where(Evidence.case_id == case.id))).scalars().all()
        events = (await db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case.id))).scalars().all()
        entities = (await db.execute(select(Entity).where(Entity.case_id == case.id))).scalars().all()
        notes = (await db.execute(select(CaseNote).where(CaseNote.case_id == case.id))).scalars().all()

        report_type = report_type.lower()
        if report_type not in {"executive", "technical", "timeline", "ioc"}:
            raise ValueError("report_type must be executive, technical, timeline, or ioc")

        now = datetime.utcnow()
        lines = [
            f"# Sentinel AI {report_type.title()} Report",
            "",
            f"- Case: {case.name} ({case.id})",
            f"- Investigator: {case.investigator}",
            f"- Client: {case.client_name or 'N/A'}",
            f"- Severity: {getattr(case.severity, 'value', case.severity)}",
            f"- Status: {getattr(case.status, 'value', case.status)}",
            f"- Generated: {now.isoformat()} UTC",
            "",
        ]

        if report_type == "executive":
            lines.extend([
                "## Investigation Snapshot",
                f"- Evidence items: {len(evidence)}",
                f"- Timeline events: {len(events)}",
                f"- Tracked entities: {len(entities)}",
                f"- Investigator notes: {len(notes)}",
                "",
                "## Current Evidence State",
            ])
            for item in evidence:
                lines.append(f"- {item.original_filename}: {item.analysis_status}, SHA256 {item.sha256}")
            lines.extend(["", "## Threat, Fraud, And Risk Summary"])
            for item in evidence:
                analysis = ForensicWorkspaceService._safe_json(item.analysis_result)
                if analysis:
                    lines.extend(ForensicWorkspaceService._analysis_sections(item, analysis))
                else:
                    lines.append(f"### {item.original_filename}")
                    lines.append("- No analysis result stored yet.")
                    lines.append("")

        elif report_type == "technical":
            lines.append("## Evidence Technical Inventory")
            for item in evidence:
                analysis = ForensicWorkspaceService._safe_json(item.analysis_result)
                lines.extend([
                    f"### {item.original_filename}",
                    f"- Type: {item.evidence_type}",
                    f"- Size: {item.file_size} bytes",
                    f"- Path: {item.file_path}",
                    f"- MD5: {item.md5 or 'N/A'}",
                    f"- SHA1: {item.sha1 or 'N/A'}",
                    f"- SHA256: {item.sha256}",
                    f"- Analysis status: {item.analysis_status}",
                    f"- Analysis keys: {', '.join(sorted(analysis.keys())) if analysis else 'none'}",
                    "",
                ])
                if analysis:
                    lines.extend(ForensicWorkspaceService._analysis_sections(item, analysis))

        elif report_type == "timeline":
            lines.append("## Investigation Timeline")
            for event in sorted(events, key=lambda item: item.created_at or now):
                lines.append(
                    f"- {event.created_at.isoformat() if event.created_at else 'unknown'} "
                    f"[{event.event_type}] {event.title}: {event.description or ''}"
                )

        elif report_type == "ioc":
            found = {"urls": set(), "domains": set(), "ip_addresses": set()}
            for entity in entities:
                entity_type = getattr(entity.entity_type, "value", entity.entity_type)
                if entity_type == "url":
                    found["urls"].add(entity.value)
                elif entity_type == "domain":
                    found["domains"].add(entity.value)
                elif entity_type == "ip_address":
                    found["ip_addresses"].add(entity.value)
            for item in evidence:
                ForensicWorkspaceService._collect_iocs(
                    ForensicWorkspaceService._safe_json(item.analysis_result),
                    found,
                )

            lines.append("## Indicators Of Compromise")
            for label, values in found.items():
                lines.append(f"### {label.replace('_', ' ').title()}")
                if values:
                    lines.extend(f"- {value}" for value in sorted(values))
                else:
                    lines.append("- None discovered in current case data")
                lines.append("")

        filename = f"{now.strftime('%Y%m%d_%H%M%S')}_{report_type}_report.md"
        path = reports_dir / filename
        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info(
            "Generated case report case_id=%s report_type=%s evidence=%s events=%s entities=%s notes=%s file=%s",
            case.id,
            report_type,
            len(evidence),
            len(events),
            len(entities),
            len(notes),
            path,
        )

        await TimelineService.create_auto_event(
            db=db,
            case_id=case.id,
            user_id=user_id,
            event_type="report",
            title=f"Report Generated: {report_type.title()}",
            description=f"{filename} written to case reports directory",
            metadata={"report_type": report_type, "filename": filename},
        )

        stat = path.stat()
        return {
            "id": hashlib.sha1(str(path.resolve()).encode("utf-8")).hexdigest()[:16],
            "name": path.name,
            "report_type": report_type,
            "relative_path": ForensicWorkspaceService._safe_relative(case_dir, path),
            "size": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "sha256": ForensicWorkspaceService._file_sha256(path),
        }
