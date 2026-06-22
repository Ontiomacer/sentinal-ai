"""
AI integration endpoints for Sentinel case workspaces.

The suggestion endpoint is grounded in real case, evidence, timeline, entity,
note, and analysis data. When Ollama is available it adds a concise model
summary, but rule suggestions remain deterministic and evidence-driven.
"""

from __future__ import annotations

import json
import logging
import asyncio
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.api.v1.endpoints.cases import get_user_id
from app.models.case import Case, CaseNote, Entity, Evidence, TimelineEvent
from app.models.scan import Scan
from app.services.code_interpreter import CodeInterpreter
from app.services.neural_engine import NeuralEngine, get_neural_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["ai"])


class AISuggestionRequest(BaseModel):
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None
    scan_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    use_ai: bool = True


class AISuggestion(BaseModel):
    id: str
    title: str
    detail: str
    severity: str = "info"
    source: str = "sentinel-rules"
    action: Optional[str] = None
    route: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AISuggestionsResponse(BaseModel):
    generated_at: str
    ai_powered: bool
    health: Dict[str, Any]
    scope: Dict[str, Optional[str]]
    suggestions: List[AISuggestion]
    evidence_count: int = 0
    timeline_count: int = 0
    entity_count: int = 0
    note_count: int = 0
    model_summary: Optional[str] = None


class AIExplainRequest(BaseModel):
    code: str
    scan_id: str
    function_name: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class AIExplainResponse(BaseModel):
    ai_powered: bool
    explanation: str
    health: Dict[str, Any]
    function_name: Optional[str] = None
    interpretation: Dict[str, Any] = Field(default_factory=dict)


def _safe_json(value: Any) -> Dict[str, Any]:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _enum_value(value: Any) -> str:
    return getattr(value, "value", str(value or ""))


def _risk_score(analysis: Dict[str, Any]) -> int:
    candidates = [
        analysis.get("risk_score"),
        (analysis.get("risk_assessment") or {}).get("risk_score"),
        (analysis.get("threat_assessment") or {}).get("risk_score"),
        ((analysis.get("ai_analysis") or {}).get("threat_assessment") or {}).get("risk_score"),
    ]
    for value in candidates:
        if isinstance(value, (int, float)):
            return int(value)
    return 0


def _severity(analysis: Dict[str, Any], score: int) -> str:
    candidates = [
        analysis.get("threat_level"),
        (analysis.get("risk_assessment") or {}).get("severity"),
        (analysis.get("threat_assessment") or {}).get("severity"),
        ((analysis.get("ai_analysis") or {}).get("threat_assessment") or {}).get("severity"),
    ]
    for value in candidates:
        if value:
            return str(value).lower()
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _extract_indicators(analysis: Dict[str, Any]) -> List[Any]:
    neural = analysis.get("neural_analysis") or {}
    ai_analysis = analysis.get("ai_analysis") or {}
    values = [
        neural.get("malware_indicators"),
        ai_analysis.get("malware_indicators"),
        analysis.get("malware_indicators"),
        analysis.get("iocs"),
    ]
    for value in values:
        if isinstance(value, list):
            return value
    return []


async def _load_case_context(
    db: AsyncSession,
    case_id: Optional[str],
    evidence_id: Optional[str],
    scan_id: Optional[str],
    user_id: str,
) -> Dict[str, Any]:
    context: Dict[str, Any] = {
        "case": None,
        "evidence": [],
        "scan": None,
        "timeline": [],
        "entities": [],
        "notes": [],
        "report_count": 0,
    }

    if case_id:
        case_result = await db.execute(
            select(Case).where(Case.id == case_id, Case.user_id == user_id)
        )
        case = case_result.scalar_one_or_none()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        context["case"] = {
            "id": case.id,
            "name": case.name,
            "severity": _enum_value(case.severity),
            "status": _enum_value(case.status),
            "investigator": case.investigator,
            "description": case.description,
        }

        evidence_result = await db.execute(
            select(Evidence).where(Evidence.case_id == case_id)
        )
        context["evidence"] = list(evidence_result.scalars().all())

        timeline_result = await db.execute(
            select(TimelineEvent).where(TimelineEvent.case_id == case_id)
        )
        context["timeline"] = list(timeline_result.scalars().all())

        entity_result = await db.execute(select(Entity).where(Entity.case_id == case_id))
        context["entities"] = list(entity_result.scalars().all())

        note_result = await db.execute(select(CaseNote).where(CaseNote.case_id == case_id))
        context["notes"] = list(note_result.scalars().all())

        reports_dir = Path(case.case_directory or "") / "reports"
        if reports_dir.exists():
            context["report_count"] = len([p for p in reports_dir.iterdir() if p.is_file()])

    if evidence_id:
        evidence_result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        evidence = evidence_result.scalar_one_or_none()
        if evidence and evidence not in context["evidence"]:
            context["evidence"].append(evidence)

    if scan_id:
        scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = scan_result.scalar_one_or_none()
        if scan:
            context["scan"] = scan

    return context


def _serialize_context(context: Dict[str, Any], request_context: Dict[str, Any]) -> Dict[str, Any]:
    evidence_payload = []
    for item in context["evidence"]:
        analysis = _safe_json(item.analysis_result)
        evidence_payload.append(
            {
                "id": item.id,
                "filename": item.original_filename,
                "type": item.evidence_type,
                "status": item.analysis_status,
                "sha256": item.sha256,
                "risk_score": _risk_score(analysis),
                "severity": _severity(analysis, _risk_score(analysis)),
                "indicator_count": len(_extract_indicators(analysis)),
                "analysis": analysis,
            }
        )

    scan_payload = None
    scan = context.get("scan")
    if scan:
        analysis = _safe_json(scan.analysis_result)
        scan_payload = {
            "id": scan.id,
            "filename": scan.filename,
            "status": scan.status,
            "sha256": scan.sha256,
            "risk_score": _risk_score(analysis),
            "severity": _severity(analysis, _risk_score(analysis)),
            "analysis": analysis,
        }

    return {
        "case": context.get("case"),
        "evidence": evidence_payload,
        "scan": scan_payload,
        "timeline_count": len(context["timeline"]),
        "entity_count": len(context["entities"]),
        "note_count": len(context["notes"]),
        "report_count": context["report_count"],
        "request_context": request_context,
    }


def _rule_suggestions(
    payload: Dict[str, Any],
    case_id: Optional[str],
) -> List[AISuggestion]:
    suggestions: List[AISuggestion] = []
    evidence = payload["evidence"]
    high_risk = [item for item in evidence if item["risk_score"] >= 65]
    pending = [item for item in evidence if item["status"] in {"pending", "uploaded", "queued"}]
    analyzed = [item for item in evidence if item["status"] in {"completed", "analyzed"}]
    indicators = sum(item["indicator_count"] for item in evidence)

    if not evidence and case_id:
        suggestions.append(
            AISuggestion(
                id="case-empty-ingest-evidence",
                title="Ingest first evidence item",
                detail="This case has no artifacts yet. Add the APK, triage files, disk image, logs, or PCAP before opening analysis workflows.",
                severity="medium",
                action="Upload evidence",
                route=f"/cases/{case_id}/evidence",
            )
        )

    if pending:
        suggestions.append(
            AISuggestion(
                id="pending-evidence-analysis",
                title="Run analysis on pending evidence",
                detail=f"{len(pending)} evidence item(s) are waiting for analysis. Start neural or deep reverse engineering to populate reports, IOCs, and code views.",
                severity="high",
                action="Analyze evidence",
                route=f"/cases/{case_id}/evidence" if case_id else None,
                metadata={"pending_evidence": [item["id"] for item in pending]},
            )
        )

    if high_risk:
        top = max(high_risk, key=lambda item: item["risk_score"])
        suggestions.append(
            AISuggestion(
                id="high-risk-neural-lab",
                title="Open high-risk artifact in Neural Lab",
                detail=f"{top['filename']} is scored {top['risk_score']} ({top['severity']}). Review suspicious APIs, behavior matrix, and AI chat before report generation.",
                severity=top["severity"],
                action="Open Neural Lab",
                route=f"/cases/{case_id}/neural-lab" if case_id else None,
                metadata={"evidence_id": top["id"], "sha256": top["sha256"]},
            )
        )

    if indicators and payload["entity_count"] == 0:
        suggestions.append(
            AISuggestion(
                id="promote-iocs-to-entities",
                title="Promote extracted IOCs into case entities",
                detail=f"{indicators} indicator(s) are present in analyzed artifacts, but the case entity graph is empty.",
                severity="medium",
                action="Review entities",
                route=f"/cases/{case_id}/entities" if case_id else None,
            )
        )

    if analyzed and payload["report_count"] == 0:
        suggestions.append(
            AISuggestion(
                id="generate-live-report",
                title="Generate a real-time technical report",
                detail="Analyzed evidence exists, but no report files are present in the case workspace. Generate a technical or IOC report to preserve findings.",
                severity="medium",
                action="Generate report",
                route=f"/cases/{case_id}/reports" if case_id else None,
            )
        )

    if payload["timeline_count"] == 0 and evidence:
        suggestions.append(
            AISuggestion(
                id="start-custody-timeline",
                title="Record acquisition timeline",
                detail="Evidence is present but no timeline events have been logged. Add acquisition, triage, and analysis milestones for chain-of-custody clarity.",
                severity="info",
                action="Open timeline",
                route=f"/cases/{case_id}/timeline" if case_id else None,
            )
        )

    if not suggestions:
        suggestions.append(
            AISuggestion(
                id="case-ready-next-pass",
                title="Case workspace is ready for next analysis pass",
                detail="No blocking gaps were detected in the current case data. Continue with deeper reverse engineering, triage import, or reporting as needed.",
                severity="info",
                action="Continue investigation",
                route=f"/cases/{case_id}" if case_id else None,
            )
        )

    return suggestions


@router.get("/health")
async def ai_health(engine: NeuralEngine = Depends(get_neural_engine)) -> Dict[str, Any]:
    """Return Ollama and configured model health."""
    return await engine.health_check()


@router.post("/suggestions", response_model=AISuggestionsResponse)
async def ai_suggestions(
    request: AISuggestionRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id),
    engine: NeuralEngine = Depends(get_neural_engine),
) -> AISuggestionsResponse:
    """Generate case-aware AI and rule-backed investigation suggestions."""
    logger.info(
        "AI SUGGESTIONS REQUEST: case=%s evidence=%s scan=%s",
        request.case_id,
        request.evidence_id,
        request.scan_id,
    )
    context = await _load_case_context(
        db,
        request.case_id,
        request.evidence_id,
        request.scan_id,
        user_id,
    )
    payload = _serialize_context(context, request.context)
    suggestions = _rule_suggestions(payload, request.case_id)

    health = await engine.health_check()
    model_summary: Optional[str] = None
    ai_powered = False

    if request.use_ai and health.get("healthy"):
        try:
            model_summary = await asyncio.wait_for(
                engine.generate_summary(
                    {
                        "case": payload.get("case"),
                        "evidence": [
                            {
                                key: value
                                for key, value in item.items()
                                if key != "analysis"
                            }
                            for item in payload["evidence"]
                        ],
                        "timeline_count": payload["timeline_count"],
                        "entity_count": payload["entity_count"],
                        "note_count": payload["note_count"],
                        "request_context": payload["request_context"],
                    }
                ),
                timeout=8.0,
            )
            ai_powered = True
            suggestions.insert(
                0,
                AISuggestion(
                    id="ollama-investigator-summary",
                    title="AI investigator summary ready",
                    detail=model_summary[:700],
                    severity="info",
                    source="ollama",
                    action="Review AI summary",
                ),
            )
        except Exception as exc:
            logger.warning("AI SUGGESTIONS MODEL SUMMARY FAILED: %s", exc)

    logger.info(
        "AI SUGGESTIONS COMPLETE: case=%s count=%s ai_powered=%s",
        request.case_id,
        len(suggestions),
        ai_powered,
    )
    return AISuggestionsResponse(
        generated_at=datetime.utcnow().isoformat(),
        ai_powered=ai_powered,
        health=health,
        scope={
            "case_id": request.case_id,
            "evidence_id": request.evidence_id,
            "scan_id": request.scan_id,
        },
        suggestions=suggestions,
        evidence_count=len(payload["evidence"]),
        timeline_count=payload["timeline_count"],
        entity_count=payload["entity_count"],
        note_count=payload["note_count"],
        model_summary=model_summary,
    )


@router.post("/explain", response_model=AIExplainResponse)
async def explain_code(
    request: AIExplainRequest,
    engine: NeuralEngine = Depends(get_neural_engine),
) -> AIExplainResponse:
    """Explain code through Ollama when available."""
    logger.info("AI Explain Request: scan=%s, func=%s", request.scan_id, request.function_name)
    health = await engine.health_check()
    interpretation = CodeInterpreter.interpret(
        request.code,
        symbol_name=request.function_name,
        context=request.context,
    )
    if interpretation.get("status") == "unavailable":
        logger.warning("Interpretation unavailable for scan=%s", request.scan_id)
        return AIExplainResponse(
            ai_powered=False,
            explanation="Code interpretation unavailable because no decompiled source was provided.",
            health=health,
            function_name=request.function_name,
            interpretation=interpretation,
        )

    if not health.get("healthy"):
        logger.warning("Ollama unhealthy for explain scan=%s: %s", request.scan_id, health.get("error"))
        return AIExplainResponse(
            ai_powered=False,
            explanation="Ollama is not available. The structured interpretation is rule-based and limited to matched source evidence.",
            health=health,
            function_name=request.function_name,
            interpretation=interpretation,
        )

    try:
        explanation = await engine.explain_code(
            request.code,
            apk_context={
                "scan_id": request.scan_id,
                "function_name": request.function_name,
                **request.context,
            },
        )
        logger.info("AI Explain Success: scan=%s", request.scan_id)
        return AIExplainResponse(
            ai_powered=True,
            explanation=explanation,
            health=health,
            function_name=request.function_name,
            interpretation=interpretation,
        )
    except Exception as exc:
        logger.error("AI Explain Exception: %s", exc, exc_info=True)
        return AIExplainResponse(
            ai_powered=False,
            explanation=f"AI inference failed — {str(exc)}",
            health=health,
            function_name=request.function_name,
            interpretation=interpretation,
        )
