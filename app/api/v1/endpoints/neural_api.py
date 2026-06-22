"""
Neural Lab API — Core intelligence endpoints for the AI malware cognition engine.

Endpoints:
  POST /api/v1/neural/analyze          — Trigger full analysis pipeline
  GET  /api/v1/neural/summary/{scan_id} — AI threat cognition summary
  GET  /api/v1/neural/risk/{scan_id}    — Risk scoring with severity/confidence/category
  POST /api/v1/neural/explain           — Explain a function/code block
  POST /api/v1/neural/chat              — Streaming AI chat with investigation context
  GET  /api/v1/neural/health            — Ollama health check
  GET  /api/v1/neural/pipeline/{scan_id} — Pipeline status
  POST /api/v1/neural/report            — Generate investigation report

Investigation CRUD:
  GET    /api/v1/neural/investigations
  POST   /api/v1/neural/investigations
  GET    /api/v1/neural/investigations/{id}
  PUT    /api/v1/neural/investigations/{id}
  DELETE /api/v1/neural/investigations/{id}
  POST   /api/v1/neural/investigations/{id}/notes
  GET    /api/v1/neural/investigations/{id}/notes
  POST   /api/v1/neural/investigations/{id}/bookmarks
  GET    /api/v1/neural/investigations/{id}/bookmarks
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel
import json
import logging
import asyncio
import traceback

from app.database import get_db
from app.models.scan import Scan
from app.config import settings
from app.services.neural_engine import get_neural_engine
from app.services.investigation_service import InvestigationService
from app.services.threat_scoring import ThreatScoring
from app.services.attack_mapper import AttackMapper
from app.services.intelligence_engine import IntelligenceEngine
from app.services.code_interpreter import CodeInterpreter
from app.services.analyst_workflow import AnalystWorkflow

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Request/Response schemas
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    scan_id: str

class ExplainRequest(BaseModel):
    scan_id: str
    code: str
    function_name: Optional[str] = None
    context_hint: Optional[str] = None

class ChatRequest(BaseModel):
    scan_id: str
    message: str
    stream: bool = True

class ReportRequest(BaseModel):
    scan_id: str
    report_type: str = "executive"  # executive, technical, ioc, attack, fraud, cognition

class InvestigationCreateRequest(BaseModel):
    scan_id: str
    title: str = "Untitled Investigation"
    description: str = ""
    analyst_name: str = "Analyst"

class InvestigationUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    analyst_name: Optional[str] = None
    threat_level: Optional[str] = None
    risk_score: Optional[float] = None
    malware_family: Optional[str] = None

class NoteCreateRequest(BaseModel):
    content: str
    note_type: str = "general"
    tags: List[str] = []

class BookmarkCreateRequest(BaseModel):
    target_type: str
    target_id: str
    label: str = ""
    notes: str = ""
    severity: str = "medium"

class BridgeEvidenceRequest(BaseModel):
    case_id: str
    evidence_id: str


# ---------------------------------------------------------------------------
# Helper: load analysis data for a scan
# ---------------------------------------------------------------------------

async def _get_scan_analysis(scan_id: str, db: AsyncSession) -> tuple:
    """Load scan and its analysis data. Returns (scan, analysis_data)."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    analysis_data = {}
    if scan.analysis_result:
        try:
            analysis_data = json.loads(scan.analysis_result) if isinstance(
                scan.analysis_result, str
            ) else scan.analysis_result
        except (json.JSONDecodeError, TypeError):
            pass

    return scan, analysis_data


def _build_ai_context(analysis_data: dict, scan: Any = None) -> dict:
    """Build condensed context for AI prompts from analysis data."""
    ctx: Dict[str, Any] = {}
    apk_data = analysis_data.get("apk_analysis") if isinstance(analysis_data.get("apk_analysis"), dict) else analysis_data

    # Basic APK info
    for key in [
        "package_name", "app_name", "version_name", "version_code",
        "min_sdk_version", "target_sdk_version",
    ]:
        if key in apk_data:
            ctx[key] = apk_data[key]

    # Permissions
    permissions = apk_data.get("permissions", [])
    if permissions:
        ctx["permissions"] = [
            p.get("name", p) if isinstance(p, dict) else str(p)
            for p in permissions[:30]
        ]

    # Risk assessment
    risk = (
        analysis_data.get("risk_assessment")
        or (analysis_data.get("intelligence") or {}).get("risk_assessment")
        or analysis_data.get("threat_assessment")
    )
    if risk:
        ctx["risk_assessment"] = {
            "risk_score": risk.get("risk_score"),
            "severity": risk.get("severity"),
            "summary": risk.get("summary"),
            "findings": risk.get("findings", [])[:15],
            "contributors": risk.get("contributors", [])[:10],
            "technical_risk_score": risk.get("technical_risk_score"),
            "fraud_risk_score": risk.get("fraud_risk_score"),
        }

    if analysis_data.get("threat_classification"):
        ctx["threat_classification"] = analysis_data["threat_classification"]

    if analysis_data.get("fraud_intent"):
        fraud = analysis_data["fraud_intent"]
        ctx["fraud_intent"] = {
            "summary": fraud.get("summary"),
            "objectives": fraud.get("objectives", [])[:8],
        }

    if analysis_data.get("attack_flow"):
        flow = analysis_data["attack_flow"]
        ctx["attack_flow"] = {
            "summary": flow.get("summary"),
            "steps": flow.get("steps", [])[:8],
        }

    # Neural analysis
    neural = analysis_data.get("neural_analysis", {})
    if neural:
        ctx["suspicious_functions"] = [
            {"name": f.get("name"), "class": f.get("class_name"),
             "risk_score": f.get("risk_score"), "indicators": f.get("threat_indicators", [])}
            for f in neural.get("suspicious_functions", [])[:20]
        ]
        ctx["malware_indicators"] = [
            {"type": i.get("type"), "value": i.get("value", "")[:100],
             "severity": i.get("severity")}
            for i in neural.get("malware_indicators", [])[:20]
        ]
        ctx["behavioral_patterns"] = [
            {"pattern": p.get("pattern_name"), "confidence": p.get("confidence"),
             "fraud_indicators": p.get("fraud_indicators", [])}
            for p in neural.get("behavioral_patterns", [])[:10]
        ]
        stats = neural.get("statistics", {})
        if stats:
            ctx["analysis_statistics"] = stats

    # YARA results
    yara_results = analysis_data.get("yara_scan")
    if yara_results:
        ctx["yara_matches"] = yara_results.get("matches", [])[:10]

    # Components
    for comp in ["activities", "services", "receivers", "providers", "exported_components"]:
        items = apk_data.get(comp, [])
        if items:
            ctx[comp] = [
                c.get("name", c) if isinstance(c, dict) else str(c)
                for c in items[:10]
            ]

    ctx["urls"] = apk_data.get("urls", [])[:20]
    ctx["domains"] = apk_data.get("domains", [])[:20]
    ctx["api_usage"] = apk_data.get("api_usage", [])[:12]
    ctx["strings_sample"] = [
        item.get("value") if isinstance(item, dict) else item
        for item in apk_data.get("strings", [])[:60]
    ]

    return ctx


def _apk_core(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    apk_analysis = analysis_data.get("apk_analysis")
    if isinstance(apk_analysis, dict) and apk_analysis:
        merged = dict(apk_analysis)
        for key in [
            "package_name", "app_name", "version_name", "version_code",
            "min_sdk_version", "target_sdk_version", "permissions",
            "activities", "services", "receivers", "providers",
            "urls", "domains", "strings", "api_usage", "network_artifacts",
            "exported_components", "certificates", "manifest",
        ]:
            if key in analysis_data and key not in merged:
                merged[key] = analysis_data[key]
        return merged
    return analysis_data


def _attack_context(analysis_data: Dict[str, Any], threat_assessment: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "package_name": analysis_data.get("package_name"),
        "app_name": analysis_data.get("app_name"),
        "permissions": [p.get("name") for p in analysis_data.get("permissions", []) if isinstance(p, dict)],
        "activities": [c.get("name") for c in analysis_data.get("activities", []) if isinstance(c, dict)],
        "services": [c.get("name") for c in analysis_data.get("services", []) if isinstance(c, dict)],
        "receivers": [c.get("name") for c in analysis_data.get("receivers", []) if isinstance(c, dict)],
        "providers": [c.get("name") for c in analysis_data.get("providers", []) if isinstance(c, dict)],
        "urls": analysis_data.get("urls", []),
        "domains": analysis_data.get("domains", []),
        "heuristic_indicators": threat_assessment.get("indicators", []),
    }


def _stream_text_chunks(text: str, chunk_size: int = 28):
    words = text.split(" ")
    chunk = ""
    for word in words:
        addition = f"{word} "
        if len(chunk) + len(addition) > chunk_size and chunk:
            yield chunk
            chunk = addition
        else:
            chunk += addition
    if chunk:
        yield chunk


# ===========================================================================
# Core Neural Endpoints
# ===========================================================================

@router.post("/analyze")
async def neural_analyze(req: AnalyzeRequest, db: AsyncSession = Depends(get_db)):
    """Trigger the full neural analysis pipeline for an APK."""
    scan, analysis_data = await _get_scan_analysis(req.scan_id, db)

    apk_path = Path(scan.file_path) if hasattr(scan, "file_path") and scan.file_path else None
    if apk_path and not apk_path.exists():
        apk_path = None

    output_dir = Path(settings.STORAGE_DIR) / "neural_analysis" / req.scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    stages_completed = []
    neural_results: Dict[str, Any] = {}

    try:
        # Stage 1: Run YARA scan on available data
        from app.services.yara_scanner import YaraScanner
        scanner = YaraScanner(rules_dir=settings.yara_rules_dir)

        manifest = analysis_data.get("manifest", "")
        permissions = [
            p.get("name", p) if isinstance(p, dict) else str(p)
            for p in analysis_data.get("permissions", [])
        ]
        yara_matches = scanner.scan_apk_artifacts(
            manifest=manifest,
            permissions=permissions,
            strings=analysis_data.get("strings") or analysis_data.get("extracted_strings", []),
        )
        yara_summary = scanner.get_summary(yara_matches)
        neural_results["yara_scan"] = yara_summary
        stages_completed.append("yara_scan")

        # Stage 2: Run reverse engineering pipeline if APK available
        if apk_path:
            try:
                from app.services.reverse_engineering import ReverseEngineeringPipeline
                pipeline = ReverseEngineeringPipeline(apk_path, output_dir)
                re_results = await pipeline.run_full_analysis()
                if re_results.get("status") == "complete":
                    neural_results.update(re_results.get("analysis", {}))
                    stages_completed.extend(re_results.get("stages_completed", []))
            except Exception as e:
                logger.warning("RE pipeline partially failed: %s", e)
                stages_completed.append("re_pipeline_partial")
        else:
            stages_completed.append("re_pipeline_skipped")

        # Stage 3: AI cognition report (if Ollama available)
        engine = get_neural_engine()
        health = await engine.health_check()

        if health.get("healthy"):
            try:
                ctx = _build_ai_context({**analysis_data, **neural_results})
                cognition = await engine.generate_cognition_report(ctx)
                neural_results["ai_cognition"] = cognition
                stages_completed.append("ai_cognition")
            except Exception as e:
                logger.warning("AI cognition failed: %s", e)
                neural_results["ai_cognition"] = {"error": str(e)}
                stages_completed.append("ai_cognition_failed")
        else:
            neural_results["ai_cognition"] = {
                "status": "offline",
                "message": "Ollama not available — AI cognition skipped",
            }
            stages_completed.append("ai_cognition_offline")

        apk_evidence = _apk_core(analysis_data)
        threat_assessment = analysis_data.get("threat_assessment") or ThreatScoring.calculate_threat_score(apk_evidence)
        attack_mapping = analysis_data.get("attack_mapping") or AttackMapper().map_artifacts(
            _attack_context(apk_evidence, threat_assessment)
        )
        intelligence = IntelligenceEngine.enrich(
            apk_data=apk_evidence,
            threat_assessment=threat_assessment,
            attack_mapping=attack_mapping,
            neural_analysis=neural_results,
        )
        stages_completed.append("intelligence_enrichment")

        # Stage 4: Generate static runtime reconstruction
        try:
            from app.services.sandbox_simulator import SandboxSimulator
            simulator = SandboxSimulator()
            sandbox_data = simulator.simulate_from_static(apk_evidence, neural_results)
            neural_results["sandbox_simulation"] = sandbox_data
            stages_completed.append("runtime_reconstruction")
        except Exception as e:
            logger.warning("Runtime reconstruction failed: %s", e)
            stages_completed.append("runtime_reconstruction_failed")

        # Save results to DB
        neural_results.setdefault("statistics", {})
        neural_results["statistics"]["stages_completed"] = stages_completed
        analysis_data["neural_analysis"] = neural_results
        analysis_data["yara_scan"] = yara_summary
        analysis_data["threat_assessment"] = threat_assessment
        analysis_data["attack_mapping"] = attack_mapping
        analysis_data["intelligence"] = intelligence
        analysis_data.update(intelligence)
        analysis_data["top_suspicious_functions"] = AnalystWorkflow.rank_suspicious_functions(analysis_data)
        scan.analysis_result = json.dumps(analysis_data, default=str)
        await db.commit()

        return {
            "scan_id": req.scan_id,
            "status": "complete",
            "stages_completed": stages_completed,
            "total_stages": len(stages_completed),
            "yara_matches": yara_summary.get("total_matches", 0),
            "ai_available": health.get("healthy", False),
        }

    except Exception as e:
        logger.error("Neural analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/summary/{scan_id}")
async def neural_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get concise threat summary for a scan."""
    logger.info("Neural Summary Request: scan=%s", scan_id)
    scan, analysis_data = await _get_scan_analysis(scan_id, db)
    ctx = _build_ai_context(analysis_data)

    engine = get_neural_engine()
    health = await engine.health_check()

    if health.get("healthy"):
        try:
            summary = await engine.generate_summary(ctx)
            logger.info("Neural Summary Success: scan=%s", scan_id)
            return {"scan_id": scan_id, "summary": summary, "ai_powered": True}
        except Exception as e:
            logger.error("Neural AI summary failed: %s", e, exc_info=True)

    # Fallback
    risk = analysis_data.get("risk_assessment") or analysis_data.get("threat_assessment") or {}
    severity = risk.get("severity", "UNKNOWN")
    risk_score = risk.get("risk_score", 0)
    fallback = (
        f"This APK is classified as {severity} risk (Score: {risk_score}/100). "
        "AI summary unavailable — using heuristic extraction."
    )
    return {"scan_id": scan_id, "summary": fallback, "ai_powered": False}


@router.get("/risk/{scan_id}")
async def neural_risk(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get specialized Banking Fraud Intelligence risk assessment for a scan."""
    logger.info("Neural Risk Request: scan=%s", scan_id)
    scan, analysis_data = await _get_scan_analysis(scan_id, db)
    ctx = _build_ai_context(analysis_data)

    from app.services.ai_cognition import OllamaEnhancedCognition
    cognition = OllamaEnhancedCognition()
    
    # Generate the specialized hybrid banking report
    report = await cognition.generate_hybrid_report({**analysis_data, "intelligence": analysis_data.get("intelligence", {})})
    
    return {
        "scan_id": scan_id,
        "banking_intelligence": report,
        "ai_powered": report.get("ai_powered", False),
        # Legacy fields for backward compatibility
        "rule_based": {
            "risk_score": report.get("overall_risk", 0),
            "severity": report.get("threat_classification", "UNKNOWN"),
            "findings": report.get("technical_findings", []),
        }
    }


@router.post("/explain")
async def neural_explain(req: ExplainRequest, db: AsyncSession = Depends(get_db)):
    """Explain a specific function, API call, or code block."""
    logger.info("Neural Explain Request: scan=%s, func=%s", req.scan_id, req.function_name)
    scan, analysis_data = await _get_scan_analysis(req.scan_id, db)
    ctx = _build_ai_context(analysis_data)
    
    # Merge additional context if provided
    merged_ctx = {**ctx}
    if req.context_hint:
        merged_ctx["class_name"] = req.context_hint

    interpretation = CodeInterpreter.interpret(
        req.code,
        symbol_name=req.function_name,
        context=merged_ctx,
    )

    if interpretation.get("status") == "unavailable":
        logger.warning("Neural interpretation unavailable for scan=%s", req.scan_id)
        return {
            "scan_id": req.scan_id,
            "explanation": "Code interpretation unavailable because no decompiled source was provided.",
            "interpretation": interpretation,
            "ai_powered": False,
            "function_name": req.function_name,
        }

    engine = get_neural_engine()
    health = await engine.health_check()

    if health.get("healthy"):
        try:
            explanation_data = await engine.explain_code(req.code, apk_context=merged_ctx)
            logger.info("Neural Explain Success: scan=%s", req.scan_id)
            
            # Merge AI interpretation with rule-based interpretation
            interpretation.update(explanation_data)
            
            return {
                "scan_id": req.scan_id,
                "explanation": explanation_data.get("purpose", "AI analysis complete."),
                "interpretation": interpretation,
                "ai_powered": True,
                "function_name": req.function_name,
            }
        except Exception as e:
            logger.error("Neural AI explain failed: %s", e, exc_info=True)

    return {
        "scan_id": req.scan_id,
        "explanation": "Ollama is offline or the request could not be completed. The structured interpretation is limited to matched source evidence.",
        "interpretation": interpretation,
        "ai_powered": False,
        "function_name": req.function_name,
    }


@router.post("/chat")
async def neural_chat(req: ChatRequest, db: AsyncSession = Depends(get_db)):
    """AI chat with investigation context. Supports streaming (SSE)."""
    scan, analysis_data = await _get_scan_analysis(req.scan_id, db)
    ctx = _build_ai_context(analysis_data)
    deterministic_response = AnalystWorkflow.answer(req.message, analysis_data)

    engine = get_neural_engine()
    health = await engine.health_check()

    if False and not health.get("healthy"):
        raise HTTPException(
            status_code=503,
            detail="AI engine offline — Ollama not available",
        )

    if req.stream:
        async def event_stream():
            try:
                logger.info("Chat Request: scan=%s, msg=%s", req.scan_id, req.message)
                
                # Heuristic Fast-Path: Provide instant response for common questions
                if deterministic_response:
                    logger.info("Using Heuristic Fast-Path for chat response.")
                    for chunk in _stream_text_chunks(deterministic_response):
                        yield f"data: {json.dumps({'token': chunk})}\n\n"
                    yield f"data: {json.dumps({'done': True})}\n\n"
                    return

                if health.get("healthy"):
                    # Provide an immediate "Thinking" status to keep the user engaged
                    thinking_msg = "Analyst is analyzing the artifact code and behavior chains... This may take a moment on local hardware.\n\n"
                    for chunk in _stream_text_chunks(thinking_msg):
                        yield f"data: {json.dumps({'token': chunk})}\n\n"
                    
                    async for chunk in engine.chat_stream(req.scan_id, req.message, context=ctx):
                        yield f"data: {json.dumps({'token': chunk})}\n\n"
                else:
                    fallback = (
                        "AI model is offline. Here is the evidence-backed overview instead:\n\n"
                        + AnalystWorkflow.concise_overview(analysis_data)
                    )
                    for chunk in _stream_text_chunks(fallback):
                        yield f"data: {json.dumps({'token': chunk})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
                logger.info("Chat stream completed for scan=%s", req.scan_id)
            except Exception as e:
                logger.error("Chat stream exception: %s", e, exc_info=True)
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
    else:
        try:
            logger.info("Non-streaming Chat Request: scan=%s", req.scan_id)
            if deterministic_response:
                response = deterministic_response
            elif health.get("healthy"):
                response = await engine.chat(req.scan_id, req.message, context=ctx)
            else:
                response = (
                    "AI model is offline. Here is the evidence-backed overview instead:\n\n"
                    + AnalystWorkflow.concise_overview(analysis_data)
                )
            logger.info("Non-streaming Chat Success: scan=%s", req.scan_id)
            return {"scan_id": req.scan_id, "response": response}
        except Exception as e:
            logger.error("Non-streaming chat failed: %s", e, exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def neural_health():
    """Check Ollama and AI engine health."""
    engine = get_neural_engine()
    return await engine.health_check()


@router.get("/pipeline/{scan_id}")
async def neural_pipeline_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get analysis pipeline status for a scan."""
    scan, analysis_data = await _get_scan_analysis(scan_id, db)
    neural = analysis_data.get("neural_analysis", {})

    return {
        "scan_id": scan_id,
        "has_neural_analysis": bool(neural),
        "statistics": neural.get("statistics", {}),
        "yara_scan": analysis_data.get("yara_scan", {}),
        "ai_cognition_status": neural.get("ai_cognition", {}).get("status", "unknown")
            if isinstance(neural.get("ai_cognition"), dict) else "complete",
        "runtime_reconstruction_available": "sandbox_simulation" in neural,
    }


@router.post("/report")
async def neural_report(req: ReportRequest, db: AsyncSession = Depends(get_db)):
    """Generate investigation report."""
    scan, analysis_data = await _get_scan_analysis(req.scan_id, db)

    try:
        from app.services.report_generator import ReportGenerator
        generator = ReportGenerator()
        report = generator.generate(analysis_data, report_type=req.report_type)
        return {
            "scan_id": req.scan_id,
            "report_type": req.report_type,
            "report": report,
        }
    except Exception as e:
        logger.error("Report generation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Investigation Workflow — Bridge & Recent
# ---------------------------------------------------------------------------

@router.get("/investigations/recent")
async def get_recent_investigations(db: AsyncSession = Depends(get_db)):
    """Return the most recent investigations with associated scan metadata.
    Used by the Neural Lab landing page to offer 'Resume Investigation'.
    """
    from app.models.investigation import Investigation

    result = await db.execute(
        select(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(10)
    )
    investigations = result.scalars().all()

    enriched = []
    for inv in investigations:
        inv_dict = inv.to_dict()
        # Attach scan filename for display
        scan_result = await db.execute(
            select(Scan).where(Scan.id == inv.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if scan:
            inv_dict["filename"] = scan.filename
            analysis = {}
            if scan.analysis_result:
                try:
                    analysis = json.loads(scan.analysis_result) if isinstance(
                        scan.analysis_result, str
                    ) else scan.analysis_result
                except Exception:
                    pass
            inv_dict["app_name"] = analysis.get("app_name", scan.filename)
            inv_dict["has_neural_analysis"] = bool(
                analysis.get("neural_analysis")
            )
        else:
            inv_dict["filename"] = "Unknown"
            inv_dict["app_name"] = "Unknown"
            inv_dict["has_neural_analysis"] = False
        enriched.append(inv_dict)

    return enriched


@router.post("/bridge-evidence")
async def bridge_evidence_to_scan(
    req: BridgeEvidenceRequest,
    db: AsyncSession = Depends(get_db),
):
    """Bridge a case evidence item to a Scan record so Neural Lab can open it.

    Logic:
      1. Load the Evidence row by evidence_id + case_id.
      2. Look up an existing Scan by the evidence's sha256.
      3. If no Scan exists, create one from the evidence metadata.
      4. Return { scan_id, filename, status }.
    """
    from app.models.case import Evidence as EvidenceModel

    # 1. Load evidence
    ev_result = await db.execute(
        select(EvidenceModel).where(
            EvidenceModel.id == req.evidence_id,
            EvidenceModel.case_id == req.case_id,
        )
    )
    evidence = ev_result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # 2. Find existing scan by sha256
    scan_result = await db.execute(
        select(Scan).where(Scan.sha256 == evidence.sha256)
    )
    scan = scan_result.scalar_one_or_none()

    # 3. Create scan if missing
    if not scan:
        import uuid
        scan = Scan(
            id=str(uuid.uuid4()),
            sha256=evidence.sha256,
            filename=evidence.original_filename,
            file_size=evidence.file_size,
            file_path=evidence.file_path,
            status="completed" if evidence.analysis_result else "pending",
        )
        # Copy analysis result if the evidence already has one
        if evidence.analysis_result:
            scan.analysis_result = evidence.analysis_result
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        logger.info(
            "Created scan %s from evidence %s (sha256=%s)",
            scan.id, evidence.id, evidence.sha256,
        )

    return {
        "scan_id": scan.id,
        "filename": evidence.original_filename,
        "status": scan.status,
        "evidence_id": evidence.id,
        "case_id": req.case_id,
    }


# ---------------------------------------------------------------------------
# Static runtime reconstruction endpoint
# ---------------------------------------------------------------------------

@router.get("/sandbox/{scan_id}")
async def neural_sandbox(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get static runtime reconstruction data."""
    scan, analysis_data = await _get_scan_analysis(scan_id, db)
    neural = analysis_data.get("neural_analysis", {})
    sandbox = neural.get("sandbox_simulation")

    if not sandbox:
        # Generate on-the-fly from static evidence
        try:
            from app.services.sandbox_simulator import SandboxSimulator
            simulator = SandboxSimulator()
            sandbox = simulator.simulate_from_static(analysis_data, neural)
        except Exception:
            sandbox = {
                "mode": "static_runtime_reconstruction",
                "dynamic_execution": False,
                "events": [],
                "timeline": [],
                "statistics": {
                    "duration_seconds": 0,
                    "total_events": 0,
                    "critical_events": 0,
                    "high_events": 0,
                    "network_requests": 0,
                    "file_writes": 0,
                    "permission_abuses": 0,
                    "dynamic_execution": False,
                },
                "limitations": ["Static runtime reconstruction unavailable for this artifact."],
            }

    return {"scan_id": scan_id, "sandbox": sandbox}


# ===========================================================================
# Investigation CRUD Endpoints
# ===========================================================================

@router.get("/investigations")
async def list_investigations(
    scan_id: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """List investigations, optionally filtered by scan_id."""
    service = InvestigationService(db)
    return await service.list_investigations(scan_id=scan_id)


@router.post("/investigations")
async def create_investigation(
    req: InvestigationCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a new investigation session."""
    service = InvestigationService(db)
    return await service.create_investigation(
        scan_id=req.scan_id,
        title=req.title,
        description=req.description,
        analyst_name=req.analyst_name,
    )


@router.get("/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get investigation by ID."""
    service = InvestigationService(db)
    inv = await service.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.put("/investigations/{investigation_id}")
async def update_investigation(
    investigation_id: str,
    req: InvestigationUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update investigation."""
    service = InvestigationService(db)
    updated = await service.update_investigation(
        investigation_id, **req.dict(exclude_none=True)
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return updated


@router.delete("/investigations/{investigation_id}")
async def delete_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete investigation."""
    service = InvestigationService(db)
    success = await service.delete_investigation(investigation_id)
    if not success:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"deleted": True}


# Notes

@router.post("/investigations/{investigation_id}/notes")
async def add_note(
    investigation_id: str,
    req: NoteCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    service = InvestigationService(db)
    return await service.add_note(
        investigation_id, req.content, req.note_type, req.tags
    )


@router.get("/investigations/{investigation_id}/notes")
async def list_notes(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    service = InvestigationService(db)
    return await service.list_notes(investigation_id)


# Bookmarks

@router.post("/investigations/{investigation_id}/bookmarks")
async def add_bookmark(
    investigation_id: str,
    req: BookmarkCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    service = InvestigationService(db)
    return await service.add_bookmark(
        investigation_id, req.target_type, req.target_id,
        req.label, req.notes, req.severity,
    )


@router.get("/investigations/{investigation_id}/bookmarks")
async def list_bookmarks(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    service = InvestigationService(db)
    return await service.list_bookmarks(investigation_id)
