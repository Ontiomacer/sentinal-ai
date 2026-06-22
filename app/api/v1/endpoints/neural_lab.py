"""
Neural Lab API Endpoints
Advanced reverse engineering and malware cognition interface
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pathlib import Path
from typing import Dict, List, Optional
import json
import logging

from app.database import get_db
from app.models.scan import Scan
from app.services.reverse_engineering import ReverseEngineeringPipeline
from app.services.ai_cognition import AICognitionEngine
from app.services.analyst_workflow import AnalystWorkflow
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/scans/{scan_id}/neural-analysis")
async def initiate_neural_analysis(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate comprehensive neural analysis for a scan.
    Runs the full reverse engineering pipeline.
    """
    # Get scan from database
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check if APK file exists
    apk_path = Path(scan.file_path)
    if not apk_path.exists():
        raise HTTPException(status_code=404, detail="APK file not found")
    
    # Create output directory for analysis
    output_dir = Path(settings.STORAGE_DIR) / "neural_analysis" / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Run reverse engineering pipeline
        pipeline = ReverseEngineeringPipeline(apk_path, output_dir)
        results = await pipeline.run_full_analysis()
        
        # Store results
        if results.get('status') == 'complete':
            # Update scan with neural analysis results
            analysis_data = json.loads(scan.analysis_result) if scan.analysis_result else {}
            analysis_data['neural_analysis'] = results.get('analysis', {})
            
            scan.analysis_result = json.dumps(analysis_data)
            await db.commit()
        
        return {
            "scan_id": scan_id,
            "status": results.get('status'),
            "stages_completed": results.get('stages_completed', []),
            "message": "Neural analysis initiated successfully"
        }
        
    except Exception as e:
        logger.error(f"Neural analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/scans/{scan_id}/neural-analysis")
async def get_neural_analysis(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get neural analysis results for a scan.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not scan.analysis_result:
        raise HTTPException(status_code=404, detail="No analysis results available")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        neural_analysis = analysis_data.get('neural_analysis')
        
        if not neural_analysis:
            raise HTTPException(status_code=404, detail="Neural analysis not yet performed")
        
        return {
            "scan_id": scan_id,
            "neural_analysis": neural_analysis
        }
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Failed to parse analysis results")


@router.get("/scans/{scan_id}/suspicious-functions")
async def get_suspicious_functions(
    scan_id: str,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """
    Get list of suspicious functions detected in the APK.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        
        # Phase 1: Use AnalystWorkflow which includes SuspiciousFunctionDiscovery
        suspicious_functions = AnalystWorkflow.rank_suspicious_functions(analysis_data)
        
        # Paginate results
        paginated = suspicious_functions[offset:offset + limit]
        
        return {
            "scan_id": scan_id,
            "total": len(suspicious_functions),
            "offset": offset,
            "limit": limit,
            "functions": paginated
        }
        
    except Exception as e:
        logger.error(f"Failed to get suspicious functions: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/function/{function_signature}")
async def get_function_details(
    scan_id: str,
    function_signature: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific function.
    Includes decompiled code and AI explanation.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        
        # Get ranked functions with Phase 1 discovery
        suspicious_functions = AnalystWorkflow.rank_suspicious_functions(analysis_data)
        
        # Find the function by either signature or function_name
        function = next(
            (
                f for f in suspicious_functions 
                if f.get('signature') == function_signature 
                or f.get('function_name') == function_signature
            ),
            None
        )
        
        if not function:
            raise HTTPException(status_code=404, detail="Function not found")
        
        # Try to get decompiled code if available
        apk_data = analysis_data.get('apk_analysis', {})
        decompiled_code = function.get('decompiled_code')
        if not decompiled_code:
            # Could try to get from decompiled_artifacts here if we have it
            pass
        
        # Use NeuralEngine for AI explanation if available
        ai_explanation = None
        from app.services.neural_engine import NeuralEngine
        try:
            neural_engine = NeuralEngine()
            health = await neural_engine.health_check()
            if health.get("healthy"):
                context = {
                    "scan_id": scan_id,
                    "function_name": function.get('function_name'),
                    "apk_analysis": apk_data,
                    "intelligence": analysis_data.get('intelligence', {})
                }
                code_for_explanation = decompiled_code or f"{function.get('function_name')}: {function.get('reason')}"
                ai_explanation = await neural_engine.explain_code(code_for_explanation, context)
        except Exception as e:
            logger.warning(f"Failed to get AI explanation: {e}")
        
        # Fallback to old explanation if AI isn't available
        if not ai_explanation:
            ai_engine = AICognitionEngine()
            ai_explanation = ai_engine.explain_suspicious_behavior(
                function.get('name', function.get('function_name')),
                function.get('threat_indicators', function.get('evidence', [])),
                function
            )
        
        return {
            "scan_id": scan_id,
            "function": function,
            "ai_explanation": ai_explanation
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get function details: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/malware-indicators")
async def get_malware_indicators(
    scan_id: str,
    indicator_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get malware indicators detected in the APK.
    Optionally filter by indicator type.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        neural_analysis = analysis_data.get('neural_analysis', {})
        
        indicators = neural_analysis.get('malware_indicators', [])
        
        # Filter by type if specified
        if indicator_type:
            indicators = [i for i in indicators if i.get('type') == indicator_type]
        
        # Group by type
        grouped = {}
        for indicator in indicators:
            ind_type = indicator.get('type', 'unknown')
            if ind_type not in grouped:
                grouped[ind_type] = []
            grouped[ind_type].append(indicator)
        
        return {
            "scan_id": scan_id,
            "total": len(indicators),
            "grouped_by_type": grouped,
            "indicators": indicators
        }
        
    except Exception as e:
        logger.error(f"Failed to get malware indicators: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/behavioral-patterns")
async def get_behavioral_patterns(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get behavioral threat patterns detected in the APK.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        neural_analysis = analysis_data.get('neural_analysis', {})
        
        patterns = neural_analysis.get('behavioral_patterns', [])
        
        # Generate attack chain narratives
        ai_engine = AICognitionEngine()
        for pattern in patterns:
            pattern['attack_narrative'] = ai_engine.generate_attack_chain_narrative(pattern)
        
        return {
            "scan_id": scan_id,
            "total": len(patterns),
            "patterns": patterns
        }
        
    except Exception as e:
        logger.error(f"Failed to get behavioral patterns: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/call-graph")
async def get_call_graph(
    scan_id: str,
    function_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get call relationship graph.
    Optionally filter by specific function.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        neural_analysis = analysis_data.get('neural_analysis', {})
        
        call_graph = neural_analysis.get('call_graph', {})
        
        if function_name:
            # Return subgraph for specific function
            subgraph = {
                function_name: call_graph.get(function_name, [])
            }
            return {
                "scan_id": scan_id,
                "function": function_name,
                "call_graph": subgraph
            }
        
        return {
            "scan_id": scan_id,
            "call_graph": call_graph
        }
        
    except Exception as e:
        logger.error(f"Failed to get call graph: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/forensic-note")
async def get_forensic_note(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get AI-generated forensic intelligence note.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        neural_analysis = analysis_data.get('neural_analysis', {})
        
        if not neural_analysis:
            raise HTTPException(status_code=404, detail="Neural analysis not yet performed")
        
        # Generate forensic note
        ai_engine = AICognitionEngine()
        forensic_note = ai_engine.generate_forensic_note(neural_analysis)
        
        return {
            "scan_id": scan_id,
            "forensic_note": {
                "title": forensic_note.title,
                "summary": forensic_note.summary,
                "technical_details": forensic_note.technical_details,
                "attack_intent": forensic_note.attack_intent,
                "fraud_correlation": forensic_note.fraud_correlation,
                "mitigation": forensic_note.mitigation,
                "confidence": forensic_note.confidence
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate forensic note: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/fraud-analysis")
async def get_fraud_analysis(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get fraud-specific analysis and indicators.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        analysis_data = json.loads(scan.analysis_result)
        neural_analysis = analysis_data.get('neural_analysis', {})
        
        # Generate fraud analysis
        ai_engine = AICognitionEngine()
        fraud_functions = ai_engine.identify_fraud_functionality(
            neural_analysis.get('malware_indicators', []),
            neural_analysis.get('suspicious_functions', [])
        )
        
        return {
            "scan_id": scan_id,
            "fraud_functionalities": fraud_functions,
            "fraud_patterns": [
                p for p in neural_analysis.get('behavioral_patterns', [])
                if 'fraud' in p.get('pattern_name', '').lower()
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get fraud analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
