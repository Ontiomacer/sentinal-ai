import json
import asyncio
import logging
from typing import Optional, Dict, Any
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.evidence_service import EvidenceService
from app.services.timeline_service import TimelineService
from app.services.apk_analyzer import APKAnalyzer
from app.services.threat_scoring import ThreatScoring
from app.services.attack_mapper import AttackMapper
from app.services.context_builder import ContextBuilder
from app.services.neural_engine import NeuralEngine
from app.services.entity_service import EntityService
from app.services.intelligence_engine import IntelligenceEngine
from app.services.analyst_workflow import AnalystWorkflow
from app.services.ghidra_service import get_ghidra_service, GhidraService
from app.models.case import EntityType

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """Orchestrates dual forensic analysis pipelines."""
    
    PIPELINE_NEURAL = "neural_ai"
    PIPELINE_DEEP = "deep_reverse_engineering"
    
    @staticmethod
    async def run_analysis_task(
        evidence_id: str,
        case_id: str,
        user_id: str,
        pipeline_type: str
    ):
        """Background task wrapper for analysis pipeline."""
        from app.database import AsyncSessionLocal
        
        async with AsyncSessionLocal() as db:
            try:
                await AnalysisPipeline.start_analysis(
                    db=db,
                    evidence_id=evidence_id,
                    case_id=case_id,
                    user_id=user_id,
                    pipeline_type=pipeline_type
                )
            except Exception as e:
                logger.error(f"Background analysis task failed: {str(e)}")
                await EvidenceService.update_analysis_status(db, evidence_id, 'failed')

    @staticmethod
    async def start_analysis(
        db: AsyncSession,
        evidence_id: str,
        case_id: str,
        user_id: str,
        pipeline_type: str
    ) -> Dict[str, Any]:
        """Start analysis pipeline for evidence."""
        
        # Get evidence
        evidence = await EvidenceService.get_evidence(db, evidence_id)
        if not evidence:
            raise ValueError("Evidence not found")
        
        # Update status to indexing
        await EvidenceService.update_analysis_status(db, evidence_id, 'INDEXING')
        
        # Create timeline event
        await TimelineService.create_auto_event(
            db=db,
            case_id=case_id,
            user_id=user_id,
            event_type='analysis',
            title=f'Analysis Started: {pipeline_type}',
            description=f'Initiating {pipeline_type} pipeline for {evidence.original_filename}',
            evidence_id=evidence_id,
            metadata={'pipeline': pipeline_type}
        )
        
        # Route to appropriate pipeline
        if pipeline_type == AnalysisPipeline.PIPELINE_NEURAL:
            result = await AnalysisPipeline._neural_ai_pipeline(db, evidence, case_id, user_id)
        elif pipeline_type == AnalysisPipeline.PIPELINE_DEEP:
            result = await AnalysisPipeline._deep_reverse_engineering_pipeline(db, evidence, case_id, user_id)
        else:
            raise ValueError(f"Unknown pipeline type: {pipeline_type}")
        
        return result
    
    @staticmethod
    async def _neural_ai_pipeline(
        db: AsyncSession,
        evidence: Any,
        case_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Pipeline A: Neural AI Analysis
        - Fast behavioral analysis
        - APK heuristics
        - Risk scoring
        - AI threat cognition
        - Malware behavior detection
        """
        
        result = {
            'pipeline': 'neural_ai',
            'evidence_id': evidence.id,
            'stages': []
        }
        
        try:
            # Stage 1: Static Analysis
            await EvidenceService.update_analysis_status(db, evidence.id, 'static_analysis')
            await TimelineService.create_auto_event(
                db=db,
                case_id=case_id,
                user_id=user_id,
                event_type='analysis',
                title='Static Analysis: In Progress',
                evidence_id=evidence.id
            )
            
            # Perform APK analysis
            apk_data = await APKAnalyzer.analyze(Path(evidence.file_path))
            result['stages'].append({
                'stage': 'static_analysis',
                'status': 'complete',
                'data': apk_data
            })
            
            # Stage 2: Threat Scoring, ATT&CK Mapping, and Neural Cognition
            await EvidenceService.update_analysis_status(db, evidence.id, 'ai_correlation')
            await TimelineService.create_auto_event(
                db=db,
                case_id=case_id,
                user_id=user_id,
                event_type='analysis',
                title='Neural Cognition: Correlating Threat Indicators',
                evidence_id=evidence.id
            )

            threat_assessment = ThreatScoring.calculate_threat_score(apk_data)
            attack_mapper = AttackMapper()
            attack_mapping = attack_mapper.map_artifacts({
                'package_name': apk_data.get('package_name'),
                'app_name': apk_data.get('app_name'),
                'permissions': [p.get('name') for p in apk_data.get('permissions', [])],
                'activities': [a.get('name') for a in apk_data.get('activities', [])],
                'services': [s.get('name') for s in apk_data.get('services', [])],
                'receivers': [r.get('name') for r in apk_data.get('receivers', [])],
                'providers': [p.get('name') for p in apk_data.get('providers', [])],
                'urls': apk_data.get('urls', []),
                'domains': apk_data.get('domains', []),
                'heuristic_indicators': threat_assessment.get('indicators', [])
            })

            context = ContextBuilder.build_context(
                apk_data=apk_data,
                threat_assessment=threat_assessment,
                attack_mapping=attack_mapping
            )

            neural_engine = NeuralEngine()
            try:
                health = await neural_engine.health_check()
                if health.get("healthy"):
                    neural_insights = await neural_engine.generate_cognition_report(context)
                else:
                    neural_insights = {
                        "status": "offline",
                        "message": "Ollama is unavailable; AI cognition was not generated.",
                        "health": health,
                    }
            finally:
                await neural_engine.close()

            intelligence = IntelligenceEngine.enrich(
                apk_data=apk_data,
                threat_assessment=threat_assessment,
                attack_mapping=attack_mapping,
                neural_analysis={"neural_insights": neural_insights},
            )
            risk_assessment = intelligence["risk_assessment"]
            ai_analysis = {
                'threat_assessment': threat_assessment,
                'attack_mapping': attack_mapping,
                'analysis_context': context,
                'neural_insights': neural_insights,
                **intelligence,
            }
            result['stages'].append({
                'stage': 'ai_correlation',
                'status': 'complete',
                'data': ai_analysis
            })

            # Stage 3: Entity Extraction
            entities_extracted = await AnalysisPipeline._extract_entities(
                db, case_id, apk_data, threat_assessment
            )
            result['entities_extracted'] = entities_extracted
            
            # Stage 4: Report Ready
            await EvidenceService.update_analysis_status(
                db, 
                evidence.id, 
                'complete',
                {
                    'pipeline': 'neural_ai',
                    'apk_analysis': apk_data,
                    'threat_assessment': threat_assessment,
                    'attack_mapping': attack_mapping,
                    'ai_analysis': ai_analysis,
                    'intelligence': intelligence,
                    **intelligence,
                    'top_suspicious_functions': AnalystWorkflow.rank_suspicious_functions({
                        'apk_analysis': apk_data,
                        'neural_analysis': ai_analysis,
                        **intelligence,
                    }),
                    'risk_score': risk_assessment.get('risk_score', 0),
                    'threat_level': risk_assessment.get('severity', 'UNKNOWN')
                }
            )
            
            await TimelineService.create_auto_event(
                db=db,
                case_id=case_id,
                user_id=user_id,
                event_type='finding',
                title=f'Neural AI Analysis Complete',
                description=f"Risk Score: {risk_assessment.get('risk_score', 0)}/100, Threat Level: {risk_assessment.get('severity', 'UNKNOWN')}",
                evidence_id=evidence.id,
                metadata={
                    'risk_score': risk_assessment.get('risk_score', 0),
                    'threat_level': risk_assessment.get('severity', 'UNKNOWN'),
                    'threat_family': intelligence.get('threat_classification', {}).get('threat_family'),
                    'entities_found': entities_extracted
                }
            )
            
            result['status'] = 'complete'
            return result
            
        except Exception as e:
            await EvidenceService.update_analysis_status(db, evidence.id, 'failed')
            await TimelineService.create_auto_event(
                db=db,
                case_id=case_id,
                user_id=user_id,
                event_type='analysis',
                title='Analysis Failed',
                description=f'Error: {str(e)}',
                evidence_id=evidence.id
            )
            raise
    
    @staticmethod
    async def _deep_reverse_engineering_pipeline(
        db: AsyncSession,
        evidence: Any,
        case_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Pipeline B: Deep Reverse Engineering (Fixed Pipeline)
        1. Unzip APK
        2. Extract classes.dex
        3. Import DEX into Ghidra
        4. Run auto-analysis
        5. Enumerate artifacts
        """
        
        result = {
            'pipeline': 'deep_reverse_engineering',
            'evidence_id': evidence.id,
            'stages': []
        }
        
        try:
            # Stage 1: Extraction
            await EvidenceService.update_analysis_status(db, evidence.id, 'INDEXING')
            
            from app.config import settings
            output_dir = Path(settings.STORAGE_DIR) / "cases" / case_id / "analysis" / evidence.id
            output_dir.mkdir(parents=True, exist_ok=True)
            
            import zipfile
            apk_path = Path(evidence.file_path)
            extracted_dir = output_dir / "extracted"
            extracted_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Unzipping APK: {apk_path}")
            dex_files = []
            with zipfile.ZipFile(apk_path, 'r') as z:
                for file_info in z.filelist:
                    if file_info.filename.endswith('.dex'):
                        z.extract(file_info, extracted_dir)
                        dex_files.append(extracted_dir / file_info.filename)
            
            if not dex_files:
                raise Exception("No DEX files found in APK")
            
            # Stage 2: Ghidra Import
            await EvidenceService.update_analysis_status(db, evidence.id, 'IMPORTING')
            ghidra_service = get_ghidra_service()
            project_name = f"case_{case_id}_evidence_{evidence.id}"
            
            # Import main DEX
            main_dex = dex_files[0]
            logger.info(f"Importing {main_dex.name} into Ghidra via direct MCP")
            import_success = await ghidra_service.import_program(
                file_path=main_dex,
                project_name=project_name
            )
            
            if not import_success:
                raise Exception("Ghidra DEX import failed via MCP")
            
            # Stage 3: Auto-Analysis
            await EvidenceService.update_analysis_status(db, evidence.id, 'ANALYZING')
            logger.info("Triggering Ghidra auto-analysis via direct MCP")
            analysis_success = await ghidra_service.run_analysis(project_name)
            
            if not analysis_success:
                logger.warning("Ghidra auto-analysis returned failure, proceeding anyway")
            
            # Stage 4: Artifact Enumeration
            await EvidenceService.update_analysis_status(db, evidence.id, 'INDEXING')
            functions = await ghidra_service.list_functions(project_name)
            classes = await ghidra_service.list_classes(project_name)
            strings = await ghidra_service.extract_strings(project_name)
            
            # Stage 5: Combine & Persist
            from app.services.apk_analyzer import APKAnalyzer
            apk_data = await APKAnalyzer.analyze(apk_path)
            threat_assessment = ThreatScoring.calculate_threat_score(apk_data)
            attack_mapping = AttackMapper().map_artifacts({
                'package_name': apk_data.get('package_name'),
                'app_name': apk_data.get('app_name'),
                'permissions': [p.get('name') for p in apk_data.get('permissions', []) if isinstance(p, dict)],
                'activities': [a.get('name') for a in apk_data.get('activities', []) if isinstance(a, dict)],
                'services': [s.get('name') for s in apk_data.get('services', []) if isinstance(s, dict)],
                'receivers': [r.get('name') for r in apk_data.get('receivers', []) if isinstance(r, dict)],
                'providers': [p.get('name') for p in apk_data.get('providers', []) if isinstance(p, dict)],
                'urls': apk_data.get('urls', []),
                'domains': apk_data.get('domains', []),
                'heuristic_indicators': threat_assessment.get('indicators', [])
            })
            intelligence = IntelligenceEngine.enrich(
                apk_data=apk_data,
                threat_assessment=threat_assessment,
                attack_mapping=attack_mapping,
                neural_analysis={
                    "ghidra_counts": {
                        "functions": len(functions),
                        "classes": len(classes),
                        "strings": len(strings),
                    }
                },
            )
            risk_assessment = intelligence["risk_assessment"]
            
            final_result = {
                'apk_analysis': apk_data,
                'threat_assessment': threat_assessment,
                'attack_mapping': attack_mapping,
                'ghidra_analysis': {
                    'status': 'complete',
                    'project_name': project_name,
                    'functions_count': len(functions),
                    'classes_count': len(classes),
                    'strings_count': len(strings),
                    'first_function': functions[0].dict() if functions else None,
                },
                'intelligence': intelligence,
                **intelligence,
                'top_suspicious_functions': AnalystWorkflow.rank_suspicious_functions({
                    'apk_analysis': apk_data,
                    'neural_analysis': {
                        'suspicious_functions': [],
                    },
                    **intelligence,
                }),
                'risk_score': risk_assessment.get('risk_score', 0),
                'threat_level': risk_assessment.get('severity', 'UNKNOWN')
            }
            
            await EvidenceService.update_analysis_status(
                db,
                evidence.id,
                'READY',
                final_result
            )
            
            result['status'] = 'complete'
            result['data'] = final_result
            return result
            
        except Exception as e:
            logger.error(f"Deep analysis pipeline failed: {str(e)}")
            await EvidenceService.update_analysis_status(db, evidence.id, 'FAILED')
            raise
    
    @staticmethod
    async def _extract_entities(
        db: AsyncSession,
        case_id: str,
        apk_data: Dict[str, Any],
        ai_analysis: Dict[str, Any]
    ) -> int:
        """Extract and create entities from analysis results."""
        
        entities_created = 0
        
        # Extract URLs
        urls = apk_data.get('urls', [])
        for url in urls[:10]:  # Limit to top 10
            try:
                from app.schemas.case import EntityCreate
                entity_data = EntityCreate(
                    entity_type=EntityType.URL,
                    name=f"URL: {url[:50]}",
                    value=url,
                    description="Extracted from APK analysis",
                    risk_score=ai_analysis.get('risk_score', 50),
                    tags=['auto-extracted', 'url'],
                    related_evidence=[],
                    metadata={'source': 'apk_analysis'}
                )
                await EntityService.create_entity(db, case_id, entity_data)
                entities_created += 1
            except:
                pass
        
        # Extract domains
        domains = apk_data.get('domains', [])
        for domain in domains[:10]:
            try:
                from app.schemas.case import EntityCreate
                entity_data = EntityCreate(
                    entity_type=EntityType.DOMAIN,
                    name=f"Domain: {domain}",
                    value=domain,
                    description="Extracted from APK analysis",
                    risk_score=ai_analysis.get('risk_score', 50),
                    tags=['auto-extracted', 'domain'],
                    related_evidence=[],
                    metadata={'source': 'apk_analysis'}
                )
                await EntityService.create_entity(db, case_id, entity_data)
                entities_created += 1
            except:
                pass
        
        return entities_created
