"""
Evidence-backed report generator for APK fraud investigations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


class ReportGenerator:
    """Generate report payloads using only persisted analysis findings."""

    def generate(self, analysis_data: Dict[str, Any], report_type: str = "executive") -> Dict[str, Any]:
        report_type = report_type.lower()
        if report_type not in {"executive", "technical", "ioc", "attack", "fraud", "cognition", "banking_fraud"}:
            raise ValueError(f"Unknown report type: {report_type}")

        meta = self._meta(analysis_data, report_type)
        common = self._common_sections(analysis_data)

        if report_type == "banking_fraud":
            return {**meta, **self._banking_fraud_report(analysis_data, common)}
        if report_type == "executive":
            return {**meta, **common, "executive_summary": self._executive_summary(analysis_data)}
        if report_type == "technical":
            return {**meta, **common, "technical_findings": self._technical_findings(analysis_data)}
        if report_type == "ioc":
            return {**meta, "indicators_of_compromise": self._iocs(analysis_data)}
        if report_type == "attack":
            return {**meta, "attack_flow": common["attack_flow"], "attack_mapping": analysis_data.get("attack_mapping", [])}
        if report_type == "fraud":
            return {**meta, "fraud_intent": common["fraud_intent"], "risk_scores": common["risk_scores"]}

        return {
            **meta,
            "ai_cognition": self._ai_cognition(analysis_data),
            "threat_classification": common["threat_classification"],
            "limitations": self._limitations(analysis_data),
        }

    def _banking_fraud_report(self, data: Dict[str, Any], common: Dict[str, Any]) -> Dict[str, Any]:
        risk = data.get("risk_assessment") or data.get("threat_assessment") or {}
        intel = risk.get("banking_fraud_intelligence", {})
        classification = common.get("threat_classification", {})
        
        return {
            "executive_summary": self._executive_summary(data),
            "threat_classification": classification,
            "banking_impact_assessment": {
                "targeted_apps": risk.get("targeted_banking_apps", []),
                "impact_summary": "High risk of account takeover and financial theft." if risk.get("risk_score", 0) > 60 else "Moderate risk to banking applications.",
                "fraud_vectors": [k.replace("_", " ").title() for k, v in intel.get("scores", {}).items() if v > 40]
            },
            "technical_findings": self._technical_findings(data),
            "mitre_attack_mapping": data.get("attack_mapping", []),
            "risk_factors": intel.get("risk_factors", []) or [f for f in risk.get("findings", []) if "risk" in f.lower()],
            "indicators_of_compromise": self._iocs(data),
            "recommended_actions": common.get("recommendations", []),
            "fraud_prevention_recommendations": [
                "Implement biometric multi-factor authentication",
                "Enable real-time transaction monitoring for targeted banking apps",
                "Deploy device-binding security policies",
                "Alert customers about potential overlay attacks"
            ],
            "fraud_scores": intel.get("scores", {})
        }

    def _meta(self, data: Dict[str, Any], report_type: str) -> Dict[str, Any]:
        risk = data.get("risk_assessment") or data.get("threat_assessment") or {}
        return {
            "meta": {
                "report_type": report_type,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "app_name": data.get("app_name") or (data.get("apk_analysis") or {}).get("app_name") or "Unknown APK",
                "package_name": data.get("package_name") or (data.get("apk_analysis") or {}).get("package_name") or "unknown",
                "version": data.get("version_name") or (data.get("apk_analysis") or {}).get("version_name"),
                "target_sdk": data.get("target_sdk_version") or (data.get("apk_analysis") or {}).get("target_sdk_version"),
                "risk_score": risk.get("risk_score", 0),
                "severity": risk.get("severity", "UNKNOWN"),
            }
        }

    def _common_sections(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "threat_classification": data.get("threat_classification") or {
                "threat_type": "Unknown",
                "threat_family": "No high-confidence family identified",
                "confidence": 0,
                "evidence": [],
            },
            "fraud_intent": data.get("fraud_intent") or {
                "objectives": [],
                "summary": "No fraud objective could be inferred from current evidence.",
            },
            "risk_scores": data.get("risk_assessment") or data.get("threat_assessment") or {},
            "attack_flow": data.get("attack_flow") or {
                "steps": [],
                "summary": "Insufficient evidence to reconstruct an attack flow.",
            },
            "recommendations": data.get("recommendations") or [],
            "evidence": self._evidence_summary(data),
            "limitations": self._limitations(data),
        }

    def _executive_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        risk = data.get("risk_assessment") or data.get("threat_assessment") or {}
        classification = data.get("threat_classification") or {}
        fraud = data.get("fraud_intent") or {}
        objectives = fraud.get("objectives", [])
        return {
            "headline": (
                f"{classification.get('threat_family', 'No high-confidence family identified')} "
                f"with {risk.get('severity', 'UNKNOWN')} severity"
            ),
            "summary": risk.get("summary") or "Risk summary unavailable from current analysis.",
            "fraud_objectives": [
                {
                    "objective": item.get("objective"),
                    "confidence": item.get("confidence"),
                    "evidence": item.get("evidence", []),
                }
                for item in objectives
            ],
            "key_findings": (risk.get("findings") or [])[:8],
        }

    def _technical_findings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        apk = data.get("apk_analysis") if isinstance(data.get("apk_analysis"), dict) else data
        neural = data.get("neural_analysis") or {}
        return {
            "manifest": {
                "package_name": apk.get("package_name"),
                "main_activity": apk.get("main_activity"),
                "min_sdk": apk.get("min_sdk_version"),
                "target_sdk": apk.get("target_sdk_version"),
                "exported_components": apk.get("exported_components", []),
            },
            "permissions": apk.get("permissions", []),
            "components": {
                "activities": apk.get("activities", []),
                "services": apk.get("services", []),
                "receivers": apk.get("receivers", []),
                "providers": apk.get("providers", []),
            },
            "certificates": apk.get("certificates", []),
            "dex_analysis": apk.get("dex_analysis", {}),
            "api_usage": apk.get("api_usage", []),
            "suspicious_functions": neural.get("suspicious_functions", []),
            "behavioral_patterns": neural.get("behavioral_patterns", []),
            "ghidra_analysis": data.get("ghidra_analysis") or neural.get("ghidra_analysis", {}),
        }

    def _iocs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        apk = data.get("apk_analysis") if isinstance(data.get("apk_analysis"), dict) else data
        threat_iocs = (data.get("threat_assessment") or {}).get("iocs", {})
        network = apk.get("network_artifacts", {}) if isinstance(apk, dict) else {}
        return {
            "urls": list(dict.fromkeys(apk.get("urls", []) + threat_iocs.get("urls", []))),
            "domains": list(dict.fromkeys(apk.get("domains", []) + threat_iocs.get("domains", []))),
            "ip_addresses": list(dict.fromkeys(network.get("ip_addresses", []) + threat_iocs.get("ips", []))),
            "certificates": apk.get("certificates", []),
            "hardcoded_strings_sample": apk.get("strings", [])[:50],
        }

    def _ai_cognition(self, data: Dict[str, Any]) -> Dict[str, Any]:
        neural = data.get("neural_analysis") or {}
        cognition = neural.get("ai_cognition") or (data.get("ai_analysis") or {}).get("neural_insights")
        if not cognition:
            return {
                "status": "unavailable",
                "message": "No AI cognition output is stored for this artifact.",
            }
        return cognition

    def _evidence_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        apk = data.get("apk_analysis") if isinstance(data.get("apk_analysis"), dict) else data
        return {
            "permission_count": len(apk.get("permissions", [])),
            "exported_component_count": len(apk.get("exported_components", [])),
            "string_count": apk.get("string_count", len(apk.get("strings", []))),
            "url_count": len(apk.get("urls", [])),
            "domain_count": len(apk.get("domains", [])),
            "certificate_count": len(apk.get("certificates", [])),
            "api_usage_categories": [item.get("category") for item in apk.get("api_usage", []) if isinstance(item, dict)],
        }

    def _limitations(self, data: Dict[str, Any]) -> List[str]:
        limitations = []
        if not data.get("neural_analysis"):
            limitations.append("Neural Lab reverse-engineering pipeline has not been run for this artifact.")
        if not data.get("ghidra_analysis"):
            limitations.append("Ghidra analysis results are not stored in this report payload.")
        runtime = ((data.get("neural_analysis") or {}).get("sandbox_simulation") or {})
        if not runtime.get("dynamic_execution"):
            limitations.append("No live dynamic sandbox execution is claimed.")
        return limitations
