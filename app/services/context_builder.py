import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.services.analysis_graph import AnalysisGraph
from app.services.attack_mapper import AttackMapper

logger = logging.getLogger(__name__)


class ContextBuilder:
    """Builds condensed AI context from APK and analysis artifacts."""

    MAX_ITEMS = 50

    @staticmethod
    def build_context(
        apk_data: Dict[str, Any],
        threat_assessment: Dict[str, Any],
        attack_mapping: List[Dict[str, Any]],
        ghidra_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        iocs = ContextBuilder._extract_iocs(apk_data)
        artifact_summary = ContextBuilder._summarize_artifacts(apk_data)
        mapping_summary = AttackMapper().summarize_mappings(attack_mapping)

        context = {
            "package_name": apk_data.get("package_name"),
            "app_name": apk_data.get("app_name"),
            "version_name": apk_data.get("version_name"),
            "version_code": apk_data.get("version_code"),
            "permissions": [p.get("name") for p in apk_data.get("permissions", [])],
            "suspicious_permissions": threat_assessment.get("suspicious_permissions", []),
            "components": {
                "activities": [a.get("name") for a in apk_data.get("activities", [])],
                "services": [s.get("name") for s in apk_data.get("services", [])],
                "receivers": [r.get("name") for r in apk_data.get("receivers", [])],
                "providers": [p.get("name") for p in apk_data.get("providers", [])]
            },
            "urls": apk_data.get("urls", [])[:ContextBuilder.MAX_ITEMS],
            "domains": apk_data.get("domains", [])[:ContextBuilder.MAX_ITEMS],
            "native_libraries": apk_data.get("native_libraries", [])[:ContextBuilder.MAX_ITEMS],
            "file_summary": artifact_summary,
            "iocs": iocs,
            "heuristic_indicators": threat_assessment.get("indicators", []),
            "threat_assessment": {
                "risk_score": threat_assessment.get("risk_score"),
                "severity": threat_assessment.get("severity"),
                "summary": threat_assessment.get("summary"),
                "score_breakdown": threat_assessment.get("score_breakdown", {})
            },
            "attack_mapping": attack_mapping,
            "attack_mapping_summary": mapping_summary,
            "ghidra_data": {
                "summary": ghidra_data.get("summary") if ghidra_data else None,
                "functions_count": ghidra_data.get("functions_count") if ghidra_data else None,
                "strings_count": ghidra_data.get("strings_count") if ghidra_data else None,
            } if ghidra_data else None,
        }

        context["analysis_graph"] = AnalysisGraph.from_analysis(
            apk_data, threat_assessment, attack_mapping
        ).to_dict()

        return context

    @staticmethod
    def _extract_iocs(apk_data: Dict[str, Any]) -> Dict[str, List[str]]:
        urls = apk_data.get("urls", [])[:ContextBuilder.MAX_ITEMS]
        domains = apk_data.get("domains", [])[:ContextBuilder.MAX_ITEMS]
        package_name = apk_data.get("package_name", "")
        app_name = apk_data.get("app_name", "")
        suspicious_package_names = []

        if package_name and any(keyword in package_name.lower() for keyword in ["bank", "pay", "secure", "mobile", "wallet"]):
            suspicious_package_names.append(package_name)

        if app_name and any(keyword in app_name.lower() for keyword in ["bank", "payment", "otp", "secure", "login", "auth"]):
            suspicious_package_names.append(app_name)

        crypto_constants = []
        for candidate in [package_name, app_name] + urls + domains:
            if candidate and any(token in candidate.lower() for token in ["aes", "rsa", "sha", "md5", "hmac", "crypto", "cipher"]):
                crypto_constants.append(candidate)

        suspicious_intents = []
        for activity in apk_data.get("activities", []):
            name = activity.get("name", "")
            if any(token in name.lower() for token in ["boot", "receiver", "accessibility", "overlay", "payment", "auth"]):
                suspicious_intents.append(name)

        webview_indicators = []
        for component_type in [apk_data.get("activities", []), apk_data.get("services", [])]:
            for component in component_type:
                name = component.get("name", "")
                if "webview" in name.lower() or "loadurl" in name.lower():
                    webview_indicators.append(name)

        return {
            "urls": urls,
            "domains": domains,
            "suspicious_package_names": list(dict.fromkeys(suspicious_package_names)),
            "crypto_constants": list(dict.fromkeys(crypto_constants)),
            "suspicious_intents": list(dict.fromkeys(suspicious_intents)),
            "webview_indicators": list(dict.fromkeys(webview_indicators))
        }

    @staticmethod
    def _summarize_artifacts(apk_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "permission_count": len(apk_data.get("permissions", [])),
            "activity_count": len(apk_data.get("activities", [])),
            "service_count": len(apk_data.get("services", [])),
            "receiver_count": len(apk_data.get("receivers", [])),
            "provider_count": len(apk_data.get("providers", [])),
            "url_count": len(apk_data.get("urls", [])),
            "domain_count": len(apk_data.get("domains", [])),
            "native_library_count": len(apk_data.get("native_libraries", []))
        }
