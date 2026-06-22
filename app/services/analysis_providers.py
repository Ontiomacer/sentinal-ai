from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from app.services.security_assessment_engine import SecurityAssessmentEngine


class AnalysisProvider(ABC):
    """Provider interface for APK intelligence generation."""

    provider_name: str

    @abstractmethod
    async def assess(
        self,
        *,
        apk_data: Dict[str, Any],
        risk_assessment: Optional[Dict[str, Any]] = None,
        analysis_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured security assessment from APK findings."""


class RuleBasedProvider(AnalysisProvider):
    """Deterministic Sentinel assessment provider used for APK demo analysis."""

    provider_name = "rule_based"

    async def assess(
        self,
        *,
        apk_data: Dict[str, Any],
        risk_assessment: Optional[Dict[str, Any]] = None,
        analysis_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return SecurityAssessmentEngine.generate(
            apk_data=apk_data,
            risk_assessment=risk_assessment,
            analysis_metadata=analysis_metadata,
        )


class OllamaProvider(AnalysisProvider):
    """Future Ollama-backed provider. Disabled for APK analysis demo reliability."""

    provider_name = "ollama"

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    async def assess(
        self,
        *,
        apk_data: Dict[str, Any],
        risk_assessment: Optional[Dict[str, Any]] = None,
        analysis_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {
                "provider": self.provider_name,
                "engine": "OllamaProvider",
                "status": "disabled",
                "evidence_based": False,
                "verdict": "Ollama provider is disabled for deterministic APK analysis.",
                "risk_score": None,
                "threat_level": "Unavailable",
                "malicious_confidence": None,
                "key_findings": [],
                "sections": {},
                "recommendations": [],
            }

        raise NotImplementedError("OllamaProvider is intentionally disabled for APK analysis.")


def get_default_analysis_provider() -> AnalysisProvider:
    return RuleBasedProvider()
