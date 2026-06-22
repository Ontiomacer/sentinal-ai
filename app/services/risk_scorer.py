from typing import Dict, List, Any
from app.services.threat_scoring import ThreatScoring, ThreatSeverity


class Severity:
    """Risk severity levels (Backward compatibility wrapper)."""
    LOW = ThreatSeverity.LOW
    MEDIUM = ThreatSeverity.MEDIUM
    HIGH = ThreatSeverity.HIGH
    CRITICAL = ThreatSeverity.CRITICAL


class RiskScorer:
    """
    Backward compatibility wrapper for ThreatScoring.
    """
    
    @staticmethod
    def calculate_risk_score(analysis_result: Dict) -> Dict:
        """
        Calculate risk score using the improved ThreatScoring engine.
        """
        # ThreatScoring expects the same input structure as RiskScorer did
        threat_data = ThreatScoring.calculate_threat_score(analysis_result)
        
        # Map ThreatScoring results to the structure expected by RiskScorer callers
        return {
            "risk_score": threat_data.get("risk_score", 0),
            "severity": threat_data.get("severity", Severity.LOW),
            "findings": threat_data.get("findings", []),
            "summary": threat_data.get("summary", ""),
            "score_breakdown": threat_data.get("score_breakdown", {})
        }
