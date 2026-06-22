"""
AI Cognition Layer for Malware Analysis
Provides explainable intelligence, banking trojan signature detection,
and hybrid rule + GenAI cognition.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import logging

from app.services.neural_engine import get_neural_engine

logger = logging.getLogger(__name__)


@dataclass
class BankingFraudIntelligence:
    """Specialized banking fraud intelligence data."""
    overall_risk: int
    credential_theft_score: int
    otp_theft_score: int
    upi_fraud_score: int
    account_takeover_score: int
    financial_data_exposure_score: int
    targeted_apps: List[str]
    risk_factors: List[str]
    evidence: Dict[str, List[str]]


@dataclass
class ForensicNote:
    """Human-readable forensic intelligence note."""
    title: str
    summary: str
    technical_details: str
    attack_intent: str
    fraud_correlation: str
    mitigation: str
    confidence: float


class AICognitionEngine:
    """
    AI-powered cognition engine for explainable malware analysis.
    Generates human-readable intelligence from technical findings using rules.
    """
    
    BANKING_APPS = {
        "com.google.android.apps.nbu.paisa.user": "Google Pay",
        "com.phonepe.app": "PhonePe",
        "com.paytm.payments": "Paytm",
        "com.sbi.lotusintouch": "SBI YONO",
        "com.hdfcbank.smartbuy": "HDFC Bank",
        "com.csam.icici.bank.imobile": "ICICI Bank",
        "com.axis.mobile": "Axis Bank",
        "com.kotak.mobilebanking": "Kotak Bank",
        "in.org.npci.upiapp": "BHIM UPI",
        "com.amazon.mShop.android.shopping": "Amazon (Pay)",
        "com.freecharge.android": "Freecharge",
        "com.mobikwik_new": "MobiKwik"
    }

    def __init__(self):
        self.knowledge_base = self._load_knowledge_base()
    
    def detect_targeted_banking_apps(self, indicators: List[Dict]) -> List[str]:
        """Detect references to banking and fintech applications."""
        targeted = set()
        for ind in indicators:
            val = str(ind.get('value', '')).lower()
            # Check package names
            for pkg, name in self.BANKING_APPS.items():
                if pkg.lower() in val or name.lower() in val:
                    targeted.add(name)
            
            # General keywords
            if any(k in val for k in ['bank', 'payment', 'wallet', 'upi', 'checkout']):
                # If we found a generic keyword but no specific app yet
                pass
        
        return list(targeted)

    def calculate_banking_fraud_scores(self, analysis_results: Dict) -> Dict[str, Any]:
        """Calculate granular banking fraud scores based on evidence."""
        indicators = analysis_results.get('malware_indicators', [])
        functions = analysis_results.get('suspicious_functions', [])
        patterns = analysis_results.get('behavioral_patterns', [])
        permissions = analysis_results.get('permissions', [])
        
        scores = {
            "credential_theft": 0,
            "otp_theft": 0,
            "upi_fraud": 0,
            "account_takeover": 0,
            "financial_data_exposure": 0
        }
        
        evidence = {
            "credential_theft": [],
            "otp_theft": [],
            "upi_fraud": [],
            "account_takeover": [],
            "financial_data_exposure": []
        }

        # 1. Credential Theft (Overlays, Keylogging, Accessibility)
        if any('overlay' in f.get('name', '').lower() for f in functions):
            scores["credential_theft"] += 40
            evidence["credential_theft"].append("Overlay attack functions detected in code.")
        if any('accessibility' in str(p).lower() for p in permissions):
            scores["credential_theft"] += 30
            scores["account_takeover"] += 30
            evidence["credential_theft"].append("Accessibility Service permission requested.")
        
        # 2. OTP Interception (SMS, Notifications)
        sms_perms = [p for p in permissions if 'SMS' in str(p).upper()]
        if sms_perms:
            scores["otp_theft"] += 50
            evidence["otp_theft"].append(f"SMS permissions requested: {', '.join(sms_perms)}")
        if any('notification' in f.get('name', '').lower() for f in functions):
            scores["otp_theft"] += 30
            evidence["otp_theft"].append("Notification listener patterns found.")

        # 3. UPI/Payment Fraud
        upi_indicators = [i for i in indicators if 'upi' in str(i.get('value', '')).lower()]
        if upi_indicators:
            scores["upi_fraud"] += 60
            evidence["upi_fraud"].append(f"UPI intent/URI references found: {len(upi_indicators)} instances.")

        # 4. Account Takeover (Remote Control, Persistence)
        if any('admin' in str(p).lower() for p in permissions):
            scores["account_takeover"] += 40
            evidence["account_takeover"].append("Device Admin permission requested.")
        
        # 5. Financial Data Exfiltration
        if any(k in str(indicators).lower() for k in ['contact', 'call_log', 'account']):
            scores["financial_data_exposure"] += 40
            evidence["financial_data_exposure"].append("PII/Account harvesting indicators detected.")

        # Cap scores at 100
        for k in scores:
            scores[k] = min(scores[k], 100)
            
        overall_risk = int(sum(scores.values()) / len(scores))
        
        return {
            "scores": scores,
            "evidence": evidence,
            "overall_risk": overall_risk
        }

    def identify_top_suspicious_functions(self, analysis_results: Dict) -> List[Dict]:
        """
        Identify and rank the top 10 most suspicious functions based on technical evidence.
        """
        functions = analysis_results.get('suspicious_functions', [])
        indicators = analysis_results.get('malware_indicators', [])
        permissions = analysis_results.get('permissions', [])
        
        ranked_functions = []
        
        for func in functions:
            name = func.get('name', '').lower()
            risk_score = 0
            reasons = []
            
            # 1. Overlay & Window behavior
            if any(k in name for k in ['overlay', 'window', 'view', 'alert', 'toast']):
                risk_score += 25
                reasons.append("Potential UI overlay/manipulation")
            
            # 2. SMS & Interception
            if any(k in name for k in ['sms', 'receive', 'intercept', 'read', 'otp']):
                risk_score += 35
                reasons.append("SMS interception capability")
                
            # 3. Network & Transmission
            if any(k in name for k in ['send', 'upload', 'post', 'http', 'socket', 'connect']):
                risk_score += 20
                reasons.append("Network transmission logic")
                
            # 4. Credential & Data handling
            if any(k in name for k in ['login', 'pass', 'user', 'auth', 'cred', 'token', 'card', 'cvv']):
                risk_score += 30
                reasons.append("Sensitive data/credential handling")
                
            # 5. Evasion & Advanced techniques
            if any(k in name for k in ['reflect', 'invoke', 'load', 'dex', 'native', 'crypto', 'decrypt']):
                risk_score += 25
                reasons.append("Evasion or dynamic code execution")
            
            # 6. Accessibility abuse
            if 'accessibility' in name or any('accessibility' in str(p).lower() for p in permissions):
                if 'accessibility' in name:
                    risk_score += 40
                    reasons.append("Direct Accessibility Service abuse")
            
            # Only include if there's actual evidence
            if risk_score > 0:
                ranked_functions.append({
                    "function_name": func.get('name'),
                    "class_name": func.get('class_name'),
                    "risk_score": min(risk_score, 100),
                    "reason": ", ".join(reasons[:2]) if reasons else "Suspicious patterns detected"
                })
        
        # Sort by risk score and return top 10
        ranked_functions.sort(key=lambda x: x['risk_score'], reverse=True)
        return ranked_functions[:10]

    def explain_suspicious_behavior(self, function_name: str, indicators: List[str], 
                                    context: Dict) -> str:
        """Generate natural language explanation of suspicious code behavior."""
        explanations = []
        
        # Analyze function name
        func_lower = function_name.lower()
        if 'decrypt' in func_lower:
            explanations.append(
                "This function performs decryption operations, which may be used to "
                "unpack hidden payloads or decode command-and-control communications."
            )
        
        if 'runtime' in func_lower or 'exec' in func_lower:
            explanations.append(
                "This function executes system commands at runtime, a technique commonly "
                "used by malware to gain elevated privileges or execute malicious payloads."
            )
        
        if 'reflection' in func_lower or 'invoke' in func_lower:
            explanations.append(
                "This function uses Java reflection to dynamically invoke methods, "
                "which can bypass static analysis and hide malicious behavior."
            )
        
        # Analyze indicators
        for indicator in indicators:
            if indicator == "Native method":
                explanations.append(
                    "This is a native method implemented in C/C++, which provides "
                    "low-level system access and is harder to analyze than Java code."
                )
        
        if not explanations:
            explanations.append(
                f"The function '{function_name}' exhibits patterns consistent with "
                "potentially malicious behavior and warrants further investigation."
            )
        
        return " ".join(explanations)
    
    def summarize_attack_intent(self, behavioral_patterns: List[Dict], 
                               indicators: List[Dict]) -> str:
        """Summarize the overall attack intent based on behavioral analysis."""
        intents = []
        
        # Analyze patterns
        pattern_names = [p.get('pattern_name', '') for p in behavioral_patterns]
        
        if 'SMS Fraud' in pattern_names or 'SMS Interception' in pattern_names:
            intents.append(
                "SMS-based fraud targeting two-factor authentication and premium services"
            )
        
        if 'Financial Data Theft' in pattern_names or 'Overlay Attack' in pattern_names:
            intents.append(
                "Financial credential harvesting and banking trojan behavior"
            )
        
        # Analyze indicators
        indicator_types = [i.get('type', '') for i in indicators]
        
        if 'url' in indicator_types or 'ip_address' in indicator_types:
            intents.append(
                "Command-and-control communication with remote servers"
            )
        
        if 'native_library' in indicator_types:
            intents.append(
                "Native code execution for advanced evasion and persistence"
            )
        
        if not intents:
            return "The application exhibits suspicious characteristics that require further investigation."
        
        return "This APK demonstrates: " + "; ".join(intents) + "."
    
    def identify_fraud_functionality(self, indicators: List[Dict], 
                                    functions: List[Dict]) -> List[str]:
        """Identify specific fraud-related functionality."""
        fraud_functions = []
        
        # Check for SMS manipulation
        sms_related = [i for i in indicators if 'sms' in str(i.get('value', '')).lower()]
        if sms_related:
            fraud_functions.append(
                "SMS Interception: Capability to read and send SMS messages, "
                "commonly used to steal banking OTP codes"
            )
        
        # Check for credential theft
        credential_keywords = ['password', 'login', 'auth', 'credential', 'token']
        credential_related = [
            i for i in indicators 
            if any(k in str(i.get('value', '')).lower() for k in credential_keywords)
        ]
        if credential_related:
            fraud_functions.append(
                "Credential Harvesting: References to authentication data suggest "
                "credential theft capabilities"
            )
        
        # Check for overlay attacks
        overlay_functions = [
            f for f in functions 
            if any(k in f.get('name', '').lower() for k in ['overlay', 'window', 'view'])
        ]
        if overlay_functions:
            fraud_functions.append(
                "Overlay Attack: Ability to display fake UI elements over legitimate "
                "banking apps to steal credentials"
            )
        
        # Check for keylogging
        keylog_functions = [
            f for f in functions 
            if any(k in f.get('name', '').lower() for k in ['key', 'input', 'accessibility'])
        ]
        if keylog_functions:
            fraud_functions.append(
                "Keylogging: Input monitoring capabilities that can capture "
                "sensitive user data"
            )
        
        return fraud_functions
    
    def generate_forensic_note(self, analysis_results: Dict) -> ForensicNote:
        """Generate comprehensive forensic intelligence note."""
        suspicious_functions = analysis_results.get('suspicious_functions', [])
        indicators = analysis_results.get('malware_indicators', [])
        patterns = analysis_results.get('behavioral_patterns', [])
        
        # Generate title
        if patterns:
            primary_pattern = patterns[0].get('pattern_name', 'Unknown Threat')
            title = f"Malware Analysis: {primary_pattern} Detected"
        else:
            title = "Malware Analysis: Suspicious Behavior Detected"
        
        # Generate summary
        summary = self.summarize_attack_intent(patterns, indicators)
        
        # Technical details
        technical_details = self._compile_technical_details(
            suspicious_functions, indicators, patterns
        )
        
        # Attack intent
        attack_intent = self._analyze_attack_intent(patterns, indicators)
        
        # Fraud correlation
        fraud_correlation = self._correlate_fraud_indicators(
            suspicious_functions, indicators
        )
        
        # Mitigation
        mitigation = self._generate_mitigation_advice(patterns, indicators)
        
        # Calculate confidence
        confidence = self._calculate_confidence(patterns, indicators)
        
        return ForensicNote(
            title=title,
            summary=summary,
            technical_details=technical_details,
            attack_intent=attack_intent,
            fraud_correlation=fraud_correlation,
            mitigation=mitigation,
            confidence=confidence
        )
    
    def generate_attack_chain_narrative(self, behavioral_pattern: Dict) -> str:
        """Generate narrative description of attack chain."""
        attack_chain = behavioral_pattern.get('attack_chain', [])
        
        if not attack_chain:
            return "Attack chain could not be reconstructed."
        
        narrative = "The attack unfolds in the following sequence:\n\n"
        
        for idx, step in enumerate(attack_chain, 1):
            narrative += f"{idx}. {step}\n"
        
        narrative += f"\n{behavioral_pattern.get('ai_explanation', '')}"
        
        return narrative
    
    def _load_knowledge_base(self) -> Dict:
        """Load malware knowledge base."""
        return {
            "fraud_patterns": {
                "sms_fraud": {
                    "description": "SMS-based fraud and OTP interception",
                    "indicators": ["READ_SMS", "SEND_SMS", "RECEIVE_SMS"],
                    "severity": "high"
                },
                "banking_trojan": {
                    "description": "Banking credential theft",
                    "indicators": ["overlay", "accessibility", "keylog"],
                    "severity": "critical"
                },
                "adware": {
                    "description": "Aggressive advertising and click fraud",
                    "indicators": ["ad", "click", "impression"],
                    "severity": "medium"
                }
            }
        }
    
    def _compile_technical_details(self, functions: List[Dict], 
                                   indicators: List[Dict], 
                                   patterns: List[Dict]) -> str:
        """Compile technical details section."""
        details = []
        
        if functions:
            details.append(
                f"Identified {len(functions)} suspicious functions with "
                "potential malicious behavior."
            )
        
        if indicators:
            indicator_types = {}
            for ind in indicators:
                ind_type = ind.get('type', 'unknown')
                indicator_types[ind_type] = indicator_types.get(ind_type, 0) + 1
            
            details.append(
                f"Detected {len(indicators)} malware indicators across "
                f"{len(indicator_types)} categories."
            )
        
        if patterns:
            details.append(
                f"Mapped {len(patterns)} behavioral threat patterns."
            )
        
        return " ".join(details)
    
    def _analyze_attack_intent(self, patterns: List[Dict], 
                              indicators: List[Dict]) -> str:
        """Analyze and describe attack intent."""
        if not patterns and not indicators:
            return "Attack intent unclear - insufficient behavioral data."
        
        intent_description = "Based on behavioral analysis, this malware appears designed to "
        
        intents = []
        
        for pattern in patterns:
            pattern_name = pattern.get('pattern_name', '')
            if 'SMS' in pattern_name:
                intents.append("intercept SMS-based authentication")
            elif 'Financial' in pattern_name:
                intents.append("steal banking credentials and financial data")
        
        if intents:
            intent_description += ", ".join(intents) + "."
        else:
            intent_description += "perform unauthorized actions on the device."
        
        return intent_description
    
    def _correlate_fraud_indicators(self, functions: List[Dict], 
                                   indicators: List[Dict]) -> str:
        """Correlate findings with known fraud patterns."""
        correlations = []
        
        # Check for banking trojan indicators
        banking_keywords = ['bank', 'credit', 'card', 'payment', 'wallet']
        banking_refs = sum(
            1 for i in indicators 
            if any(k in str(i.get('value', '')).lower() for k in banking_keywords)
        )
        
        if banking_refs > 0:
            correlations.append(
                f"Found {banking_refs} references to financial services, "
                "consistent with banking trojan behavior."
            )
        
        # Check for SMS fraud indicators
        sms_refs = sum(1 for i in indicators if 'sms' in str(i.get('value', '')).lower())
        if sms_refs > 0:
            correlations.append(
                f"Detected {sms_refs} SMS-related indicators, "
                "suggesting SMS fraud capabilities."
            )
        
        if not correlations:
            return "No direct correlation with known fraud patterns."
        
        return " ".join(correlations)
    
    def _generate_mitigation_advice(self, patterns: List[Dict], 
                                   indicators: List[Dict]) -> str:
        """Generate mitigation and remediation advice."""
        advice = []
        
        advice.append(
            "Immediate Actions: Remove this application from all devices and "
            "reset credentials for any accounts accessed while it was installed."
        )
        
        if any('SMS' in p.get('pattern_name', '') for p in patterns):
            advice.append(
                "SMS Fraud Mitigation: Contact your bank to report potential "
                "OTP interception and enable additional security measures."
            )
        
        if any('Financial' in p.get('pattern_name', '') for p in patterns):
            advice.append(
                "Financial Security: Monitor bank accounts for unauthorized "
                "transactions and consider freezing affected cards."
            )
        
        advice.append(
            "Prevention: Only install applications from trusted sources and "
            "review permissions carefully before granting access."
        )
        
        return " ".join(advice)
    
    def _calculate_confidence(self, patterns: List[Dict], 
                            indicators: List[Dict]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on patterns
        confidence += len(patterns) * 0.1
        
        # Increase confidence based on indicators
        confidence += min(len(indicators) * 0.02, 0.3)
        
        # Cap at 0.95 (never 100% certain)
        return min(confidence, 0.95)


class OllamaEnhancedCognition(AICognitionEngine):
    """
    Subclass that integrates the NeuralEngine (Ollama) to perform
    hybrid rules + LLM malware classification.
    """

    def __init__(self):
        super().__init__()
        self.neural_engine = get_neural_engine()

    async def generate_hybrid_report(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produce a combined rules-based and Ollama-based threat report.
        Focused on Banking Fraud Intelligence.
        """
        # Run rule-based scoring first
        from app.services.intelligence_engine import IntelligenceEngine
        
        # We assume context already has what IntelligenceEngine needs
        # If not, we should pass the raw data
        
        # Check LLM health
        health = await self.neural_engine.health_check()
        
        if health.get("healthy"):
            try:
                # Ask Ollama for advanced threat intelligence
                ai_report = await self.neural_engine.generate_cognition_report(context)
                structured = ai_report.get("structured_output", {})
                
                # Stage 2: Rank suspicious functions for the analyst
                from app.services.analyst_workflow import AnalystWorkflow
                top_functions = AnalystWorkflow.rank_suspicious_functions(context)
                
                # Merge rule findings with AI insights
                return {
                    "status": "complete",
                    "ai_powered": True,
                    "overall_risk": structured.get("risk_score", context.get("risk_assessment", {}).get("risk_score", 0)),
                    "threat_classification": structured.get("threat_classification", "Banking Trojan"),
                    "fraud_intent": structured.get("fraud_intent", "Unknown"),
                    "executive_summary": structured.get("executive_summary", "AI-generated executive summary unavailable."),
                    "banking_impact_assessment": structured.get("banking_impact_assessment", "Impact assessment unavailable."),
                    "technical_findings": structured.get("key_findings", []),
                    "mitre_attack_mapping": structured.get("mitre_attack_mapping", []),
                    "risk_factors": structured.get("risk_contributors", []),
                    "indicators_of_compromise": structured.get("indicators_of_compromise", []),
                    "recommended_actions": structured.get("recommendations", []),
                    "targeted_banking_apps": structured.get("targeted_banking_apps", []),
                    "top_suspicious_functions": top_functions,
                    "fraud_scores": structured.get("fraud_scores", {
                        "overall_risk": 0,
                        "credential_theft": 0,
                        "otp_theft": 0,
                        "upi_fraud": 0,
                        "account_takeover": 0,
                        "financial_data_exposure": 0
                    }),
                    "confidence_score": structured.get("confidence", 85),
                }
            except Exception as e:
                logger.error("Ollama query failed in hybrid report: %s", e)
        
        # Fallback to rules-only report (using IntelligenceEngine findings if present)
        intelligence = context.get("intelligence", {})
        risk = intelligence.get("risk_assessment", {})
        banking_intel = risk.get("banking_fraud_intelligence", {})
        from app.services.analyst_workflow import AnalystWorkflow
        top_functions = AnalystWorkflow.rank_suspicious_functions(context)
        
        return {
            "status": "complete",
            "ai_powered": False,
            "overall_risk": risk.get("risk_score", 0),
            "threat_classification": intelligence.get("threat_classification", {}).get("threat_family", "Suspicious APK"),
            "fraud_intent": "Detected Suspicious Patterns",
            "executive_summary": risk.get("summary", "Rule-based analysis summary."),
            "banking_impact_assessment": "This application demonstrates high-risk patterns consistent with banking fraud.",
            "technical_findings": risk.get("findings", []),
            "mitre_attack_mapping": [],
            "risk_factors": [f"{item['label']} +{item['score']}" for item in risk.get("contributors", [])],
            "indicators_of_compromise": intelligence.get("threat_classification", {}).get("evidence", []),
            "recommended_actions": [rec.get("action") for rec in intelligence.get("recommendations", [])],
            "targeted_banking_apps": risk.get("targeted_banking_apps", []),
            "top_suspicious_functions": top_functions,
            "fraud_scores": banking_intel.get("scores", {
                "overall_risk": banking_intel.get("overall_risk", 0),
                "credential_theft": 0,
                "otp_theft": 0,
                "upi_fraud": 0,
                "account_takeover": 0,
                "financial_data_exposure": 0
            }),
            "confidence_score": intelligence.get("threat_classification", {}).get("confidence", 70),
        }
