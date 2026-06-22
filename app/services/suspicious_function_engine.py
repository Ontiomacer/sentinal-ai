from typing import List, Dict, Any
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class SuspiciousFunctionDiscovery:
    """Engine to identify and rank suspicious functions in an APK."""
    
    RISK_WEIGHTS = {
        "sms": 25,
        "accessibility": 25,
        "overlay": 20,
        "credential_collection": 20,
        "crypto": 15,
        "reflection": 15,
        "dynamic_loading": 15,
        "network": 10,
    }
    
    SUSPICIOUS_PATTERNS = {
        "sms": [
            "SmsManager", "SMS_RECEIVED", "READ_SMS", "SEND_SMS",
            "telephony.TelephonyManager", "getLine1Number", "getSubscriberId"
        ],
        "accessibility": [
            "AccessibilityService", "AccessibilityEvent", "BIND_ACCESSIBILITY_SERVICE",
            "onAccessibilityEvent", "getSource", "getRootInActiveWindow",
            "findAccessibilityNodeInfosByText", "performAction"
        ],
        "overlay": [
            "WindowManager", "TYPE_APPLICATION_OVERLAY", "TYPE_SYSTEM_ALERT",
            "SYSTEM_ALERT_WINDOW", "LayoutParams"
        ],
        "credential_collection": [
            "EditText", "getText", "PasswordEditText", "android.webkit.CookieManager",
            "AccountManager", "getAccounts", "getPassword"
        ],
        "reflection": [
            "Class.forName", "Method.invoke", "getDeclaredMethod", "getDeclaredField",
            "java/lang/reflect"
        ],
        "dynamic_loading": [
            "DexClassLoader", "PathClassLoader", "loadClass", "Runtime.getRuntime"
        ],
        "crypto": [
            "Cipher", "SecretKeySpec", "MessageDigest", "AES", "RSA", "encrypt", "decrypt"
        ],
        "network": [
            "HttpURLConnection", "OkHttp", "Retrofit", "Socket", "WebSocket",
            "getInputStream", "getOutputStream", "URL"
        ],
    }

    @staticmethod
    def analyze_methods(dex_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify and rank suspicious functions from DEX analysis."""
        
        suspicious_functions = []
        methods = dex_analysis.get("methods", [])
        
        for method in methods:
            method_name = method.get("name", "")
            class_name = method.get("class_name", "")
            descriptor = method.get("descriptor", "")
            
            # Build corpus for pattern matching
            corpus = f"{class_name} {method_name} {descriptor}"
            corpus_lower = corpus.lower()
            
            # Calculate risk score
            risk_score = 0
            matched_categories = []
            matched_evidence = []
            
            for category, patterns in SuspiciousFunctionDiscovery.SUSPICIOUS_PATTERNS.items():
                matches = [p for p in patterns if p.lower() in corpus_lower]
                if matches:
                    risk_score += SuspiciousFunctionDiscovery.RISK_WEIGHTS.get(category, 10)
                    matched_categories.append(category)
                    matched_evidence.extend(matches)
            
            if risk_score > 0:
                # Generate reason
                reason = SuspiciousFunctionDiscovery._generate_reason(
                    method_name, class_name, matched_categories
                )
                
                suspicious_functions.append({
                    "function_name": f"{class_name}.{method_name}",
                    "class_name": class_name,
                    "method_name": method_name,
                    "descriptor": descriptor,
                    "risk_score": min(risk_score, 100),  # Cap at 100
                    "categories": sorted(set(matched_categories)),
                    "reason": reason,
                    "evidence": sorted(set(matched_evidence)),
                })
        
        # Sort by risk score descending
        suspicious_functions.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return suspicious_functions[:20]  # Return top 20

    @staticmethod
    def _generate_reason(method_name: str, class_name: str, categories: List[str]) -> str:
        """Generate a human-readable reason why a function is suspicious."""
        
        category_reasons = {
            "sms": "uses SMS and telephony APIs which can be abused for OTP theft",
            "accessibility": "uses accessibility services which can enable keylogging and screen scraping",
            "overlay": "uses overlay APIs which can display fake login screens over legitimate apps",
            "credential_collection": "contains patterns consistent with credential collection and theft",
            "reflection": "uses reflection which can be used to hide malicious behavior",
            "dynamic_loading": "uses dynamic class loading which is common in evasive malware",
            "crypto": "uses cryptographic APIs which can be used to encrypt malicious payloads or stolen data",
            "network": "uses network APIs which can be used for data exfiltration or C2 communication",
        }
        
        reason_parts = []
        for cat in categories:
            reason_parts.append(category_reasons.get(cat, f"contains {cat}-related behavior"))
        
        return f"This function {'; '.join(reason_parts)}."
