from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional

from app.services.neural_engine import get_neural_engine

logger = logging.getLogger(__name__)


class CodeInterpreter:
    """Evidence-constrained interpretation for selected decompiled code."""

    RULES = [
        {
            "behavior": "SMS handling",
            "tokens": ["SmsManager", "TelephonyManager", "SMS_RECEIVED", "sendTextMessage", "pdus", "READ_SMS", "RECEIVE_SMS"],
            "security": "May access or process SMS messages when matched with manifest capabilities.",
            "fraud": "Could support OTP interception or unauthorized SMS-based transaction flows.",
        },
        {
            "behavior": "Accessibility interaction",
            "tokens": ["AccessibilityService", "AccessibilityEvent", "performAction", "rootInActiveWindow", "AccessibilityNodeInfo"],
            "security": "May inspect UI state or automate user interface actions.",
            "fraud": "Could support account takeover by observing credentials or approving prompts.",
        },
        {
            "behavior": "Overlay or UI redress capability",
            "tokens": ["WindowManager", "TYPE_APPLICATION_OVERLAY", "SYSTEM_ALERT_WINDOW", "addView", "LayoutParams"],
            "security": "May draw UI over other applications.",
            "fraud": "Could support banking overlay fraud or credential capture if tied to login screens.",
        },
        {
            "behavior": "Network communication",
            "tokens": ["HttpURLConnection", "OkHttp", "Retrofit", "Socket", "WebSocket", "https://", "http://"],
            "security": "May communicate with remote infrastructure.",
            "fraud": "Could transmit collected data when paired with collection evidence.",
        },
        {
            "behavior": "WebView execution",
            "tokens": ["WebView", "loadUrl", "addJavascriptInterface", "evaluateJavascript"],
            "security": "May bridge JavaScript and Android code or load remote web content.",
            "fraud": "Could support phishing flows if remote/login content is loaded.",
        },
        {
            "behavior": "Dynamic loading or reflection",
            "tokens": ["DexClassLoader", "PathClassLoader", "Class.forName", "Method.invoke", "getDeclaredMethod"],
            "security": "May hide behavior from static analysis or load code at runtime.",
            "fraud": "Could fetch or activate fraud modules after installation.",
        },
        {
            "behavior": "Local storage or file access",
            "tokens": ["SharedPreferences", "SQLiteDatabase", "FileOutputStream", "openFileOutput", "getExternalStorage"],
            "security": "May persist local data on the device.",
            "fraud": "Could stage collected credentials or device identifiers for later use.",
        },
        {
            "behavior": "Cryptographic processing",
            "tokens": ["Cipher", "SecretKeySpec", "MessageDigest", "AES", "RSA", "Base64"],
            "security": "May encrypt, decrypt, hash, or encode data.",
            "fraud": "Could conceal payloads, credentials, or exfiltrated data.",
        },
        {
            "behavior": "Location or device data collection",
            "tokens": ["LocationManager", "getLastLocation", "READ_PHONE_STATE", "getDeviceId", "getImei", "ContactsContract"],
            "security": "May collect device, location, or contact data.",
            "fraud": "Could enrich victim profiling or financial social-engineering workflows.",
        },
    ]

    UNAVAILABLE_MARKERS = [
        "decompilation failed",
        "decompiled logic not cached",
        "code stub",
        "waiting for symbol",
        "select a function",
        "decompiler returned no source",
    ]

    @classmethod
    def interpret(
        cls,
        code: str,
        symbol_name: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        context = context or {}
        if not cls._has_real_source(code):
            return {
                "status": "unavailable",
                "purpose": "Source unavailable.",
                "behavior": "No behavior was inferred because decompiled source was not available.",
                "security_impact": "Unavailable.",
                "fraud_impact": "Unavailable.",
                "confidence": 0,
                "evidence": [],
                "source_used": "none",
            }

        matched = []
        evidence: List[str] = []
        for rule in cls.RULES:
            tokens = [token for token in rule["tokens"] if token.lower() in code.lower()]
            if tokens:
                matched.append({**rule, "matched_tokens": tokens})
                evidence.extend(cls._snippets(code, tokens))

        purpose = cls._purpose(symbol_name, matched)
        risk_contribution = 0
        if matched:
            behavior = "; ".join(
                f"{item['behavior']} ({', '.join(item['matched_tokens'][:5])})"
                for item in matched
            )
            security = " ".join(dict.fromkeys(item["security"] for item in matched))
            fraud = " ".join(dict.fromkeys(item["fraud"] for item in matched))
            confidence = min(90, 35 + len(matched) * 12 + min(20, len(evidence) * 2))
            
            # Simple heuristic risk contribution based on rules matched
            risk_contribution = len(matched) * 15
        else:
            behavior = "No high-risk behavior tokens were found in the selected source."
            security = "No specific security impact was inferred from this source selection."
            fraud = "No fraud impact was inferred from this source selection."
            confidence = 25

        return {
            "status": "available",
            "purpose": purpose,
            "behavior": behavior,
            "security_impact": security,
            "fraud_impact": fraud,
            "risk_contribution": min(risk_contribution, 60),
            "confidence": confidence,
            "evidence": evidence[:12],
            "matched_behaviors": [
                {
                    "behavior": item["behavior"],
                    "matched_tokens": item["matched_tokens"],
                    "security_impact": item["security"],
                    "fraud_impact": item["fraud"],
                }
                for item in matched
            ],
            "source_used": "decompiled_source",
            "context": {
                "symbol_name": symbol_name,
                "package_name": context.get("package_name"),
                "class_name": context.get("class_name"),
            },
        }

    @classmethod
    def _has_real_source(cls, code: str) -> bool:
        if not code or len(code.strip()) < 40:
            return False
        lowered = code.lower()
        if any(marker in lowered for marker in cls.UNAVAILABLE_MARKERS):
            return False
        return True

    @staticmethod
    def _purpose(symbol_name: Optional[str], matched: List[Dict[str, Any]]) -> str:
        name = (symbol_name or "").lower()
        if "onreceive" in name:
            return "Handles an Android broadcast receiver callback."
        if "oncreate" in name:
            return "Initializes an Android component or activity lifecycle entry point."
        if "onstartcommand" in name:
            return "Handles a service start lifecycle callback."
        if "decrypt" in name or "encrypt" in name:
            return "Processes encoded or cryptographic data."
        if "login" in name or "auth" in name:
            return "Handles authentication-related logic based on the symbol name."
        if matched:
            return f"Appears related to {matched[0]['behavior'].lower()} based on matched source tokens."
        return "Purpose could not be determined confidently from the selected source."

    @staticmethod
    def _snippets(code: str, tokens: List[str]) -> List[str]:
        snippets: List[str] = []
        lines = code.splitlines()
        for token in tokens:
            pattern = re.compile(re.escape(token), re.IGNORECASE)
            for line in lines:
                if pattern.search(line):
                    cleaned = line.strip()
                    if cleaned and cleaned not in snippets:
                        snippets.append(cleaned[:220])
                    break
        return snippets
