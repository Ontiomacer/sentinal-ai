"""
YARA Scanner — Rule-based malware pattern matching for APK analysis.

Ships with built-in rules for banking trojans, fraud APKs, credential theft,
overlay attacks, and financial malware. Also supports custom rule files.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Try to import yara; gracefully degrade if not installed
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.info("yara-python not installed — using built-in pattern scanner")


@dataclass
class YaraMatch:
    """Represents a YARA rule match or pattern match."""
    rule_name: str
    category: str
    severity: str  # low, medium, high, critical
    description: str
    matched_strings: List[str]
    tags: List[str]
    meta: Dict[str, Any]


# ---------------------------------------------------------------------------
# Built-in pattern rules (no yara-python dependency required)
# ---------------------------------------------------------------------------

BUILTIN_RULES = [
    {
        "name": "BankingTrojan_Overlay",
        "category": "banking_trojan",
        "severity": "critical",
        "description": "Detects overlay attack patterns used by banking trojans to steal credentials",
        "tags": ["banking", "overlay", "credential_theft"],
        "patterns": [
            r"(?i)TYPE_APPLICATION_OVERLAY",
            r"(?i)SYSTEM_ALERT_WINDOW",
            r"(?i)WindowManager\.LayoutParams",
            r"(?i)FLAG_NOT_TOUCH_MODAL",
            r"(?i)TYPE_PHONE",
            r"(?i)android\.permission\.SYSTEM_ALERT_WINDOW",
        ],
    },
    {
        "name": "BankingTrojan_Accessibility",
        "category": "banking_trojan",
        "severity": "critical",
        "description": "Detects accessibility service abuse for credential theft and UI manipulation",
        "tags": ["banking", "accessibility", "keylogging"],
        "patterns": [
            r"(?i)AccessibilityService",
            r"(?i)onAccessibilityEvent",
            r"(?i)AccessibilityNodeInfo",
            r"(?i)performAction",
            r"(?i)BIND_ACCESSIBILITY_SERVICE",
            r"(?i)android\.accessibilityservice",
        ],
    },
    {
        "name": "SMS_Interception",
        "category": "sms_fraud",
        "severity": "high",
        "description": "Detects SMS interception capabilities used for OTP theft",
        "tags": ["sms", "otp", "fraud"],
        "patterns": [
            r"(?i)SmsReceiver",
            r"(?i)SMS_RECEIVED",
            r"(?i)android\.provider\.Telephony\.SMS",
            r"(?i)getMessageBody",
            r"(?i)SmsManager",
            r"(?i)RECEIVE_SMS",
            r"(?i)READ_SMS",
            r"(?i)SEND_SMS",
        ],
    },
    {
        "name": "CredentialTheft_Keylogging",
        "category": "credential_theft",
        "severity": "critical",
        "description": "Detects keylogging and input capture mechanisms",
        "tags": ["keylogging", "credential_theft", "input_capture"],
        "patterns": [
            r"(?i)onKey\w*",
            r"(?i)KeyEvent",
            r"(?i)InputMethodService",
            r"(?i)onTextChanged",
            r"(?i)TextWatcher",
            r"(?i)getPassword",
            r"(?i)clipboard",
            r"(?i)ClipboardManager",
        ],
    },
    {
        "name": "RemoteAccess_C2",
        "category": "remote_access",
        "severity": "high",
        "description": "Detects command-and-control communication patterns",
        "tags": ["c2", "remote_access", "backdoor"],
        "patterns": [
            r"(?i)HttpURLConnection",
            r"(?i)HttpClient",
            r"(?i)OkHttp",
            r"(?i)Retrofit",
            r"(?i)WebSocket",
            r"(?i)MQTT",
            r"(?i)Firebase.*Messaging",
        ],
    },
    {
        "name": "DataExfiltration",
        "category": "data_theft",
        "severity": "high",
        "description": "Detects data collection and exfiltration patterns",
        "tags": ["exfiltration", "data_theft", "privacy"],
        "patterns": [
            r"(?i)getDeviceId",
            r"(?i)getSubscriberId",
            r"(?i)getSimSerialNumber",
            r"(?i)getLine1Number",
            r"(?i)READ_CONTACTS",
            r"(?i)READ_CALL_LOG",
            r"(?i)READ_PHONE_STATE",
            r"(?i)CAMERA",
            r"(?i)RECORD_AUDIO",
            r"(?i)ACCESS_FINE_LOCATION",
        ],
    },
    {
        "name": "AntiAnalysis_Evasion",
        "category": "evasion",
        "severity": "medium",
        "description": "Detects anti-analysis and evasion techniques",
        "tags": ["evasion", "anti_analysis", "obfuscation"],
        "patterns": [
            r"(?i)isEmulator",
            r"(?i)isRooted",
            r"(?i)isDebugger",
            r"(?i)Debug\.isDebuggerConnected",
            r"(?i)getprop.*ro\.build",
            r"(?i)Build\.FINGERPRINT",
            r"(?i)DexClassLoader",
            r"(?i)PathClassLoader",
            r"(?i)loadDex",
        ],
    },
    {
        "name": "Crypto_Operations",
        "category": "crypto",
        "severity": "medium",
        "description": "Detects cryptographic operations that may hide malicious payloads",
        "tags": ["crypto", "encryption", "payload"],
        "patterns": [
            r"(?i)Cipher\.getInstance",
            r"(?i)SecretKeySpec",
            r"(?i)AES",
            r"(?i)DES",
            r"(?i)RSA",
            r"(?i)Base64\.decode",
            r"(?i)javax\.crypto",
        ],
    },
    {
        "name": "PhishingApp",
        "category": "phishing",
        "severity": "high",
        "description": "Detects phishing app patterns mimicking legitimate services",
        "tags": ["phishing", "social_engineering", "fraud"],
        "patterns": [
            r"(?i)WebView.*loadUrl",
            r"(?i)setWebViewClient",
            r"(?i)shouldOverrideUrlLoading",
            r"(?i)addJavascriptInterface",
            r"(?i)evaluateJavascript",
            r"(?i)@JavascriptInterface",
        ],
    },
    {
        "name": "DeviceAdmin_Abuse",
        "category": "persistence",
        "severity": "high",
        "description": "Detects device administrator abuse for persistence",
        "tags": ["persistence", "device_admin", "lock"],
        "patterns": [
            r"(?i)DeviceAdminReceiver",
            r"(?i)BIND_DEVICE_ADMIN",
            r"(?i)DevicePolicyManager",
            r"(?i)lockNow",
            r"(?i)wipeData",
            r"(?i)resetPassword",
        ],
    },
]


class YaraScanner:
    """YARA-based and pattern-based malware scanner for APK artifacts."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir
        self._compiled_rules = None
        if YARA_AVAILABLE and rules_dir and rules_dir.exists():
            self._compile_yara_rules()

    def _compile_yara_rules(self) -> None:
        """Compile YARA rules from the rules directory."""
        if not YARA_AVAILABLE or not self.rules_dir:
            return
        try:
            rule_files = list(self.rules_dir.glob("*.yar")) + list(
                self.rules_dir.glob("*.yara")
            )
            if rule_files:
                filepaths = {
                    f.stem: str(f) for f in rule_files
                }
                self._compiled_rules = yara.compile(filepaths=filepaths)
                logger.info("Compiled %d YARA rule files", len(rule_files))
        except Exception as e:
            logger.warning("Failed to compile YARA rules: %s", e)

    def scan_text(self, text: str) -> List[YaraMatch]:
        """Scan text content (decompiled code, strings, manifest) for matches."""
        matches: List[YaraMatch] = []

        # Built-in pattern scanning (always available)
        matches.extend(self._scan_builtin_patterns(text))

        # YARA rule scanning (if available)
        if YARA_AVAILABLE and self._compiled_rules:
            matches.extend(self._scan_yara_rules(text))

        return matches

    def scan_file(self, file_path: Path) -> List[YaraMatch]:
        """Scan a file for matches."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.scan_text(content)
        except Exception as e:
            logger.warning("Failed to scan file %s: %s", file_path, e)
            return []

    def scan_apk_artifacts(
        self,
        manifest: str = "",
        permissions: List[str] = None,
        strings: List[str] = None,
        decompiled_code: Dict[str, str] = None,
    ) -> List[YaraMatch]:
        """Scan all APK artifacts comprehensively."""
        all_matches: List[YaraMatch] = []

        # Scan manifest
        if manifest:
            all_matches.extend(self.scan_text(manifest))

        # Scan permissions
        if permissions:
            perm_text = "\n".join(permissions)
            all_matches.extend(self.scan_text(perm_text))

        # Scan strings
        if strings:
            # Process in chunks to avoid memory issues
            chunk_size = 1000
            for i in range(0, len(strings), chunk_size):
                chunk = "\n".join(strings[i : i + chunk_size])
                all_matches.extend(self.scan_text(chunk))

        # Scan decompiled code
        if decompiled_code:
            for filename, code in decompiled_code.items():
                file_matches = self.scan_text(code)
                for m in file_matches:
                    m.meta["source_file"] = filename
                all_matches.extend(file_matches)

        # Deduplicate by rule name
        return self._deduplicate_matches(all_matches)

    def _scan_builtin_patterns(self, text: str) -> List[YaraMatch]:
        """Scan using built-in pattern rules."""
        matches = []

        for rule in BUILTIN_RULES:
            matched_strings = []
            for pattern in rule["patterns"]:
                found = re.findall(pattern, text)
                matched_strings.extend(found[:5])  # Cap per pattern

            if matched_strings:
                matches.append(
                    YaraMatch(
                        rule_name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        description=rule["description"],
                        matched_strings=list(set(matched_strings))[:20],
                        tags=rule["tags"],
                        meta={"source": "builtin", "match_count": len(matched_strings)},
                    )
                )

        return matches

    def _scan_yara_rules(self, text: str) -> List[YaraMatch]:
        """Scan using compiled YARA rules."""
        if not self._compiled_rules:
            return []
        matches = []
        try:
            yara_matches = self._compiled_rules.match(data=text.encode("utf-8", errors="ignore"))
            for m in yara_matches:
                matched_strings = []
                if hasattr(m, "strings"):
                    for s in m.strings:
                        if hasattr(s, "instances"):
                            for inst in s.instances[:5]:
                                matched_strings.append(str(inst))
                matches.append(
                    YaraMatch(
                        rule_name=m.rule,
                        category=m.meta.get("category", "unknown"),
                        severity=m.meta.get("severity", "medium"),
                        description=m.meta.get("description", ""),
                        matched_strings=matched_strings,
                        tags=list(m.tags) if m.tags else [],
                        meta={**m.meta, "source": "yara"},
                    )
                )
        except Exception as e:
            logger.warning("YARA scanning failed: %s", e)

        return matches

    @staticmethod
    def _deduplicate_matches(matches: List[YaraMatch]) -> List[YaraMatch]:
        """Deduplicate matches by rule name, merging matched strings."""
        seen: Dict[str, YaraMatch] = {}
        for m in matches:
            if m.rule_name in seen:
                existing = seen[m.rule_name]
                existing.matched_strings = list(
                    set(existing.matched_strings + m.matched_strings)
                )[:30]
                existing.meta["match_count"] = len(existing.matched_strings)
            else:
                seen[m.rule_name] = m
        return list(seen.values())

    def get_summary(self, matches: List[YaraMatch]) -> Dict[str, Any]:
        """Generate a summary of scan results."""
        if not matches:
            return {
                "total_matches": 0,
                "severity_breakdown": {},
                "categories": [],
                "matches": [],
            }

        severity_counts = {}
        categories = set()
        for m in matches:
            severity_counts[m.severity] = severity_counts.get(m.severity, 0) + 1
            categories.add(m.category)

        return {
            "total_matches": len(matches),
            "severity_breakdown": severity_counts,
            "categories": sorted(categories),
            "matches": [asdict(m) for m in matches],
        }
