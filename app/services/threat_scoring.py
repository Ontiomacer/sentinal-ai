import json
import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ThreatSeverity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatScoring:
    """Deterministic weighted heuristic threat scoring engine."""

    PERMISSION_WEIGHTS = {
        "READ_SMS": 15,
        "RECEIVE_SMS": 15,
        "SEND_SMS": 12,
        "SYSTEM_ALERT_WINDOW": 25,
        "BIND_ACCESSIBILITY_SERVICE": 25,
        "REQUEST_INSTALL_PACKAGES": 20,
        "READ_CONTACTS": 12,
        "READ_CALL_LOG": 12,
        "WRITE_SETTINGS": 10,
        "READ_EXTERNAL_STORAGE": 5,
        "WRITE_EXTERNAL_STORAGE": 5,
        "RECEIVE_MMS": 10,
        "RECEIVE_WAP_PUSH": 10,
        "PROCESS_OUTGOING_CALLS": 12,
        "RECORD_AUDIO": 15,
        "CAMERA": 10,
        "ACCESS_FINE_LOCATION": 8,
        "ACCESS_COARSE_LOCATION": 6,
        "READ_PHONE_STATE": 8
    }

    BEHAVIORAL_PATTERNS = {
        "reflection_usage": {
            "tokens": ["Class.forName", "Method.invoke", "invoke", "reflection", "java/lang/reflect"],
            "score": 12,
            "description": "Use of reflection for dynamic behavior and evasion."
        },
        "dynamic_class_loading": {
            "tokens": ["DexClassLoader", "PathClassLoader", "loadClass", "defineClass", "ClassLoader"],
            "score": 15,
            "description": "Dynamic code loading at runtime."
        },
        "overlay_attacks": {
            "tokens": ["SYSTEM_ALERT_WINDOW", "overlay", "alert_window", "type_application_overlay"],
            "score": 20,
            "description": "Overlay attack capability detected."
        },
        "accessibility_abuse": {
            "tokens": ["BIND_ACCESSIBILITY_SERVICE", "AccessibilityService", "accessibility_event"],
            "score": 20,
            "description": "Accessibility abuse potential detected."
        },
        "webview_injection": {
            "tokens": ["WebView", "loadUrl", "addJavascriptInterface", "evaluateJavascript"],
            "score": 18,
            "description": "WebView injection or malicious web content loading."
        },
        "hardcoded_c2": {
            "tokens": ["http://", "https://", "c2", "command", "control", "payload", "api"],
            "score": 15,
            "description": "Hardcoded command-and-control or remote control indicators."
        },
        "anti_debugging": {
            "tokens": ["debuggable", "android:debuggable", "ptrace", "Debug.isDebuggerConnected"],
            "score": 15,
            "description": "Anti-debugging or analysis evasion behavior."
        },
        "obfuscation": {
            "tokens": ["obfus", "proguard", "dexguard", "minify", "shrink", "encrypted", "encoded", "a.a.a"],
            "score": 15,
            "description": "Obfuscation or packing detected in the APK."
        },
        "native_library_abuse": {
            "tokens": [".so", "JNI", "System.loadLibrary", "native"],
            "score": 15,
            "description": "Native library usage may conceal malicious operations."
        },
        "credential_harvesting": {
            "tokens": ["password", "auth", "token", "login", "username", "pin", "secure_input"],
            "score": 18,
            "description": "Credential harvesting capability detected."
        },
        "financial_app_targeting": {
            "tokens": ["com.android.vending", "com.android.settings", "com.google.android.gms", "paypal", "binance", "coinbase", "trustwallet", "metamask", "blockchain"],
            "score": 15,
            "description": "Evidence of targeting financial or system applications."
        },
        "banking_trojan_indicators": {
            "tokens": ["anubis", "hydra", "ermac", "teabot", "cerberus", "alien", "medusa", "fluubot"],
            "score": 25,
            "description": "Signatures matching known banking trojan families detected."
        }
    }

    URL_SUSPICION_TOKENS = ["bank", "pay", "login", "auth", "secure", "c2", "control", "command", "api"]
    CRYPTO_TOKENS = ["aes", "rsa", "sha", "md5", "hmac", "crypto", "cipher", "key"]

    @staticmethod
    def calculate_threat_score(apk_data: Dict[str, Any]) -> Dict[str, Any]:
        if apk_data.get("analysis_failed"):
            return {
                "risk_score": 0,
                "severity": ThreatSeverity.LOW,
                "summary": "Static APK analysis failed. Risk scoring unavailable.",
                "findings": ["Analysis failed. No threat score could be calculated."],
                "score_breakdown": {},
                "indicators": [],
                "suspicious_permissions": [],
                "iocs": {}
            }

        findings: List[str] = []
        indicators: List[Dict[str, Any]] = []
        score_breakdown: Dict[str, int] = {}
        total_score = 0

        permission_score, permission_findings, suspicious_permissions = ThreatScoring._score_permissions(
            apk_data.get("permissions", [])
        )
        total_score += permission_score
        findings.extend(permission_findings)
        score_breakdown["permissions"] = permission_score

        behavior_score, behavior_findings, behavior_indicators = ThreatScoring._score_behavioral_patterns(apk_data)
        total_score += behavior_score
        findings.extend(behavior_findings)
        score_breakdown["behavioral_indicators"] = behavior_score
        indicators.extend(behavior_indicators)

        network_score, network_findings, network_indicators = ThreatScoring._score_network_artifacts(apk_data)
        total_score += network_score
        findings.extend(network_findings)
        score_breakdown["network"] = network_score
        indicators.extend(network_indicators)

        native_score, native_findings, native_indicators = ThreatScoring._score_native_code(apk_data)
        total_score += native_score
        findings.extend(native_findings)
        score_breakdown["native_code"] = native_score
        indicators.extend(native_indicators)

        obfuscation_score, obfuscation_findings, obfuscation_indicators = ThreatScoring._score_obfuscation(apk_data)
        total_score += obfuscation_score
        findings.extend(obfuscation_findings)
        score_breakdown["obfuscation"] = obfuscation_score
        indicators.extend(obfuscation_indicators)

        # 6. Check persistence
        persistence_score, persistence_findings = ThreatScoring._score_persistence(apk_data)
        total_score += persistence_score
        findings.extend(persistence_findings)
        score_breakdown["persistence"] = persistence_score

        # 6b. Check for suspicious combinations
        combo_score, combo_findings = ThreatScoring._score_combinations(suspicious_permissions)
        total_score += combo_score
        findings.extend(combo_findings)
        score_breakdown["suspicious_combinations"] = combo_score

        # 7. Check SDK version
        sdk_score, sdk_findings = ThreatScoring._score_sdk_version(
            apk_data.get("target_sdk_version"),
            apk_data.get("min_sdk_version")
        )
        total_score += sdk_score
        findings.extend(sdk_findings)
        score_breakdown["sdk_version"] = sdk_score

        # 8. Check signing status
        signing_score, signing_findings = ThreatScoring._score_signing(
            apk_data.get("is_signed"),
            apk_data.get("is_valid_apk")
        )
        total_score += signing_score
        findings.extend(signing_findings)
        score_breakdown["signing"] = signing_score

        total_score = min(total_score, 100)
        severity = ThreatScoring._determine_severity(total_score)
        summary = ThreatScoring._generate_summary(total_score, severity, findings)

        return {
            "risk_score": total_score,
            "severity": severity,
            "summary": summary,
            "findings": findings,
            "score_breakdown": score_breakdown,
            "indicators": indicators,
            "suspicious_permissions": suspicious_permissions,
            "iocs": ThreatScoring._extract_iocs(apk_data)
        }

    @staticmethod
    def _normalize_permission(perm: str) -> str:
        return perm.split(".")[-1].strip().upper()

    @staticmethod
    def _score_permissions(permissions: List[Dict[str, Any]]) -> Any:
        score = 0
        findings: List[str] = []
        suspicious_permissions: List[str] = []

        for perm in permissions:
            name = ThreatScoring._normalize_permission(str(perm.get("name", "")))
            if name in ThreatScoring.PERMISSION_WEIGHTS:
                weight = ThreatScoring.PERMISSION_WEIGHTS[name]
                score += weight
                suspicious_permissions.append(name)
                findings.append(f"Detected high-risk permission {name} (+{weight}).")

        if len(suspicious_permissions) > 5:
            extra = (len(suspicious_permissions) - 5) * 2
            score += extra
            findings.append(f"Multiple high-risk permissions present (+{extra}).")

        return score, findings, suspicious_permissions

    @staticmethod
    def _score_behavioral_patterns(apk_data: Dict[str, Any]) -> Any:
        score = 0
        findings: List[str] = []
        indicators: List[Dict[str, Any]] = []

        evidence_text = ThreatScoring._artifact_text(apk_data)
        for key, pattern in ThreatScoring.BEHAVIORAL_PATTERNS.items():
            matches = [token for token in pattern["tokens"] if token.lower() in evidence_text]
            if matches:
                pattern_score = pattern["score"]
                score += pattern_score
                findings.append(f"Behavioral indicator detected: {pattern['description']} (+{pattern_score}).")
                indicators.append({
                    "type": key,
                    "description": pattern["description"],
                    "matched_tokens": matches,
                    "score": pattern_score
                })

        return score, findings, indicators

    @staticmethod
    def _score_network_artifacts(apk_data: Dict[str, Any]) -> Any:
        score = 0
        findings: List[str] = []
        indicators: List[Dict[str, Any]] = []

        urls = apk_data.get("urls", [])
        domains = apk_data.get("domains", [])
        suspects = []

        for url in urls:
            if any(token in url.lower() for token in ThreatScoring.URL_SUSPICION_TOKENS):
                suspects.append(url)

        for domain in domains:
            if any(token in domain.lower() for token in ThreatScoring.URL_SUSPICION_TOKENS):
                suspects.append(domain)

        if suspects:
            network_score = min(25, len(suspects) * 5)
            score += network_score
            findings.append(f"Network artifacts indicate suspicious remote hosts (+{network_score}).")
            indicators.append({
                "type": "hardcoded_c2",
                "description": "Potential command-and-control or suspicious remote endpoint.",
                "matched_values": suspects,
                "score": network_score
            })

        return score, findings, indicators

    @staticmethod
    def _score_native_code(apk_data: Dict[str, Any]) -> Any:
        score = 0
        findings: List[str] = []
        indicators: List[Dict[str, Any]] = []

        native_libraries = apk_data.get("native_libraries", [])
        if native_libraries:
            score += 15
            findings.append("Native libraries present; could conceal low-level malicious behavior (+15).")
            indicators.append({
                "type": "native_library_abuse",
                "description": "Native library usage detected.",
                "matched_values": native_libraries,
                "score": 15
            })

        return score, findings, indicators

    @staticmethod
    def _score_obfuscation(apk_data: Dict[str, Any]) -> Any:
        score = 0
        findings: List[str] = []
        indicators: List[Dict[str, Any]] = []

        evidence_text = ThreatScoring._artifact_text(apk_data)
        matches = [token for token in ThreatScoring.BEHAVIORAL_PATTERNS["obfuscation"]["tokens"] if token.lower() in evidence_text]
        if matches:
            score += ThreatScoring.BEHAVIORAL_PATTERNS["obfuscation"]["score"]
            findings.append("Obfuscation or packing patterns detected (+15).")
            indicators.append({
                "type": "obfuscation",
                "description": "Potential obfuscation or protection mechanisms.",
                "matched_tokens": matches,
                "score": ThreatScoring.BEHAVIORAL_PATTERNS["obfuscation"]["score"]
            })

        return score, findings, indicators

    @staticmethod
    def _score_combinations(permissions: List[str]) -> Any:
        score = 0
        findings = []
        
        combinations = [
            {
                "permissions": ["READ_SMS", "SEND_SMS", "INTERNET"],
                "score": 20,
                "description": "SMS reading/sending with internet access (potential SMS fraud)"
            },
            {
                "permissions": ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"],
                "score": 25,
                "description": "Overlay attacks with accessibility service (potential clickjacking/credential theft)"
            },
            {
                "permissions": ["READ_CONTACTS", "INTERNET", "ACCESS_FINE_LOCATION"],
                "score": 15,
                "description": "Contact and location exfiltration capability"
            },
            {
                "permissions": ["RECORD_AUDIO", "INTERNET"],
                "score": 18,
                "description": "Audio recording with internet access (potential eavesdropping)"
            },
            {
                "permissions": ["CAMERA", "INTERNET"],
                "score": 15,
                "description": "Camera access with internet (potential surveillance)"
            },
            {
                "permissions": ["REQUEST_INSTALL_PACKAGES", "INTERNET"],
                "score": 20,
                "description": "App installation capability (potential malware dropper)"
            }
        ]
        
        perms_set = {p.upper() for p in permissions}
        for combo in combinations:
            combo_perms = {p.upper() for p in combo["permissions"]}
            if combo_perms.issubset(perms_set):
                score += combo["score"]
                findings.append(f"Suspicious combination: {combo['description']} (+{combo['score']}).")
                
        return score, findings

    @staticmethod
    def _score_persistence(apk_data: Dict[str, Any]) -> Any:
        score = 0
        findings: List[str] = []

        # Check for BOOT_COMPLETED or similar persistence triggers
        receiver_actions = []
        for receiver in apk_data.get("receivers", []):
            if isinstance(receiver, dict):
                receiver_actions.extend(receiver.get("actions", []))
        
        manifest = apk_data.get("manifest", {})
        if isinstance(manifest, dict):
            receiver_actions.extend(manifest.get("intent_actions", []))

        persistence_actions = ["BOOT_COMPLETED", "QUICKBOOT_POWERON", "PACKAGE_REPLACED", "USER_PRESENT"]
        found_actions = [a for a in receiver_actions if any(p in str(a).upper() for p in persistence_actions)]
        
        if found_actions:
            score += 10
            findings.append(f"Persistence triggers detected: {', '.join(set(found_actions[:3]))} (+10).")

        return score, findings

    @staticmethod
    def _score_sdk_version(target_sdk: Any, min_sdk: Any) -> Any:
        score = 0
        findings = []
        
        try:
            if target_sdk and int(target_sdk) < 26:
                score += 10
                findings.append(f"Targets old Android version (API {target_sdk}) - bypasses modern security (+10).")
            if min_sdk and int(min_sdk) < 21:
                score += 5
                findings.append(f"Supports very old Android versions (API {min_sdk}) (+5).")
        except (ValueError, TypeError):
            pass
            
        return score, findings

    @staticmethod
    def _score_signing(is_signed: bool, is_valid: bool) -> Any:
        score = 0
        findings = []
        
        if is_signed is False:
            score += 20
            findings.append("APK is not digitally signed (+20).")
        if is_valid is False:
            score += 15
            findings.append("APK signature or structure is invalid (+15).")
            
        return score, findings

    @staticmethod
    def _artifact_text(apk_data: Dict[str, Any]) -> str:
        fragments: List[str] = []
        fragments.extend([str(apk_data.get("package_name", "")), str(apk_data.get("app_name", ""))])
        fragments.extend([p.get("name", "") for p in apk_data.get("permissions", [])])
        fragments.extend([c.get("name", "") for c in apk_data.get("activities", [])])
        fragments.extend([c.get("name", "") for c in apk_data.get("services", [])])
        fragments.extend([c.get("name", "") for c in apk_data.get("receivers", [])])
        fragments.extend([c.get("name", "") for c in apk_data.get("providers", [])])
        fragments.extend(apk_data.get("urls", []))
        fragments.extend(apk_data.get("domains", []))
        fragments.extend(apk_data.get("native_libraries", []))
        return " ".join([str(item).lower() for item in fragments if item])

    @staticmethod
    def _extract_iocs(apk_data: Dict[str, Any]) -> Dict[str, List[str]]:
        urls = apk_data.get("urls", [])
        domains = apk_data.get("domains", [])
        ips = ThreatScoring._extract_ips(urls)
        suspicious_package_names = []
        package_name = apk_data.get("package_name", "")
        app_name = apk_data.get("app_name", "")

        if package_name and any(token in package_name.lower() for token in ["bank", "pay", "secure", "wallet", "login"]):
            suspicious_package_names.append(package_name)
        if app_name and any(token in app_name.lower() for token in ["bank", "pay", "secure", "wallet", "login"]):
            suspicious_package_names.append(app_name)

        crypto_constants = [item for item in urls + domains if any(token in item.lower() for token in ThreatScoring.CRYPTO_TOKENS)]

        return {
            "urls": urls[:50],
            "domains": domains[:50],
            "ips": ips,
            "suspicious_package_names": list(dict.fromkeys(suspicious_package_names)),
            "crypto_constants": list(dict.fromkeys(crypto_constants))
        }

    @staticmethod
    def _extract_ips(values: List[str]) -> List[str]:
        ips = set()
        for value in values:
            for match in re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", value):
                parsed = match.split(".")
                if all(0 <= int(part) <= 255 for part in parsed):
                    ips.add(match)
        return list(ips)

    @staticmethod
    def _determine_severity(score: int) -> str:
        if score >= 70:
            return ThreatSeverity.CRITICAL
        if score >= 45:
            return ThreatSeverity.HIGH
        if score >= 25:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW

    @staticmethod
    def _generate_summary(score: int, severity: str, findings: List[str]) -> str:
        if not findings:
            return "No significant malicious indicators were detected during static APK analysis."

        return f"The APK earned a threat score of {score}/100 and is classified as {severity}. Key findings: {findings[:3]}."
