from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence


@dataclass(frozen=True)
class AssessmentFinding:
    title: str
    detail: str
    evidence: List[str]
    risk: str
    score: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "risk": self.risk,
            "score": self.score,
        }


class SecurityAssessmentEngine:
    """Deterministic APK security assessment generated only from extracted data."""

    SENSITIVE_PERMISSION_RULES = {
        "ACCESS_FINE_LOCATION": ("Location access", "Can access precise device location.", "privacy", 8),
        "ACCESS_COARSE_LOCATION": ("Location access", "Can access approximate device location.", "privacy", 6),
        "READ_EXTERNAL_STORAGE": ("Storage access", "Can read shared storage content.", "privacy", 5),
        "WRITE_EXTERNAL_STORAGE": ("Storage write access", "Can modify shared storage content.", "privacy", 5),
        "READ_MEDIA_IMAGES": ("Media access", "Can read image media from the device.", "privacy", 5),
        "READ_MEDIA_VIDEO": ("Media access", "Can read video media from the device.", "privacy", 5),
        "READ_CONTACTS": ("Contact access", "Can read contact data.", "privacy", 12),
        "GET_ACCOUNTS": ("Account access", "Can enumerate device accounts.", "privacy", 10),
        "READ_PHONE_STATE": ("Phone state access", "Can read device and SIM identifiers.", "privacy", 8),
        "READ_SMS": ("SMS access", "Can read SMS content, including potential OTP messages.", "threat", 15),
        "RECEIVE_SMS": ("SMS receiver", "Can receive SMS messages.", "threat", 15),
        "SEND_SMS": ("SMS sending", "Can send SMS messages.", "threat", 12),
        "SYSTEM_ALERT_WINDOW": ("Overlay capability", "Can draw overlays above other applications.", "threat", 25),
        "BIND_ACCESSIBILITY_SERVICE": ("Accessibility service", "Can observe and interact with UI content if enabled.", "threat", 25),
        "REQUEST_INSTALL_PACKAGES": ("Package installation", "Can request installation of additional APKs.", "threat", 20),
        "RECORD_AUDIO": ("Microphone access", "Can record audio.", "privacy", 15),
        "CAMERA": ("Camera access", "Can capture images or video.", "privacy", 10),
    }

    API_CATEGORY_RULES = {
        "dynamic_loading": ("Dynamic code loading", "Dynamic loading APIs were identified.", 20),
        "reflection": ("Reflection usage", "Reflection APIs were identified.", 12),
        "accessibility": ("Accessibility API usage", "Accessibility API references were identified.", 20),
        "sms": ("SMS API usage", "SMS or telephony API references were identified.", 15),
        "network": ("Network API usage", "Network communication API references were identified.", 10),
    }

    TRUSTED_DOMAIN_HINTS = (
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "firebaseio.com",
        "firebaseapp.com",
        "android.com",
        "samsung.com",
    )

    @classmethod
    def generate(
        cls,
        apk_data: Dict[str, Any],
        risk_assessment: Optional[Dict[str, Any]] = None,
        analysis_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        apk_data = apk_data if isinstance(apk_data, dict) else {}
        risk_assessment = risk_assessment if isinstance(risk_assessment, dict) else {}
        analysis_metadata = analysis_metadata if isinstance(analysis_metadata, dict) else {}

        permissions = cls._list(apk_data.get("permissions"))
        activities = cls._list(apk_data.get("activities"))
        services = cls._list(apk_data.get("services"))
        receivers = cls._list(apk_data.get("receivers"))
        providers = cls._list(apk_data.get("providers"))
        exported = cls._list(apk_data.get("exported_components"))
        api_usage = cls._list(apk_data.get("api_usage"))
        certificates = cls._list(apk_data.get("certificates"))
        domains = cls._list(apk_data.get("domains"))
        urls = cls._list(apk_data.get("urls"))
        strings = cls._list(apk_data.get("strings"))

        permission_findings = cls._permission_findings(permissions)
        component_findings = cls._component_findings(activities, services, receivers, providers, exported)
        network_findings = cls._network_findings(domains, urls, permissions, api_usage)
        certificate_findings = cls._certificate_findings(apk_data, certificates)
        privacy_findings = cls._privacy_findings(permission_findings, strings, domains)
        threat_findings = cls._threat_findings(apk_data, permission_findings, api_usage, strings, domains, exported)
        sdk_findings = cls._sdk_findings(apk_data)

        findings = (
            permission_findings
            + component_findings
            + network_findings
            + certificate_findings
            + privacy_findings
            + threat_findings
            + sdk_findings
        )

        score = cls._score(apk_data, risk_assessment, findings)
        severity = cls.classify(score)
        confidence = cls._confidence(apk_data, permissions, activities, services, receivers, providers, exported, certificates)
        contributors = cls._contributors(findings, risk_assessment)
        sections = cls._sections(
            apk_data=apk_data,
            severity=severity,
            score=score,
            confidence=confidence,
            permission_findings=permission_findings,
            component_findings=component_findings,
            network_findings=network_findings,
            certificate_findings=certificate_findings,
            privacy_findings=privacy_findings,
            threat_findings=threat_findings,
            sdk_findings=sdk_findings,
            contributors=contributors,
        )
        recommendations = cls._recommendations(
            severity=severity,
            exported=exported,
            network_findings=network_findings,
            certificate_findings=certificate_findings,
            permission_findings=permission_findings,
            threat_findings=threat_findings,
        )
        sections["recommendations"] = {
            "title": "Recommendations",
            "summary": "Recommended analyst actions derived from static APK findings.",
            "items": recommendations,
        }

        verdict = cls._format_verdict(sections)
        key_findings = cls._key_findings(findings, domains, exported, permissions)

        return {
            "provider": "rule_based",
            "engine": "Sentinel Assessment Engine",
            "model": "Sentinel Assessment Engine",
            "status": "available",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence_based": True,
            "verdict": verdict,
            "risk_score": score,
            "threat_level": severity,
            "severity": severity,
            "malicious_confidence": confidence["overall"],
            "confidence": confidence,
            "key_findings": key_findings,
            "risk_contributors": contributors,
            "sections": sections,
            "recommendations": recommendations,
            "metadata": {
                **analysis_metadata,
                "inputs": {
                    "permissions": len(permissions),
                    "activities": len(activities),
                    "services": len(services),
                    "receivers": len(receivers),
                    "providers": len(providers),
                    "exported_components": len(exported),
                    "api_usage": len(api_usage),
                    "domains": len(domains),
                    "urls": len(urls),
                    "strings": len(strings),
                    "certificates": len(certificates),
                },
            },
        }

    @staticmethod
    def classify(score: int) -> str:
        score = max(0, min(100, int(score or 0)))
        if score <= 25:
            return "LOW"
        if score <= 50:
            return "MEDIUM"
        if score <= 75:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _list(value: Any) -> List[Any]:
        return value if isinstance(value, list) else []

    @staticmethod
    def _name(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("name") or item.get("function_name") or item.get("domain") or item.get("url") or "")
        return str(item or "")

    @staticmethod
    def _permission_short(permission: Any) -> str:
        name = SecurityAssessmentEngine._name(permission)
        return name.split(".")[-1] if name else ""

    @classmethod
    def _permission_findings(cls, permissions: Sequence[Any]) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        seen = set()
        for permission in permissions:
            short = cls._permission_short(permission)
            if not short or short in seen:
                continue
            seen.add(short)
            rule = cls.SENSITIVE_PERMISSION_RULES.get(short)
            if not rule:
                continue
            title, detail, category, score = rule
            risk = "HIGH" if score >= 20 else "MEDIUM" if score >= 10 else "LOW"
            findings.append(AssessmentFinding(
                title=title,
                detail=detail,
                evidence=[f"Manifest permission: {short}"],
                risk=risk,
                score=score,
            ))
        return findings

    @staticmethod
    def _component_findings(
        activities: Sequence[Any],
        services: Sequence[Any],
        receivers: Sequence[Any],
        providers: Sequence[Any],
        exported: Sequence[Any],
    ) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        if exported:
            evidence = []
            for item in exported[:8]:
                if isinstance(item, dict):
                    label = item.get("type") or item.get("kind") or "component"
                    name = item.get("name") or item.get("value")
                    evidence.append(f"{label}: {name}")
                else:
                    evidence.append(str(item))
            findings.append(AssessmentFinding(
                title="Exported component exposure",
                detail=f"{len(exported)} exported Android component(s) are visible to other apps and require intent/permission review.",
                evidence=evidence,
                risk="MEDIUM" if len(exported) < 5 else "HIGH",
                score=min(20, len(exported) * 4),
            ))
        if receivers:
            boot_receivers = []
            for receiver in receivers:
                if isinstance(receiver, dict):
                    actions = " ".join(str(action) for action in receiver.get("actions", []))
                    if "BOOT_COMPLETED" in actions or "USER_PRESENT" in actions:
                        boot_receivers.append(receiver.get("name") or actions)
            if boot_receivers:
                findings.append(AssessmentFinding(
                    title="Persistence-capable receiver",
                    detail="Receiver actions include boot or user-present triggers.",
                    evidence=[str(item) for item in boot_receivers[:5]],
                    risk="MEDIUM",
                    score=10,
                ))
        if activities or services or providers:
            findings.append(AssessmentFinding(
                title="Manifest component inventory recovered",
                detail=f"Static analysis recovered {len(activities)} activities, {len(services)} services, {len(receivers)} receivers, and {len(providers)} providers.",
                evidence=[
                    f"Activities: {len(activities)}",
                    f"Services: {len(services)}",
                    f"Receivers: {len(receivers)}",
                    f"Providers: {len(providers)}",
                ],
                risk="INFO",
                score=0,
            ))
        return findings

    @classmethod
    def _network_findings(
        cls,
        domains: Sequence[Any],
        urls: Sequence[Any],
        permissions: Sequence[Any],
        api_usage: Sequence[Any],
    ) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        network_permission = any(cls._permission_short(permission) == "INTERNET" for permission in permissions)
        network_apis = [
            str(api.get("category") or api.get("name") or api)
            for api in api_usage
            if isinstance(api, dict) and str(api.get("category", "")).lower() == "network"
        ]
        remote = [str(item) for item in list(domains) + list(urls) if item]
        non_platform = [
            value for value in remote
            if not any(hint in value.lower() for hint in cls.TRUSTED_DOMAIN_HINTS)
        ]
        if remote:
            findings.append(AssessmentFinding(
                title="External network artifacts",
                detail=f"{len(remote)} domain/URL artifact(s) were extracted from APK strings.",
                evidence=remote[:8],
                risk="MEDIUM" if non_platform else "LOW",
                score=min(25, max(5, len(non_platform) * 5)),
            ))
        elif network_permission or network_apis:
            evidence = ["Manifest permission: INTERNET"] if network_permission else []
            evidence.extend(network_apis[:5])
            findings.append(AssessmentFinding(
                title="Network capability without extracted endpoints",
                detail="Network capability exists, but static analysis did not extract hardcoded domains or URLs.",
                evidence=evidence,
                risk="LOW",
                score=5,
            ))
        return findings

    @staticmethod
    def _certificate_findings(apk_data: Dict[str, Any], certificates: Sequence[Any]) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        is_signed = apk_data.get("is_signed")
        is_valid = apk_data.get("is_valid_apk")
        if certificates:
            first = certificates[0] if isinstance(certificates[0], dict) else {}
            evidence = [
                f"Subject: {first.get('subject')}",
                f"Issuer: {first.get('issuer')}",
                f"SHA256: {first.get('sha256') or first.get('fingerprint_sha256')}",
            ]
            findings.append(AssessmentFinding(
                title="Signing certificate recovered",
                detail="APK signing certificate metadata was extracted for trust-chain review.",
                evidence=[item for item in evidence if item and not item.endswith("None")],
                risk="INFO" if is_valid is not False else "MEDIUM",
                score=0 if is_valid is not False else 10,
            ))
        elif is_signed is False:
            findings.append(AssessmentFinding(
                title="APK signing not verified",
                detail="Static analysis reports the APK is not signed.",
                evidence=["is_signed: false"],
                risk="HIGH",
                score=20,
            ))
        else:
            findings.append(AssessmentFinding(
                title="Certificate metadata unavailable",
                detail="No certificate metadata was extracted from the APK container.",
                evidence=["certificates: 0"],
                risk="LOW",
                score=0,
            ))
        return findings

    @staticmethod
    def _privacy_findings(
        permission_findings: Sequence[AssessmentFinding],
        strings: Sequence[Any],
        domains: Sequence[Any],
    ) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        privacy = [item for item in permission_findings if "privacy" in item.title.lower() or item.title in {
            "Location access", "Storage access", "Storage write access", "Media access",
            "Contact access", "Account access", "Phone state access", "Microphone access", "Camera access"
        }]
        if privacy:
            evidence = [ev for finding in privacy for ev in finding.evidence][:8]
            findings.append(AssessmentFinding(
                title="Privacy-sensitive permission set",
                detail=f"{len(privacy)} privacy-sensitive permission category/categories were identified.",
                evidence=evidence,
                risk="MEDIUM" if len(privacy) >= 3 else "LOW",
                score=min(15, len(privacy) * 4),
            ))
        sensitive_tokens = [
            str(value) for value in strings[:500]
            if any(token in str(value).lower() for token in ("password", "token", "apikey", "api_key", "secret", "otp", "pin"))
        ]
        if sensitive_tokens:
            findings.append(AssessmentFinding(
                title="Sensitive string tokens",
                detail="Credential, token, OTP, or secret-like keywords were present in extracted strings.",
                evidence=sensitive_tokens[:8],
                risk="MEDIUM",
                score=10,
            ))
        if privacy and domains:
            findings.append(AssessmentFinding(
                title="Privacy data with outbound network surface",
                detail="Privacy-sensitive permissions coexist with extracted external network artifacts.",
                evidence=[*privacy[0].evidence[:2], *[str(domain) for domain in domains[:3]]],
                risk="MEDIUM",
                score=10,
            ))
        return findings

    @classmethod
    def _threat_findings(
        cls,
        apk_data: Dict[str, Any],
        permission_findings: Sequence[AssessmentFinding],
        api_usage: Sequence[Any],
        strings: Sequence[Any],
        domains: Sequence[Any],
        exported: Sequence[Any],
    ) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        perm_titles = {item.title for item in permission_findings}
        if "Accessibility service" in perm_titles:
            findings.append(AssessmentFinding(
                title="Accessibility abuse review required",
                detail="Accessibility service capability can be abused for screen reading or UI automation if the user enables it.",
                evidence=["Manifest permission: BIND_ACCESSIBILITY_SERVICE"],
                risk="HIGH",
                score=25,
            ))
        if "Overlay capability" in perm_titles:
            findings.append(AssessmentFinding(
                title="Overlay fraud review required",
                detail="Overlay capability can support phishing overlays above banking or payment apps.",
                evidence=["Manifest permission: SYSTEM_ALERT_WINDOW"],
                risk="HIGH",
                score=25,
            ))
        if any(title in perm_titles for title in ("SMS access", "SMS receiver", "SMS sending")):
            findings.append(AssessmentFinding(
                title="SMS/OTP abuse review required",
                detail="SMS permissions can support OTP interception or premium-message abuse.",
                evidence=[ev for item in permission_findings if "SMS" in item.title for ev in item.evidence],
                risk="HIGH",
                score=20,
            ))
        for api in api_usage:
            if not isinstance(api, dict):
                continue
            category = str(api.get("category") or "").lower()
            rule = cls.API_CATEGORY_RULES.get(category)
            if not rule:
                continue
            title, detail, score = rule
            evidence = [str(token) for token in api.get("matched_tokens", [])[:5]] or [str(api.get("name") or category)]
            findings.append(AssessmentFinding(
                title=title,
                detail=detail,
                evidence=evidence,
                risk="HIGH" if score >= 20 else "MEDIUM",
                score=score,
            ))
        malware_tokens = [
            str(value) for value in strings[:1000]
            if any(token in str(value).lower() for token in ("anubis", "hydra", "ermac", "teabot", "cerberus", "alien", "medusa", "fluubot"))
        ]
        if malware_tokens:
            findings.append(AssessmentFinding(
                title="Known malware-family token",
                detail="Extracted strings contain tokens associated with known Android banking malware families.",
                evidence=malware_tokens[:8],
                risk="CRITICAL",
                score=25,
            ))
        if not findings:
            evidence = []
            if domains:
                evidence.append("Network domains extracted but no known malware-family tokens were found.")
            if exported:
                evidence.append("Exported components exist and require review, but no command execution or known-family token was identified.")
            if not evidence:
                evidence.append("No high-confidence threat indicators were identified in permissions, APIs, strings, or network artifacts.")
            findings.append(AssessmentFinding(
                title="No high-confidence malware indicator",
                detail="Static analysis did not identify known malware-family strings, command execution APIs, SMS abuse, overlay abuse, or accessibility abuse.",
                evidence=evidence,
                risk="INFO",
                score=0,
            ))
        return findings

    @staticmethod
    def _sdk_findings(apk_data: Dict[str, Any]) -> List[AssessmentFinding]:
        findings: List[AssessmentFinding] = []
        target_sdk = apk_data.get("target_sdk_version")
        min_sdk = apk_data.get("min_sdk_version")
        evidence = []
        score = 0
        try:
            if target_sdk is not None and str(target_sdk) != "" and int(target_sdk) < 26:
                evidence.append(f"targetSdkVersion: {target_sdk}")
                score += 10
            if min_sdk is not None and str(min_sdk) != "" and int(min_sdk) < 21:
                evidence.append(f"minSdkVersion: {min_sdk}")
                score += 5
        except (TypeError, ValueError):
            evidence = []
            score = 0
        if evidence:
            findings.append(AssessmentFinding(
                title="Legacy Android SDK target",
                detail="The APK targets older Android API levels with weaker platform behavior controls.",
                evidence=evidence,
                risk="MEDIUM",
                score=score,
            ))
        return findings

    @classmethod
    def _score(cls, apk_data: Dict[str, Any], risk_assessment: Dict[str, Any], findings: Sequence[AssessmentFinding]) -> int:
        evidence_score = sum(max(0, finding.score) for finding in findings)
        factor_score = sum(
            cls._score_from_text(item)
            for item in risk_assessment.get("risk_factors", [])
            if isinstance(item, str)
        )
        contributor_score = sum(
            int(item.get("score") or 0)
            for item in risk_assessment.get("contributors", [])
            if isinstance(item, dict) and str(item.get("score") or "").isdigit()
        )
        return max(0, min(100, max(evidence_score, factor_score, contributor_score)))

    @classmethod
    def _confidence(
        cls,
        apk_data: Dict[str, Any],
        permissions: Sequence[Any],
        activities: Sequence[Any],
        services: Sequence[Any],
        receivers: Sequence[Any],
        providers: Sequence[Any],
        exported: Sequence[Any],
        certificates: Sequence[Any],
    ) -> Dict[str, Any]:
        cert_score = 0
        if certificates:
            cert_score = 25
        elif apk_data.get("is_signed") is not None or apk_data.get("is_valid_apk") is not None:
            cert_score = 15

        permission_score = 25 if isinstance(apk_data.get("permissions"), list) else 0

        manifest_fields = [
            bool(apk_data.get("package_name")),
            isinstance(apk_data.get("manifest"), dict),
            apk_data.get("main_activity") is not None,
            apk_data.get("target_sdk_version") is not None or apk_data.get("min_sdk_version") is not None,
        ]
        manifest_score = int(round((sum(1 for item in manifest_fields if item) / len(manifest_fields)) * 25))

        component_lists = [
            isinstance(apk_data.get("activities"), list),
            isinstance(apk_data.get("services"), list),
            isinstance(apk_data.get("receivers"), list),
            isinstance(apk_data.get("providers"), list),
            isinstance(apk_data.get("exported_components"), list),
        ]
        component_score = int(round((sum(1 for item in component_lists if item) / len(component_lists)) * 25))

        overall = cert_score + permission_score + manifest_score + component_score
        return {
            "overall": max(0, min(100, overall)),
            "certificate_validity": cert_score,
            "permissions_analyzed": permission_score,
            "manifest_completeness": manifest_score,
            "component_visibility": component_score,
            "basis": [
                f"certificate_validity={cert_score}/25",
                f"permissions_analyzed={permission_score}/25 ({len(permissions)} permission records)",
                f"manifest_completeness={manifest_score}/25",
                f"component_visibility={component_score}/25 ({len(activities)} activities, {len(services)} services, {len(receivers)} receivers, {len(providers)} providers, {len(exported)} exported)",
            ],
        }

    @staticmethod
    def _contributors(findings: Sequence[AssessmentFinding], risk_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        contributors = []
        for finding in findings:
            if finding.score > 0:
                contributors.append({
                    "label": finding.title,
                    "score": finding.score,
                    "evidence": finding.evidence[:5],
                })
        for item in risk_assessment.get("risk_factors", []):
            if not isinstance(item, str):
                continue
            contributors.append({
                "label": item.split("(")[0].strip(),
                "score": SecurityAssessmentEngine._score_from_text(item),
                "evidence": [item],
            })
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for item in contributors:
            key = (item.get("label"), tuple(item.get("evidence", [])))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:20]

    @staticmethod
    def _score_from_text(value: str) -> int:
        marker = "+"
        if marker not in value:
            return 0
        tail = value.split(marker, 1)[1]
        digits = ""
        for ch in tail:
            if ch.isdigit():
                digits += ch
            elif digits:
                break
        return int(digits) if digits else 0

    @staticmethod
    def _items(findings: Sequence[AssessmentFinding]) -> List[Dict[str, Any]]:
        return [finding.as_dict() for finding in findings]

    @classmethod
    def _sections(
        cls,
        *,
        apk_data: Dict[str, Any],
        severity: str,
        score: int,
        confidence: Dict[str, Any],
        permission_findings: Sequence[AssessmentFinding],
        component_findings: Sequence[AssessmentFinding],
        network_findings: Sequence[AssessmentFinding],
        certificate_findings: Sequence[AssessmentFinding],
        privacy_findings: Sequence[AssessmentFinding],
        threat_findings: Sequence[AssessmentFinding],
        sdk_findings: Sequence[AssessmentFinding],
        contributors: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        app_name = apk_data.get("app_name") or apk_data.get("package_name") or "this APK"
        permission_topics = cls._permission_topics(permission_findings)
        network_text = " Application communicates with external domains." if network_findings else ""
        indicator_text = (
            " No high-confidence known malware indicators were detected during static analysis."
            if not any(item.risk in {"HIGH", "CRITICAL"} and item.score > 0 for item in threat_findings)
            else " Static analysis identified threat-relevant permissions, APIs, or strings requiring review."
        )
        executive = (
            f"{app_name} is classified as {severity} with a deterministic risk score of {score}/100. "
            f"The assessment is based on manifest permissions, component exposure, code/API indicators, certificate metadata, SDK levels, strings, and network artifacts. "
            f"This application demonstrates {permission_topics} exposure based on extracted APK findings.{network_text}{indicator_text}"
        )

        return {
            "executive_summary": {
                "title": "Executive Summary",
                "summary": executive,
                "items": [
                    f"Risk classification: {severity}",
                    f"Risk score: {score}/100",
                    f"Confidence: {confidence['overall']}%",
                    f"Package: {apk_data.get('package_name')}",
                ],
            },
            "risk_assessment": {
                "title": "Risk Assessment",
                "summary": f"Risk is {severity} using deterministic score bands: 0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL.",
                "items": list(contributors),
            },
            "permission_analysis": {
                "title": "Permission Analysis",
                "summary": f"{len(permission_findings)} sensitive permission finding(s) were generated from manifest permissions.",
                "items": cls._items(permission_findings),
            },
            "component_analysis": {
                "title": "Component Analysis",
                "summary": "Component exposure assessment is based on manifest activities, services, receivers, providers, and exported components.",
                "items": cls._items(component_findings),
            },
            "network_analysis": {
                "title": "Network Analysis",
                "summary": "Network assessment is based on extracted domains, URLs, INTERNET permission, and network API categories.",
                "items": cls._items(network_findings),
            },
            "certificate_analysis": {
                "title": "Certificate Analysis",
                "summary": "Certificate assessment is based on extracted signing metadata and APK validity fields.",
                "items": cls._items(certificate_findings),
            },
            "privacy_assessment": {
                "title": "Privacy Assessment",
                "summary": "Privacy exposure is derived from permissions, sensitive strings, and coexistence with network artifacts.",
                "items": cls._items(privacy_findings),
            },
            "threat_assessment": {
                "title": "Threat Assessment",
                "summary": "Threat assessment uses only static APK evidence: permissions, APIs, strings, domains, and exported components.",
                "items": cls._items(threat_findings + sdk_findings),
            },
        }

    @staticmethod
    def _permission_topics(permission_findings: Sequence[AssessmentFinding]) -> str:
        titles = {finding.title for finding in permission_findings}
        topics = []
        if any("Location" in title for title in titles):
            topics.append("location")
        if any("Storage" in title or "Media" in title for title in titles):
            topics.append("storage")
        if any("Contact" in title or "Account" in title or "Phone" in title for title in titles):
            topics.append("personal data")
        if any("SMS" in title for title in titles):
            topics.append("SMS")
        if any("Overlay" in title or "Accessibility" in title for title in titles):
            topics.append("UI automation/overlay")
        if not topics:
            return "limited permission"
        if len(topics) == 1:
            return topics[0]
        return ", ".join(topics[:-1]) + f", and {topics[-1]}"

    @staticmethod
    def _recommendations(
        *,
        severity: str,
        exported: Sequence[Any],
        network_findings: Sequence[AssessmentFinding],
        certificate_findings: Sequence[AssessmentFinding],
        permission_findings: Sequence[AssessmentFinding],
        threat_findings: Sequence[AssessmentFinding],
    ) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []
        if exported:
            exported_evidence = [ev for finding in [*network_findings, *permission_findings] for ev in finding.evidence][:5]
            recommendations.append({
                "priority": "medium",
                "action": "Review exported activities, services, receivers, and providers for intent validation and permission protection.",
                "evidence": exported_evidence or [f"{len(exported)} exported components"],
            })
        if certificate_findings:
            recommendations.append({
                "priority": "medium",
                "action": "Verify the APK signing certificate trust chain and compare the signer with the expected publisher.",
                "evidence": certificate_findings[0].evidence,
            })
        if network_findings:
            recommendations.append({
                "priority": "high" if severity in {"HIGH", "CRITICAL"} else "medium",
                "action": "Monitor outbound traffic and validate extracted domains against expected application infrastructure.",
                "evidence": [ev for finding in network_findings for ev in finding.evidence][:5],
            })
        if permission_findings:
            recommendations.append({
                "priority": "medium",
                "action": "Restrict unnecessary permissions and validate each sensitive permission against a legitimate feature requirement.",
                "evidence": [ev for finding in permission_findings for ev in finding.evidence][:6],
            })
        if any(finding.risk in {"HIGH", "CRITICAL"} for finding in threat_findings):
            recommendations.append({
                "priority": "high",
                "action": "Perform focused reverse engineering of the flagged APIs, suspicious functions, and exported entry points.",
                "evidence": [ev for finding in threat_findings for ev in finding.evidence][:6],
            })
        if not recommendations:
            recommendations.append({
                "priority": "info",
                "action": "Retain the APK hash, certificate metadata, and extracted manifest for baseline comparison and future threat-intelligence matching.",
                "evidence": ["No high-risk static indicators were identified."],
            })
        return recommendations

    @staticmethod
    def _key_findings(findings: Sequence[AssessmentFinding], domains: Sequence[Any], exported: Sequence[Any], permissions: Sequence[Any]) -> List[str]:
        items = []
        for finding in findings:
            if finding.risk in {"HIGH", "CRITICAL", "MEDIUM"} or finding.score > 0:
                items.append(f"{finding.title}: {finding.detail}")
        if domains:
            items.append(f"Application communicates with {len(domains)} extracted domain(s).")
        if exported:
            items.append(f"{len(exported)} exported component(s) require review.")
        if not items and permissions:
            items.append(f"{len(permissions)} manifest permission(s) were analyzed with no high-risk indicators.")
        if not items:
            items.append("Static analysis completed without high-confidence malicious indicators.")
        return items[:8]

    @staticmethod
    def _format_verdict(sections: Dict[str, Any]) -> str:
        ordered = [
            "executive_summary",
            "risk_assessment",
            "permission_analysis",
            "component_analysis",
            "network_analysis",
            "certificate_analysis",
            "privacy_assessment",
            "threat_assessment",
            "recommendations",
        ]
        lines: List[str] = []
        for key in ordered:
            section = sections.get(key)
            if not isinstance(section, dict):
                continue
            lines.append(f"{section.get('title')}:")
            summary = section.get("summary")
            if summary:
                lines.append(str(summary))
            items = section.get("items") or []
            for item in items[:6]:
                if isinstance(item, dict):
                    if "action" in item:
                        lines.append(f"* {item.get('action')}")
                    elif "label" in item:
                        score = item.get("score")
                        lines.append(f"* {item.get('label')} +{score}" if score else f"* {item.get('label')}")
                    elif "title" in item:
                        lines.append(f"* {item.get('title')}: {item.get('detail')}")
                else:
                    lines.append(f"* {item}")
            lines.append("")
        return "\n".join(lines).strip()
