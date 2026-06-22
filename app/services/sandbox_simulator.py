"""
Static runtime reconstruction from APK artifacts.

This module does not execute the APK and does not fabricate sandbox telemetry.
It turns manifest, permission, component, API, and network evidence into a
chronological investigation aid.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class SandboxSimulator:
    """Backward-compatible service name for static runtime reconstruction."""

    def simulate_from_static(self, analysis_data: Dict[str, Any], neural_results: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("Generating static runtime reconstruction")

        events: List[Dict[str, Any]] = []
        offset = 0.0

        def add_event(
            event_type: str,
            category: str,
            event: str,
            summary: str,
            detail: str,
            severity: str,
            evidence: List[str],
        ) -> None:
            nonlocal offset
            events.append({
                "timestamp": f"00:{offset:05.3f}",
                "type": event_type,
                "category": category,
                "event": event,
                "summary": summary,
                "detail": detail,
                "severity": severity,
                "evidence": evidence[:10],
                "observed": False,
            })
            offset += 1.0

        package_name = analysis_data.get("package_name")
        if package_name:
            add_event(
                "process",
                "manifest",
                "Package Parsed",
                "APK package identity recovered",
                f"Package declared in manifest: {package_name}",
                "low",
                [f"package_name={package_name}"],
            )

        main_activity = analysis_data.get("main_activity")
        if main_activity:
            add_event(
                "process",
                "entrypoint",
                "Launcher Activity Identified",
                "Potential user-driven launch entry point",
                f"Main activity declared by the APK: {main_activity}",
                "low",
                [f"main_activity={main_activity}"],
            )

        permissions = [
            p.get("name", p) if isinstance(p, dict) else str(p)
            for p in analysis_data.get("permissions", [])
        ]
        sensitive_permissions = [
            perm for perm in permissions
            if perm.split(".")[-1] in {
                "RECEIVE_SMS", "READ_SMS", "SEND_SMS", "SYSTEM_ALERT_WINDOW",
                "BIND_ACCESSIBILITY_SERVICE", "ACCESS_FINE_LOCATION",
                "ACCESS_COARSE_LOCATION", "READ_CONTACTS", "READ_CALL_LOG",
                "READ_PHONE_STATE", "RECORD_AUDIO", "CAMERA",
                "REQUEST_INSTALL_PACKAGES",
            }
        ]
        if sensitive_permissions:
            add_event(
                "permission",
                "capability",
                "Sensitive Permissions Declared",
                f"{len(sensitive_permissions)} sensitive permission(s) found",
                "These are manifest-declared capabilities; no runtime grant was observed.",
                "high",
                sensitive_permissions,
            )

        exported = analysis_data.get("exported_components", [])
        if exported:
            exported_evidence = [
                f"{item.get('type', 'component')}:{item.get('name')}"
                for item in exported
                if isinstance(item, dict)
            ]
            add_event(
                "process",
                "exposure",
                "Exported Components Present",
                f"{len(exported_evidence)} externally reachable component(s) identified",
                "Exported components can be invoked by other apps when platform rules allow it.",
                "medium" if len(exported_evidence) < 5 else "high",
                exported_evidence,
            )

        native_libraries = analysis_data.get("native_libraries") or []
        if native_libraries:
            add_event(
                "file",
                "native",
                "Native Libraries Present",
                f"{len(native_libraries)} native library artifact(s) found",
                "Native code exists in the APK and may require Ghidra-level review.",
                "medium",
                [str(lib) for lib in native_libraries[:10]],
            )

        receiver_actions: List[str] = []
        for receiver in analysis_data.get("receivers", []):
            if isinstance(receiver, dict):
                receiver_actions.extend(str(action) for action in receiver.get("actions", []) if action)
        manifest = analysis_data.get("manifest")
        if isinstance(manifest, dict):
            receiver_actions.extend(str(action) for action in manifest.get("intent_actions", []) if action)
        interesting_actions = sorted({
            action for action in receiver_actions
            if any(token in action.upper() for token in ["BOOT", "SMS", "PACKAGE", "CONNECTIVITY", "POWER"])
        })
        if interesting_actions:
            add_event(
                "process",
                "trigger",
                "Broadcast/System Triggers Declared",
                f"{len(interesting_actions)} trigger action(s) found",
                "These triggers are statically declared or referenced; no broadcast delivery was observed.",
                "medium",
                interesting_actions,
            )

        api_usage = analysis_data.get("api_usage", [])
        if api_usage:
            api_evidence = [
                f"{item.get('category')}: {', '.join(item.get('matched_tokens', [])[:5])}"
                for item in api_usage
                if isinstance(item, dict)
            ]
            add_event(
                "process",
                "api",
                "Sensitive API Categories Referenced",
                f"{len(api_evidence)} API category match(es) found",
                "API usage was inferred from extracted strings and DEX metadata.",
                "medium",
                api_evidence,
            )

        network = analysis_data.get("network_artifacts", {})
        remote_artifacts = list(analysis_data.get("urls", [])) + list(analysis_data.get("domains", []))
        if isinstance(network, dict):
            remote_artifacts.extend(network.get("ip_addresses", []))
        if remote_artifacts:
            add_event(
                "network",
                "remote_artifact",
                "Hardcoded Remote Artifacts",
                f"{len(remote_artifacts)} URL/domain/IP artifact(s) extracted",
                "Remote artifacts were extracted statically. No connection was observed.",
                "high",
                [str(value) for value in remote_artifacts[:10]],
            )

        behavioral_patterns = neural_results.get("behavioral_patterns", [])
        if behavioral_patterns:
            evidence = [
                f"{item.get('pattern_name')} ({item.get('confidence')})"
                for item in behavioral_patterns
                if isinstance(item, dict)
            ]
            add_event(
                "process",
                "behavior",
                "Behavioral Pattern Matches",
                f"{len(evidence)} behavior pattern(s) mapped",
                "Pattern matches are generated from static reverse-engineering artifacts.",
                "high",
                evidence,
            )

        stats = {
            "duration_seconds": offset,
            "total_events": len(events),
            "critical_events": sum(1 for event in events if event["severity"] == "critical"),
            "high_events": sum(1 for event in events if event["severity"] == "high"),
            "network_requests": 0,
            "file_writes": 0,
            "permission_abuses": 0,
            "dynamic_execution": False,
        }

        return {
            "mode": "static_runtime_reconstruction",
            "dynamic_execution": False,
            "events": events,
            "statistics": stats,
            "timeline": [
                {
                    "time": event["timestamp"],
                    "title": event["event"],
                    "description": event["summary"],
                    "type": event["type"],
                    "severity": event["severity"],
                    "evidence": event.get("evidence", []),
                }
                for event in events
            ],
            "limitations": [
                "No APK execution was performed.",
                "Events are ordered investigation hypotheses derived from static evidence.",
                "Network connections, credential theft, file writes, and permission grants are not claimed unless independently observed.",
            ],
        }
