"""
App Analysis API Endpoints
Deep application analysis using real APK extraction and Sentinel Assessment Engine

ARCHITECTURE:
1. Device Lab -> Extract APK -> Generate SHA256 -> Create analysis_id
2. Open /app-analysis/{analysis_id}
3. NO MOCK DATA - Everything from real APK

WORKFLOW:
- Pull APK from device via ADB
- Calculate SHA256 for caching
- Analyze APK with apk_analyzer service
- Generate deterministic Sentinel security assessment
- Return structured results

ASYNC PIPELINE:
- Phase 1: Quick scan (< 3s) - Basic metadata
- Phase 2: Background deep analysis (20s)
- Phase 3: Status polling
- Phase 4: Automated security assessment
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import logging
import hashlib
import json
import copy
import time
import traceback
import uuid
from pathlib import Path
import asyncio
import shutil
import struct
import zipfile

from app.services.analysis_providers import get_default_analysis_provider
from app.services.security_assessment_engine import SecurityAssessmentEngine

# Disable verbose Androguard logging
logging.getLogger('androguard').setLevel(logging.WARNING)
logging.getLogger('androguard.core.dex').setLevel(logging.ERROR)
logging.getLogger('androguard.core.apk').setLevel(logging.WARNING)
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
except Exception:
    pass

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory cache backed by APKCache/<sha256>.json. SHA caches are durable:
# once an APK is analyzed, Sentinel can reuse the result without re-running static extraction.
_analysis_cache: Dict[str, Dict[str, Any]] = {}
_cache_timestamps: Dict[str, float] = {}
APK_CACHE_DIR = Path("APKCache")
CACHE_TTL = 60 * 60

# Analysis progress tracking: analysis_id -> progress_data
_analysis_progress: Dict[str, Dict[str, Any]] = {}


PIPELINE_STEPS = [
    {"key": "extraction", "label": "APK Extracted"},
    {"key": "sha256", "label": "SHA256 Generated"},
    {"key": "manifest", "label": "Manifest Parsed"},
    {"key": "permissions", "label": "Permissions Indexed"},
    {"key": "components", "label": "Components Indexed"},
    {"key": "dex", "label": "DEX Analysis"},
    {"key": "strings", "label": "String Extraction"},
    {"key": "certificates", "label": "Certificate Analysis"},
    {"key": "risk", "label": "Risk Engine"},
    {"key": "assessment", "label": "Automated Assessment"},
]


def _cache_result_path(sha256_hash: str) -> Path:
    APK_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return APK_CACHE_DIR / f"{sha256_hash}.json"


def _apk_cache_path(sha256_hash: str) -> Path:
    APK_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return APK_CACHE_DIR / f"{sha256_hash}.apk"


def _new_analysis_id(sha256_hash: str) -> str:
    return f"{sha256_hash}-{uuid.uuid4().hex}"


def _sha_from_analysis_id(analysis_id: str) -> str:
    candidate = analysis_id[:64]
    if len(candidate) == 64 and all(ch in "0123456789abcdef" for ch in candidate.lower()):
        return candidate
    return analysis_id


def _has_stale_assessment_fallback(result: Dict[str, Any]) -> bool:
    ai_assessment = result.get("ai_assessment")
    if not isinstance(ai_assessment, dict):
        return True
    model = str(ai_assessment.get("model", ""))
    status = str(ai_assessment.get("status", ""))
    return (
        (bool(model) and model.lower() != "sentinel assessment engine")
        or "fallback" in model.lower()
        or ai_assessment.get("_ai_failed") is True
        or ai_assessment.get("status") == "fallback"
        or status in {"running", "unavailable"}
    )


def _apk_data_from_cached_result(result: Dict[str, Any]) -> Dict[str, Any]:
    apk = result.get("apk_analysis") if isinstance(result.get("apk_analysis"), dict) else {}
    summary = result.get("executive_summary") if isinstance(result.get("executive_summary"), dict) else {}
    permission_intel = result.get("permission_intelligence") if isinstance(result.get("permission_intelligence"), dict) else {}
    manifest = result.get("manifest_intelligence") if isinstance(result.get("manifest_intelligence"), dict) else {}
    network = result.get("network_intelligence") if isinstance(result.get("network_intelligence"), dict) else {}
    code = result.get("code_intelligence") if isinstance(result.get("code_intelligence"), dict) else {}
    dex = result.get("dex_intelligence") if isinstance(result.get("dex_intelligence"), dict) else {}
    cert = summary.get("certificate") if isinstance(summary.get("certificate"), dict) else {}
    certificates = apk.get("certificates") if isinstance(apk.get("certificates"), list) else ([cert] if cert else [])

    return {
        "package_name": apk.get("package_name") or summary.get("package") or result.get("package"),
        "app_name": apk.get("app_name") or summary.get("name") or result.get("package"),
        "version_name": apk.get("version_name") or summary.get("version_name"),
        "version_code": apk.get("version_code") or summary.get("version_code"),
        "target_sdk_version": apk.get("target_sdk_version") or summary.get("target_sdk"),
        "min_sdk_version": apk.get("min_sdk_version") or summary.get("min_sdk"),
        "is_signed": apk.get("is_signed", summary.get("is_signed")),
        "is_valid_apk": apk.get("is_valid_apk"),
        "main_activity": apk.get("main_activity") or summary.get("main_activity"),
        "permissions": apk.get("permissions") if isinstance(apk.get("permissions"), list) else permission_intel.get("permissions", []),
        "activities": apk.get("activities") if isinstance(apk.get("activities"), list) else manifest.get("activities", []),
        "services": apk.get("services") if isinstance(apk.get("services"), list) else manifest.get("services", []),
        "receivers": apk.get("receivers") if isinstance(apk.get("receivers"), list) else manifest.get("receivers", []),
        "providers": apk.get("providers") if isinstance(apk.get("providers"), list) else manifest.get("providers", []),
        "exported_components": apk.get("exported_components") if isinstance(apk.get("exported_components"), list) else manifest.get("exported_components", []),
        "api_usage": apk.get("api_usage") if isinstance(apk.get("api_usage"), list) else code.get("api_usage", []),
        "suspicious_functions": apk.get("suspicious_functions") if isinstance(apk.get("suspicious_functions"), list) else code.get("suspicious_functions", []),
        "domains": apk.get("domains") if isinstance(apk.get("domains"), list) else network.get("domains", []),
        "urls": apk.get("urls") if isinstance(apk.get("urls"), list) else network.get("urls", []),
        "strings": apk.get("strings") if isinstance(apk.get("strings"), list) else [],
        "certificates": certificates,
        "native_libraries": apk.get("native_libraries") if isinstance(apk.get("native_libraries"), list) else dex.get("native_libraries", []),
        "manifest": apk.get("manifest") if isinstance(apk.get("manifest"), dict) else manifest,
    }


def _assessment_risk_payload(assessment: Dict[str, Any], previous: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    previous = previous if isinstance(previous, dict) else {}
    return {
        **previous,
        "risk_score": assessment.get("risk_score"),
        "overall_score": assessment.get("risk_score"),
        "severity": assessment.get("severity"),
        "threat_level": assessment.get("severity"),
        "malicious_confidence": assessment.get("malicious_confidence"),
        "findings": assessment.get("key_findings", []),
        "risk_factors": assessment.get("key_findings", []),
        "contributors": assessment.get("risk_contributors", []),
        "summary": ((assessment.get("sections") or {}).get("risk_assessment") or {}).get("summary"),
    }


def _normalize_analysis_result(result: Dict[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(result)
    previous_risk = normalized.get("risk_assessment_internal") or normalized.get("risk_assessment") or {}
    if _has_stale_assessment_fallback(normalized):
        assessment = SecurityAssessmentEngine.generate(
            apk_data=_apk_data_from_cached_result(normalized),
            risk_assessment=previous_risk,
            analysis_metadata={"source": "cache_normalization"},
        )
        normalized["ai_assessment"] = assessment
        normalized["security_assessment"] = assessment
        normalized["automated_security_assessment"] = assessment
        normalized["risk_assessment"] = _assessment_risk_payload(assessment, previous_risk)
        summary = normalized.setdefault("executive_summary", {})
        if isinstance(summary, dict):
            summary["risk_score"] = assessment.get("risk_score")
            summary["threat_level"] = assessment.get("severity")
            summary["malicious_confidence"] = assessment.get("malicious_confidence")
    normalized.pop("risk_assessment_internal", None)
    normalized.setdefault("performance", {})
    return normalized


def _load_cached_result(sha256_hash: str) -> Optional[Dict[str, Any]]:
    if sha256_hash in _analysis_cache:
        result = _normalize_analysis_result(_analysis_cache[sha256_hash])
    else:
        cache_path = _cache_result_path(sha256_hash)
        if not cache_path.exists():
            return None
        try:
            raw_result = json.loads(cache_path.read_text(encoding="utf-8"))
            stale_cache = _has_stale_assessment_fallback(raw_result)
            result = _normalize_analysis_result(raw_result)
            if stale_cache:
                cache_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
            _analysis_cache[sha256_hash] = copy.deepcopy(result)
            _cache_timestamps[sha256_hash] = time.time()
        except Exception as exc:
            logger.warning(f"[AppAnalysis] Failed to load cache {cache_path}: {exc}")
            return None

    result.setdefault("performance", {})
    result["performance"]["cache_hit"] = True
    result["performance"]["cache_source"] = "disk" if _cache_result_path(sha256_hash).exists() else "memory"
    result.setdefault("apk_storage", {})
    result["apk_storage"].update({
        "stored_locally": True,
        "local_path": str(_apk_cache_path(sha256_hash)),
        "device_required": False,
        "cache_location": "APKCache/",
    })
    return result


def _store_cached_result(sha256_hash: str, result: Dict[str, Any]) -> None:
    result = _normalize_analysis_result(result)
    _analysis_cache[sha256_hash] = copy.deepcopy(result)
    _cache_timestamps[sha256_hash] = time.time()
    cache_path = _cache_result_path(sha256_hash)
    cache_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")


def _pipeline_state(active_key: Optional[str], completed_keys: Optional[List[str]] = None) -> List[Dict[str, str]]:
    completed = set(completed_keys or [])
    steps = []
    for step in PIPELINE_STEPS:
        key = step["key"]
        if key in completed:
            status = "complete"
        elif active_key and key == active_key:
            status = "running"
        else:
            status = "pending"
        steps.append({**step, "status": status})
    return steps


def _set_progress(
    analysis_id: str,
    *,
    status: str,
    progress: int,
    current_step: str,
    active_key: Optional[str],
    completed_keys: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "status": status,
        "progress": progress,
        "current_step": current_step,
        "pipeline": _pipeline_state(active_key, completed_keys),
        "updated_at": time.time(),
    }
    if extra:
        payload.update(extra)
    _analysis_progress[analysis_id] = payload


async def _background_deep_analysis(
    analysis_id: str,
    permanent_path: Path,
    package: str,
    sha256_hash: str,
    file_size: int,
    extraction_time: float
):
    """
    Background task for deep APK analysis - OPTIMIZED
    Updates progress as it runs
    TARGET: < 15 seconds
    """
    import time
    timings = {}
    
    try:
        logger.info(f"[BG-Analysis-{analysis_id}] Starting background deep analysis")
        total_start = time.time()
        
        _set_progress(
            analysis_id,
            status="analyzing",
            progress=20,
            current_step="Running static APK analysis",
            active_key="dex",
            completed_keys=["extraction", "sha256", "manifest", "permissions", "components"],
            extra={"started_at": total_start, "sha256": sha256_hash}
        )
        
        # STEP 1: Static Analysis (OPTIMIZED)
        step_start = time.time()
        from app.services.apk_analyzer import APKAnalyzer
        apk_analysis = await APKAnalyzer.analyze(permanent_path)
        timings['static_analysis'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] Static Analysis: {timings['static_analysis']}ms")
        
        if apk_analysis.get('error') or apk_analysis.get('analysis_failed'):
            error_msg = apk_analysis.get('error', 'Unknown error')
            _analysis_progress[analysis_id] = {
                "status": "failed",
                "progress": 0,
                "error": error_msg,
                "error_source": "APKAnalyzer",
                "error_message": error_msg,
                "sha256": sha256_hash
            }
            logger.error(f"[BG-Analysis-{analysis_id}] Failed: {error_msg}")
            return
        
        _set_progress(
            analysis_id,
            status="analyzing",
            progress=70,
            current_step="Building Analysis Result",
            active_key="risk",
            completed_keys=[
                "extraction", "sha256", "manifest", "permissions",
                "components", "dex", "strings", "certificates"
            ],
            extra={"sha256": sha256_hash}
        )
        
        # STEP 2: Build comprehensive result (OPTIMIZED)
        step_start = time.time()
        logger.info(f"[BG-Analysis-{analysis_id}] Entering _build_analysis_result for sha256={sha256_hash}")
        result = await _build_analysis_result(
            package=package,
            apk_analysis=apk_analysis,
            sha256_hash=sha256_hash,
            file_size=file_size,
            extraction_time=extraction_time,
            analysis_time=(time.time() - total_start),
            analysis_id=analysis_id,
            include_ai=False
        )
        timings['build_result'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] Build Result: {timings['build_result']}ms")
        
        # Add storage info
        result['apk_storage'] = {
            "stored_locally": True,
            "local_path": str(permanent_path),
            "device_required": False,
            "cache_location": "APKCache/"
        }
        display_result = copy.deepcopy(result)
        display_result.pop("risk_assessment_internal", None)
        
        # STEP 3: Save to JSON cache (persistent)
        step_start = time.time()
        try:
            _store_cached_result(sha256_hash, display_result)
            json_cache_path = _cache_result_path(sha256_hash)
            timings['json_save'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] JSON Save: {timings['json_save']}ms")
            logger.info(f"[BG-Analysis-{analysis_id}] âœ“ Saved to JSON cache: {json_cache_path}")
        except Exception as e:
            logger.warning(f"[BG-Analysis-{analysis_id}] Failed to save JSON cache: {e}")
            logger.error(traceback.format_exc())
            logger.error(f"[BG-Analysis-{analysis_id}] Cache save error type: {type(e).__name__}")
            logger.error(f"[BG-Analysis-{analysis_id}] Cache save error message: {str(e)}")
            timings['json_save'] = 0
        
        # Cache result in memory
        _analysis_cache[sha256_hash] = _normalize_analysis_result(display_result)
        _cache_timestamps[sha256_hash] = time.time()
        
        # Update progress: Complete
        total_time = time.time() - total_start
        timings['total'] = int(total_time * 1000)
        _set_progress(
            analysis_id,
            status="completed",
            progress=100,
            current_step="Automated Security Assessment Complete",
            active_key=None,
            completed_keys=[
                step["key"] for step in PIPELINE_STEPS
            ],
            extra={
                "total_time": round(total_time, 2),
                "result": display_result,
                "timings_ms": timings,
                "sha256": sha256_hash
            }
        )
        
        logger.info(f"[PERF] ===== TOTAL BACKGROUND ANALYSIS: {timings['total']}ms =====")
        logger.info(f"[PERF] Breakdown: {timings}")
        logger.info(f"[BG-Analysis-{analysis_id}] âœ“ Complete in {total_time:.2f}s")
        
    except Exception as e:
        error_traceback = traceback.format_exc()
        logger.error(error_traceback)
        logger.error(f"[BG-Analysis-{analysis_id}] FULL TRACEBACK:\n{error_traceback}")
        logger.error(f"[BG-Analysis-{analysis_id}] Error type: {type(e).__name__}")
        logger.error(f"[BG-Analysis-{analysis_id}] Error message: {str(e)}")
        _analysis_progress[analysis_id] = {
            "status": "failed",
            "progress": 70,
            "current_step": "Analysis failed",
            "error": f"{type(e).__name__}: {str(e)}",
            "error_source": type(e).__name__,
            "error_message": str(e),
            "traceback": error_traceback,
            "sha256": sha256_hash
        }


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SIG_IDS = (0x7109871A, 0xF05368C0, 0x1B93AD61)


def _android_attr(element: Any, name: str) -> Optional[str]:
    return element.get(f"{ANDROID_NS}{name}") or element.get(name)


def _read_len_prefixed(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ValueError("Length-prefixed field is truncated")
    size = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    end = offset + size
    if end > len(data):
        raise ValueError("Length-prefixed field exceeds available data")
    return data[offset:end], end


def _iter_len_prefixed_sequence(data: bytes) -> List[bytes]:
    items = []
    offset = 0
    while offset < len(data):
        item, offset = _read_len_prefixed(data, offset)
        items.append(item)
    return items


def _certificate_entry_from_der(cert_der: bytes) -> Optional[Dict[str, Any]]:
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(cert_der)
        return {
            "sha256": hashlib.sha256(cert_der).hexdigest(),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
    except Exception:
        return None


def _collect_der_certificates(data: bytes, seen: set[str], depth: int = 0) -> List[Dict[str, Any]]:
    certificates = []
    candidates = [data]
    if len(data) > 4:
        candidates.append(data[4:])

    for candidate in candidates:
        if not candidate or candidate[0] != 0x30:
            continue
        entry = _certificate_entry_from_der(candidate)
        if entry and entry["sha256"] not in seen:
            seen.add(entry["sha256"])
            certificates.append(entry)

    if depth >= 8:
        return certificates

    offset = 0
    while offset + 4 <= len(data):
        try:
            item, next_offset = _read_len_prefixed(data, offset)
        except Exception:
            break
        if next_offset <= offset:
            break
        certificates.extend(_collect_der_certificates(item, seen, depth + 1))
        offset = next_offset

    return certificates


def _extract_apk_signing_block_certificates(apk_path: Path) -> List[Dict[str, Any]]:
    try:
        with open(apk_path, "rb") as apk_file:
            apk_file.seek(0, 2)
            file_size = apk_file.tell()
            read_size = min(file_size, 65557)
            apk_file.seek(file_size - read_size)
            tail = apk_file.read(read_size)

            eocd_sig = b"PK\x05\x06"
            eocd_offset_in_tail = tail.rfind(eocd_sig)
            if eocd_offset_in_tail < 0:
                return []

            eocd = tail[eocd_offset_in_tail:]
            if len(eocd) < 22:
                return []
            central_dir_offset = struct.unpack_from("<I", eocd, 16)[0]
            if central_dir_offset < 24:
                return []

            apk_file.seek(central_dir_offset - 24)
            footer = apk_file.read(24)
            if len(footer) != 24 or footer[8:] != APK_SIG_MAGIC:
                return []

            block_size = struct.unpack_from("<Q", footer, 0)[0]
            block_start = central_dir_offset - block_size - 8
            if block_start < 0:
                return []

            apk_file.seek(block_start)
            signing_block = apk_file.read(block_size + 8)

        if len(signing_block) < 32:
            return []

        certificates = []
        seen: set[str] = set()
        offset = 8
        pairs_end = len(signing_block) - 24
        while offset < pairs_end:
            pair_size = struct.unpack_from("<Q", signing_block, offset)[0]
            offset += 8
            pair_end = offset + pair_size
            if pair_end > pairs_end or pair_size < 4:
                break

            pair_id = struct.unpack_from("<I", signing_block, offset)[0]
            value = signing_block[offset + 4:pair_end]
            offset = pair_end
            if pair_id not in APK_SIG_IDS:
                continue

            certificates.extend(_collect_der_certificates(value, seen))
            if certificates:
                return certificates
    except Exception as e:
        logger.warning(f"[QuickScan] Certificate extraction unavailable: {type(e).__name__}: {str(e)}")
    return []


def _decode_manifest_from_zip(apk_path: Path) -> Any:
    from androguard.core.axml import AXMLPrinter
    with zipfile.ZipFile(apk_path) as apk_zip:
        manifest_data = apk_zip.read("AndroidManifest.xml")
    return AXMLPrinter(manifest_data).get_xml_obj()


async def _quick_scan_apk(apk_path: Path) -> Dict[str, Any]:
    """
    Quick scan - returns basic metadata without DEX, string, network, or AI work.
    NO deep DEX analysis, NO string extraction
    """
    try:
        quick_start = time.time()
        manifest_start = time.time()
        manifest_xml = _decode_manifest_from_zip(Path(apk_path))
        manifest_time = int((time.time() - manifest_start) * 1000)

        component_start = time.time()
        activities_count = len(manifest_xml.findall(".//activity")) + len(manifest_xml.findall(".//activity-alias"))
        services_count = len(manifest_xml.findall(".//service"))
        receivers_count = len(manifest_xml.findall(".//receiver"))
        providers_count = len(manifest_xml.findall(".//provider"))
        component_time = int((time.time() - component_start) * 1000)

        permission_start = time.time()
        permissions = [
            {"name": name}
            for name in (
                _android_attr(element, "name")
                for element in manifest_xml.findall(".//uses-permission")
            )
            if name
        ][:50]
        permission_time = int((time.time() - permission_start) * 1000)

        certificate_start = time.time()
        certs = _extract_apk_signing_block_certificates(Path(apk_path))
        certificate_time = int((time.time() - certificate_start) * 1000)

        # Manifest-only quick scan. Do not run DEX, strings, network, obfuscation, or AI here.
        result = {
            "package_name": manifest_xml.get("package"),
            "version_name": _android_attr(manifest_xml, "versionName"),
            "version_code": _android_attr(manifest_xml, "versionCode"),
            "permissions": permissions,
            "activities_count": activities_count,
            "services_count": services_count,
            "receivers_count": receivers_count,
            "providers_count": providers_count,
            "component_counts": {
                "activities": activities_count,
                "services": services_count,
                "receivers": receivers_count,
                "providers": providers_count,
            },
        }
        
        if certs:
            result["certificate"] = certs[0]
            result["certificates_count"] = len(certs)
        else:
            result["certificate"] = None
            result["certificates_count"] = 0

        result["timings_ms"] = {
            "manifest_parsing": manifest_time,
            "permission_analysis": permission_time,
            "component_indexing": component_time,
            "certificate_analysis": certificate_time,
            "total": int((time.time() - quick_start) * 1000)
        }
        logger.info(f"[PERF] Quick Manifest Parsing: {manifest_time}ms")
        logger.info(f"[PERF] Quick Permission Analysis: {permission_time}ms")
        logger.info(f"[PERF] Quick Component Indexing: {component_time}ms")
        logger.info(f"[PERF] Quick Certificate Analysis: {certificate_time}ms")
        
        return result
        
    except Exception as e:
        logger.error(f"[QuickScan] Error: {e}")
        logger.error(traceback.format_exc())
        logger.error(f"[QuickScan] Error type: {type(e).__name__}")
        logger.error(f"[QuickScan] Error message: {str(e)}")
        raise


@router.post("/quick-scan")
async def quick_scan_package(
    package_name: str = Query(..., description="Package name"),
    serial: str = Query(..., description="Device serial"),
    background_tasks: BackgroundTasks = None
):
    """
    PHASE 1: Quick Scan - Returns immediately with basic info (< 2s TARGET)
    Launches background deep analysis task
    
    Returns:
        - analysis_id for polling
        - basic metadata (package, version, permissions, certificate)
        - sha256 hash
    """
    import time
    total_start = time.time()
    timings = {}
    
    try:
        logger.info(f"[QuickScan] Starting for {package_name}")
        
        # STEP 1: Extract APK (fast)
        step_start = time.time()
        temp_dir = Path("uploads/pulled_apks")
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / f"{package_name.replace('.', '_')}_temp.apk"
        
        from app.services.app_inventory_service import get_app_inventory_service
        app_inventory = get_app_inventory_service()
        
        logger.info(f"[QuickScan] Step 1: Extracting APK from device")
        pull_success = await app_inventory.pull_apk(serial, package_name, str(temp_path))
        
        if not pull_success:
            pull_error = getattr(app_inventory, "last_pull_error", None) or "ADB pull returned false without a specific error"
            logger.error(f"[QuickScan] Pull error source: {pull_error}")
            logger.error(f"[QuickScan] âŒ pull_apk returned False")
            logger.error(f"[QuickScan] Device: {serial}, Package: {package_name}")
            logger.error(f"[QuickScan] Target path: {temp_path}")
            logger.error(f"[QuickScan] Check ADB logs above for root cause")
            raise HTTPException(status_code=500, detail=f"APK extraction failed for {package_name}: {pull_error}")
        
        if not temp_path.exists():
            logger.error(f"[QuickScan] âŒ APK file not found at {temp_path}")
            logger.error(f"[QuickScan] pull_apk returned True but file missing")
            logger.error(f"[QuickScan] This indicates a path normalization bug")
            raise HTTPException(status_code=500, detail=f"APK file not found after extraction: {temp_path}")
        
        # Verify file size > 0
        temp_file_size = temp_path.stat().st_size
        if temp_file_size == 0:
            logger.error(f"[QuickScan] âŒ APK file is empty (0 bytes)")
            logger.error(f"[QuickScan] Path: {temp_path}")
            logger.error(f"[QuickScan] ADB pull succeeded but wrote 0 bytes")
            raise HTTPException(status_code=500, detail=f"APK file is empty (0 bytes): {temp_path}")
        
        timings['extraction'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] Extraction: {timings['extraction']}ms ({temp_file_size} bytes)")
        
        # STEP 2: Calculate SHA256
        step_start = time.time()
        logger.info(f"[QuickScan] Step 2: Calculating SHA256")
        with open(temp_path, 'rb') as f:
            file_data = f.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        file_size = len(file_data)
        timings['sha256'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] SHA256: {timings['sha256']}ms")
        logger.info(f"[QuickScan] âœ“ SHA256: {sha256_hash}")
        
        analysis_id = _new_analysis_id(sha256_hash)
        logger.info(f"[QuickScan] Analysis run id: {analysis_id}")

        # STEP 3: Move to permanent cache
        step_start = time.time()
        logger.info(f"[QuickScan] Step 3: Moving to permanent cache")
        cache_dir = Path("APKCache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        permanent_path = cache_dir / f"{sha256_hash}.apk"
        
        if not permanent_path.exists():
            import shutil
            shutil.move(str(temp_path), str(permanent_path))
            logger.info(f"[QuickScan] âœ“ Moved to: {permanent_path}")
        else:
            temp_path.unlink()
            logger.info(f"[QuickScan] âœ“ Already cached: {permanent_path}")
        
        # Verify permanent file
        if not permanent_path.exists():
            logger.error(f"[QuickScan] âŒ Permanent file not found")
            raise HTTPException(status_code=500, detail=f"Permanent APK cache file was not created: {permanent_path}")
        
        permanent_file_size = permanent_path.stat().st_size
        if permanent_file_size == 0:
            logger.error(f"[QuickScan] âŒ Permanent file is empty")
            raise HTTPException(status_code=500, detail=f"Permanent APK cache file is empty: {permanent_path}")
        
        timings['storage'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] Storage: {timings['storage']}ms")
        logger.info(f"[QuickScan] âœ“âœ“âœ“ DEVICE CAN NOW BE DISCONNECTED âœ“âœ“âœ“")
        logger.info(f"[QuickScan] Local APK: {permanent_path} ({permanent_file_size} bytes)")
        
        # STEP 4: Check JSON cache FIRST (< 1s cache hit)
        step_start = time.time()
        json_cache_path = cache_dir / f"{sha256_hash}.json"
        if json_cache_path.exists():
            try:
                import json
                with open(json_cache_path, 'r') as f:
                    cached_result = json.load(f)
                cached_result = _normalize_analysis_result(cached_result)
                cache_age = time.time() - json_cache_path.stat().st_mtime
                if cache_age < CACHE_TTL:
                    logger.info(f"[QuickScan] âš¡âš¡âš¡ JSON CACHE HIT! (age: {cache_age:.0f}s)")
                    cached_result.setdefault('performance', {})
                    cached_result['performance']['cache_hit'] = True
                    cached_result['performance']['cache_age_seconds'] = round(cache_age, 1)
                    return {
                        "status": "completed",
                        "analysis_id": analysis_id,
                        "sha256": sha256_hash,
                        "pipeline": _pipeline_state(None, [step["key"] for step in PIPELINE_STEPS]),
                        "cache_hit": True,
                        "result": cached_result
                    }
            except Exception as e:
                logger.warning(f"[QuickScan] Failed to load JSON cache: {e}")
                logger.error(traceback.format_exc())
                logger.error(f"[QuickScan] Cache load error type: {type(e).__name__}")
                logger.error(f"[QuickScan] Cache load error message: {str(e)}")
        
        # Check memory cache
        if sha256_hash in _analysis_cache:
            cache_age = time.time() - _cache_timestamps.get(sha256_hash, 0)
            if cache_age < CACHE_TTL:
                logger.info(f"[QuickScan] âš¡ Memory cache hit! (age: {cache_age:.0f}s)")
                cached = _load_cached_result(sha256_hash)
                if not cached:
                    raise ValueError(f"Memory cache exists but could not be loaded for sha256={sha256_hash}")
                cached.setdefault('performance', {})
                cached['performance']['cache_hit'] = True
                cached['performance']['cache_age_seconds'] = round(cache_age, 1)
                return {
                    "status": "completed",
                    "current_step": "Automated Security Assessment",
                    "analysis_id": analysis_id,
                    "sha256": sha256_hash,
                    "pipeline": _pipeline_state(None, [step["key"] for step in PIPELINE_STEPS]),
                    "cache_hit": True,
                    "result": cached
                }
        
        timings['cache_check'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] Cache Check: {timings['cache_check']}ms")
        
        # STEP 5: Quick metadata scan (< 500ms)
        step_start = time.time()
        quick_result = await _quick_scan_apk(permanent_path)
        quick_result["sha256"] = sha256_hash
        timings['quick_scan'] = int((time.time() - step_start) * 1000)
        logger.info(f"[PERF] Quick Scan: {timings['quick_scan']}ms")
        
        total_time = int((time.time() - total_start) * 1000)
        timings['total'] = total_time
        logger.info(f"[PERF] ===== QUICK SCAN TOTAL: {total_time}ms =====")
        logger.info(f"[PERF] Breakdown: {timings}")
        
        # STEP 6: Launch background deep analysis

        # Initialize progress tracking
        _set_progress(
            analysis_id,
            status="analyzing",
            progress=10,
            current_step="Quick scan complete - Starting deep analysis",
            active_key="dex",
            completed_keys=["extraction", "sha256", "manifest", "permissions", "components"],
            extra={"started_at": time.time(), "sha256": sha256_hash}
        )
        
        # Launch background task
        if background_tasks:
            background_tasks.add_task(
                _background_deep_analysis,
                analysis_id,
                permanent_path,
                package_name,
                sha256_hash,
                file_size,
                timings['extraction'] / 1000.0
            )
        else:
            # Fallback: run in asyncio task
            asyncio.create_task(_background_deep_analysis(
                analysis_id,
                permanent_path,
                package_name,
                sha256_hash,
                file_size,
                timings['extraction'] / 1000.0
            ))
        
        logger.info(f"[QuickScan] Background analysis scheduled exactly once for analysis_id={analysis_id}, sha256={sha256_hash}")
        
        # Return immediately with quick results
        return {
            "status": "analyzing",
            "analysis_id": analysis_id,
            "sha256": sha256_hash,
            "quick_scan": quick_result,
            "pipeline": _pipeline_state("dex", ["extraction", "sha256", "manifest", "permissions", "components"]),
            "apk_storage": {
                "stored_locally": True,
                "local_path": str(permanent_path),
                "device_required": False
            },
            "performance": {
                "extraction_time": round(timings['extraction'] / 1000.0, 2),
                "quick_scan_time": round(total_time / 1000.0, 2),
                "timings_ms": timings
            }
        }
        
    except HTTPException as e:
        if e.status_code >= 500:
            logger.error(traceback.format_exc())
            logger.error(f"[QuickScan] HTTPException type: {type(e).__name__}")
            logger.error(f"[QuickScan] HTTPException message: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"[QuickScan] âŒ UNHANDLED EXCEPTION")
        logger.error(f"[QuickScan] Exception type: {type(e).__name__}")
        logger.error(f"[QuickScan] Exception message: {str(e)}")
        logger.error(f"[QuickScan] Full traceback:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")


@router.get("/status/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """
    PHASE 3: Poll analysis status
    
    Returns:
        - status: analyzing | completed | failed
        - progress: 0-100
        - current_step: string
        - result: (when completed)
    """
    if analysis_id not in _analysis_progress:
        sha256_hash = _sha_from_analysis_id(analysis_id)
        # Check cache
        if sha256_hash in _analysis_cache:
            cached_result = _load_cached_result(sha256_hash)
            return {
                "status": "completed",
                "progress": 100,
                "current_step": "Automated Security Assessment",
                "analysis_id": analysis_id,
                "sha256": sha256_hash,
                "pipeline": _pipeline_state(None, [step["key"] for step in PIPELINE_STEPS]),
                "result": cached_result
            }
        cached_result = _load_cached_result(sha256_hash)
        if cached_result:
            return {
                "status": "completed",
                "progress": 100,
                "current_step": "Automated Security Assessment",
                "analysis_id": analysis_id,
                "sha256": sha256_hash,
                "pipeline": _pipeline_state(None, [step["key"] for step in PIPELINE_STEPS]),
                "result": cached_result
            }
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    progress_data = _analysis_progress[analysis_id]
    
    # If completed, return result and clean up progress tracking
    if progress_data["status"] == "completed":
        result = _normalize_analysis_result(progress_data.get("result") or {})
        # Keep for 5 minutes then clean up
        return {
            "status": "completed",
            "progress": 100,
            "current_step": "Automated Security Assessment",
            "analysis_id": analysis_id,
            "sha256": progress_data.get("sha256") or _sha_from_analysis_id(analysis_id),
            "pipeline": progress_data.get("pipeline") or _pipeline_state(None, [step["key"] for step in PIPELINE_STEPS]),
            "result": result
        }
    
    # Return progress
    return {
        "status": progress_data["status"],
        "progress": progress_data["progress"],
        "analysis_id": analysis_id,
        "sha256": progress_data.get("sha256") or _sha_from_analysis_id(analysis_id),
        "current_step": progress_data.get("current_step", ""),
        "pipeline": progress_data.get("pipeline") or [],
        "error": progress_data.get("error"),
        "error_source": progress_data.get("error_source"),
        "error_message": progress_data.get("error_message")
    }


async def _extract_and_analyze_apk(package: str, serial: str) -> Dict[str, Any]:
    """
    Extract APK from device and perform full analysis
    Returns real data from APK structure - NO MOCK DATA
    
    CRITICAL: APK is stored locally by SHA256. Device can be disconnected after extraction.
    All analysis runs on the local APK copy.
    
    Args:
        package: Android package name
        serial: Device serial number
        
    Returns:
        Complete analysis dictionary with all 12 tabs of data
    """
    start_time = time.time()
    
    try:
        logger.info(f"[AppAnalysis] Starting analysis for {package} on device {serial}")
        
        # Step 1: Pull APK from device to TEMPORARY location first
        temp_dir = Path("uploads/pulled_apks")
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / f"{package.replace('.', '_')}_temp.apk"
        
        logger.info(f"[AppAnalysis] Extracting APK to temporary location: {temp_path}")
        
        from app.services.app_inventory_service import get_app_inventory_service
        app_inventory = get_app_inventory_service()
        
        pull_success = await app_inventory.pull_apk(serial, package, str(temp_path))
        
        if not pull_success:
            pull_error = getattr(app_inventory, "last_pull_error", None) or "ADB pull returned false without a specific error"
            logger.error(f"[AppAnalysis] âŒ pull_apk returned False")
            logger.error(f"[AppAnalysis] Pull error source: {pull_error}")
            logger.error(f"[AppAnalysis] Device: {serial}, Package: {package}")
            logger.error(f"[AppAnalysis] Check ADB logs above for root cause")
            raise HTTPException(status_code=500, detail=f"APK extraction failed for {package} from device {serial}: {pull_error}")
            
        if not temp_path.exists():
            logger.error(f"[AppAnalysis] âŒ APK file not found at {temp_path}")
            logger.error(f"[AppAnalysis] pull_apk returned True but file missing")
            logger.error(f"[AppAnalysis] This indicates a path normalization bug")
            raise HTTPException(status_code=500, detail=f"APK file not found after extraction: {temp_path}")
        
        extraction_time = time.time() - start_time
        logger.info(f"[AppAnalysis] âœ“ APK extracted successfully in {extraction_time:.2f}s")
        
        # Step 2: Calculate SHA256 hash
        logger.info(f"[AppAnalysis] Calculating SHA256 hash")
        with open(temp_path, 'rb') as f:
            file_data = f.read()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        file_size = len(file_data)
        logger.info(f"[AppAnalysis] âœ“ SHA256: {sha256_hash}")
        logger.info(f"[AppAnalysis] âœ“ File size: {file_size / (1024*1024):.2f} MB")
        
        # Step 3: Move APK to PERMANENT cache location by SHA256
        cache_dir = Path("APKCache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        permanent_path = cache_dir / f"{sha256_hash}.apk"
        
        # Only copy if not already cached
        if not permanent_path.exists():
            import shutil
            shutil.move(str(temp_path), str(permanent_path))
            logger.info(f"[AppAnalysis] âœ“ APK stored permanently: {permanent_path}")
        else:
            # Already cached, remove temp file
            temp_path.unlink()
            logger.info(f"[AppAnalysis] âœ“ APK already in cache: {permanent_path}")
        
        logger.info(f"[AppAnalysis] âœ“âœ“âœ“ DEVICE CAN NOW BE DISCONNECTED âœ“âœ“âœ“")
        logger.info(f"[AppAnalysis] All remaining analysis uses local APK: {permanent_path}")
        
        # Step 4: Check analysis cache
        if sha256_hash in _analysis_cache:
            cache_age = time.time() - _cache_timestamps.get(sha256_hash, 0)
            if cache_age < CACHE_TTL:
                logger.info(f"[AppAnalysis] âš¡ Cache hit! Loading results instantly (age: {cache_age:.0f}s)")
                cached = _load_cached_result(sha256_hash)
                if not cached:
                    raise ValueError(f"Memory cache exists but could not be loaded for sha256={sha256_hash}")
                cached.setdefault('performance', {})
                cached['performance']['cache_hit'] = True
                cached['performance']['cache_age_seconds'] = round(cache_age, 1)
                cached['apk_storage'] = {
                    "stored_locally": True,
                    "local_path": str(permanent_path),
                    "device_required": False
                }
                return cached
            else:
                # Expired cache
                logger.info(f"[AppAnalysis] Cache expired for {sha256_hash[:12]}, re-analyzing")
                del _analysis_cache[sha256_hash]
                del _cache_timestamps[sha256_hash]
        
        # Step 5: Analyze LOCAL APK with APKAnalyzer (NO DEVICE DEPENDENCY)
        logger.info(f"[AppAnalysis] Starting static analysis on LOCAL APK (device-independent)")
        analysis_start = time.time()
        
        from app.services.apk_analyzer import APKAnalyzer
        apk_analysis = await APKAnalyzer.analyze(permanent_path)
        
        if apk_analysis.get('error') or apk_analysis.get('analysis_failed'):
            error_msg = apk_analysis.get('error', 'Unknown error')
            logger.error(f"[AppAnalysis] APK analysis failed: {error_msg}")
            raise HTTPException(
                status_code=500, 
                detail=f"APK analysis failed: {error_msg}"
            )
        
        analysis_time = time.time() - analysis_start
        logger.info(f"[AppAnalysis] âœ“ Static analysis completed in {analysis_time:.2f}s")
        
        # Step 6: Build comprehensive analysis result
        logger.info(f"[AppAnalysis] Building analysis result from LOCAL APK")
        result = await _build_analysis_result(
            package=package,
            apk_analysis=apk_analysis,
            sha256_hash=sha256_hash,
            file_size=file_size,
            extraction_time=extraction_time,
            analysis_time=analysis_time
        )
        
        # Add storage information
        result['apk_storage'] = {
            "stored_locally": True,
            "local_path": str(permanent_path),
            "device_required": False,
            "cache_location": "APKCache/"
        }
        result.pop("risk_assessment_internal", None)
        
        # Cache result
        _store_cached_result(sha256_hash, result)
        
        total_time = time.time() - start_time
        logger.info(f"[AppAnalysis] âœ“âœ“âœ“ Analysis complete! Total time: {total_time:.2f}s âœ“âœ“âœ“")
        logger.info(f"[AppAnalysis] APK permanently stored: {permanent_path}")
        logger.info(f"[AppAnalysis] Device no longer required for this APK")
        
        return result
        
    except HTTPException as e:
        if e.status_code >= 500:
            logger.error(traceback.format_exc())
            logger.error(f"[AppAnalysis] HTTPException type: {type(e).__name__}")
            logger.error(f"[AppAnalysis] HTTPException message: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"[AppAnalysis] Unexpected error: {e}", exc_info=True)
        logger.error(traceback.format_exc())
        logger.error(f"[AppAnalysis] Exception type: {type(e).__name__}")
        logger.error(f"[AppAnalysis] Exception message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


async def _build_analysis_result(
    package: str,
    apk_analysis: Dict[str, Any],
    sha256_hash: str,
    file_size: int,
    extraction_time: float,
    analysis_time: float,
    analysis_id: Optional[str] = None,
    include_ai: bool = False
) -> Dict[str, Any]:
    """
    Build comprehensive analysis result from APK analysis data
    All data comes from actual APK analysis - NO MOCK DATA
    
    Returns dictionary with all 12 tabs:
    1. Executive Summary
    2. Permission Intelligence
    3. Manifest Analysis
    4. DEX Reverse Engineering
    5. Code Intelligence
    6. Obfuscation Analysis
    7. Network Intelligence
    8. Security Weaknesses
    9. Banking Trojan Detection
    10. Attack Chain
    11. Automated Security Assessment
    12. Investigation Graph
    """
    import time
    from app.services.neural_engine import get_neural_engine
    
    logger.info(f"[BuildResult] ========== START ==========")
    logger.info(f"[BuildResult] Package: {package}")
    step_start = time.time()
    
    # STEP A: Extract data from APK analysis
    logger.info(f"[BuildResult] STEP A: Extracting data from APK analysis")
    manifest = apk_analysis.get('manifest', {})
    permissions = apk_analysis.get('permissions', [])
    dex_analysis = apk_analysis.get('dex_analysis', {})
    suspicious_functions = apk_analysis.get('suspicious_functions', [])
    urls = apk_analysis.get('urls', [])
    domains = apk_analysis.get('domains', [])
    certificates = apk_analysis.get('certificates', [])
    api_usage = apk_analysis.get('api_usage', [])
    network_artifacts = apk_analysis.get('network_artifacts', {})
    logger.info(f"[BuildResult] STEP A complete: {int((time.time() - step_start) * 1000)}ms")
    
    # STEP B: Type validation
    step_start = time.time()
    logger.info(f"[BuildResult] STEP B: Type validation")
    if not isinstance(permissions, list):
        logger.warning(f"[AppAnalysis] permissions is not a list: {type(permissions)}, value: {permissions}")
        permissions = []
    if not isinstance(suspicious_functions, list):
        logger.warning(f"[AppAnalysis] suspicious_functions is not a list: {type(suspicious_functions)}")
        suspicious_functions = []
    if not isinstance(api_usage, list):
        logger.warning(f"[AppAnalysis] api_usage is not a list: {type(api_usage)}")
        api_usage = []
    if not isinstance(urls, list):
        logger.warning(f"[AppAnalysis] urls is not a list: {type(urls)}")
        urls = []
    if not isinstance(domains, list):
        logger.warning(f"[AppAnalysis] domains is not a list: {type(domains)}")
        domains = []
    if not isinstance(certificates, list):
        logger.warning(f"[AppAnalysis] certificates is not a list: {type(certificates)}")
        certificates = []
    if not isinstance(manifest, dict):
        logger.warning(f"[AppAnalysis] manifest is not a dict: {type(manifest)}")
        manifest = {}
    if not isinstance(dex_analysis, dict):
        logger.warning(f"[AppAnalysis] dex_analysis is not a dict: {type(dex_analysis)}")
        dex_analysis = {}
    if not isinstance(network_artifacts, dict):
        logger.warning(f"[AppAnalysis] network_artifacts is not a dict: {type(network_artifacts)}")
        network_artifacts = {}
    logger.info(f"[BuildResult] STEP B complete: {int((time.time() - step_start) * 1000)}ms")
    
    # STEP C: Categorize permissions
    step_start = time.time()
    logger.info(f"[BuildResult] STEP C: Categorizing permissions")
    # Categorize permissions
    permission_categories = _categorize_permissions(permissions)
    logger.info(f"[BuildResult] STEP C complete: {int((time.time() - step_start) * 1000)}ms")
    
    # STEP D: Calculate risk score
    step_start = time.time()
    logger.info(f"[BuildResult] STEP D: Calculating risk score")
    if analysis_id:
        _set_progress(
            analysis_id,
            status="analyzing",
            progress=75,
            current_step="Risk Engine Running",
            active_key="risk",
            completed_keys=[
                "extraction", "sha256", "manifest", "permissions",
                "components", "dex", "strings", "certificates"
            ],
            extra={"sha256": sha256_hash}
        )
    # Calculate risk score based on real evidence
    risk_assessment = _calculate_risk_score(
        permissions=permissions,
        suspicious_functions=suspicious_functions,
        api_usage=api_usage,
        dex_analysis=dex_analysis,
        domains=domains
    )
    logger.info(f"[BuildResult] STEP D complete: {int((time.time() - step_start) * 1000)}ms, Risk={risk_assessment['overall_score']}")
    
    # STEP E: Detect obfuscation
    step_start = time.time()
    logger.info(f"[BuildResult] STEP E: Detecting obfuscation")
    # Detect obfuscation
    obfuscation_analysis = _analyze_obfuscation(dex_analysis, apk_analysis)
    logger.info(f"[BuildResult] STEP E complete: {int((time.time() - step_start) * 1000)}ms")
    
    # STEP F: Detect banking trojan indicators
    step_start = time.time()
    logger.info(f"[BuildResult] STEP F: Detecting banking trojan indicators")
    # Detect banking trojan indicators
    banking_indicators = _detect_banking_trojan_indicators(
        permissions=permissions,
        suspicious_functions=suspicious_functions,
        api_usage=api_usage,
        apk_analysis=apk_analysis
    )
    logger.info(f"[BuildResult] STEP F complete: {int((time.time() - step_start) * 1000)}ms")
    
    # STEP G: Build attack chain
    step_start = time.time()
    logger.info(f"[BuildResult] STEP G: Building attack chain")
    # Build attack chain
    attack_chain = _build_attack_chain(
        permissions=permissions,
        suspicious_functions=suspicious_functions,
        api_usage=api_usage,
        banking_indicators=banking_indicators
    )
    logger.info(f"[BuildResult] STEP G complete: {int((time.time() - step_start) * 1000)}ms")
    
    # STEP H: Automated Sentinel assessment from static APK findings.
    step_start = time.time()
    logger.info(f"[BuildResult] STEP H: Generating deterministic security assessment")
    if analysis_id:
        _set_progress(
            analysis_id,
            status="analyzing",
            progress=85,
            current_step="Automated Security Assessment",
            active_key="assessment",
            completed_keys=[
                "extraction", "sha256", "manifest", "permissions",
                "components", "dex", "strings", "certificates", "risk"
            ],
            extra={"sha256": sha256_hash}
        )
    assessment_provider = get_default_analysis_provider()
    security_assessment = await assessment_provider.assess(
        apk_data=apk_analysis,
        risk_assessment=risk_assessment,
        analysis_metadata={
            "analysis_id": analysis_id,
            "sha256": sha256_hash,
            "package": package,
            "include_ai_requested": include_ai,
        },
    )
    risk_assessment = _assessment_risk_payload(security_assessment, risk_assessment)
    assessment_time = int((time.time() - step_start) * 1000)
    logger.info(f"[BuildResult] STEP H complete: {assessment_time}ms ({assessment_time/1000:.1f}s)")
    if assessment_time > 10000:
        logger.warning(f"[BuildResult] Automated assessment took {assessment_time/1000:.1f}s.")
    
    # STEP I: Build investigation graph
    step_start = time.time()
    logger.info(f"[BuildResult] STEP I: Building investigation graph")
    # Build investigation graph data
    graph_data = _build_investigation_graph(
        package=package,
        permissions=permissions,
        suspicious_functions=suspicious_functions,
        api_usage=api_usage,
        attack_chain=attack_chain
    )
    logger.info(f"[BuildResult] STEP I complete: {int((time.time() - step_start) * 1000)}ms")

    # STEP J: Assemble final tab payload
    step_start = time.time()
    logger.info(f"[BuildResult] STEP J: Assembling final analysis payload")
    
    # TAB 1: Executive Summary
    executive_summary = {
        "name": apk_analysis.get('app_name', package.split('.')[-1]),
        "package": package,
        "version_name": apk_analysis.get('version_name', 'unknown'),
        "version_code": apk_analysis.get('version_code', 0),
        "developer": certificates[0].get('subject', 'Unknown') if certificates else 'Unknown',
        "sha256": sha256_hash,
        "file_size": file_size,
        "file_size_mb": round(file_size / (1024 * 1024), 2),
        "target_sdk": apk_analysis.get('target_sdk_version', 0),
        "min_sdk": apk_analysis.get('min_sdk_version', 0),
        "is_signed": apk_analysis.get('is_signed', False),
        "certificate": certificates[0] if certificates else {},
        "main_activity": apk_analysis.get('main_activity', ''),
        "risk_score": risk_assessment['overall_score'],
        "threat_level": risk_assessment['threat_level'],
        "malicious_confidence": risk_assessment['malicious_confidence']
    }
    
    # TAB 2: Permission Intelligence
    permission_intelligence = {
        "total_permissions": len(permissions),
        "dangerous_count": len([p for p in permissions if p.get('category') == 'dangerous']),
        "network_count": len([p for p in permissions if p.get('category') == 'network']),
        "system_count": len([p for p in permissions if p.get('category') == 'system']),
        "categories": permission_categories,
        "permissions": permissions,
        "risk_analysis": _analyze_permission_risks(permissions)
    }
    
    # TAB 3: Manifest Intelligence
    manifest_intelligence = {
        "activities": apk_analysis.get('activities', []),
        "services": apk_analysis.get('services', []),
        "receivers": apk_analysis.get('receivers', []),
        "providers": apk_analysis.get('providers', []),
        "exported_components": apk_analysis.get('exported_components', []),
        "intent_actions": manifest.get('intent_actions', []),
        "uses_features": manifest.get('uses_features', []),
        "is_debuggable": 'DEBUGGABLE' in apk_analysis.get('files', {}).get('flags', []),
        "allows_backup": 'ALLOW_BACKUP' in apk_analysis.get('files', {}).get('flags', []),
        "misconfigurations": _detect_manifest_misconfigurations(apk_analysis)
    }
    
    # TAB 4: DEX Reverse Engineering
    dex_intelligence = {
        "dex_files": dex_analysis.get('dex_files', []),
        "dex_count": dex_analysis.get('dex_count', 0),
        "class_count": dex_analysis.get('class_count', 0),
        "method_count": dex_analysis.get('method_count', 0),
        "is_multidex": dex_analysis.get('is_multidex', False),
        "sample_classes": dex_analysis.get('classes', [])[:100],
        "sample_methods": dex_analysis.get('methods', [])[:100],
        "has_reflection": any(api.get('category') == 'reflection' for api in api_usage),
        "has_dynamic_loading": any(api.get('category') == 'dynamic_loading' for api in api_usage),
        "native_libraries": apk_analysis.get('native_libraries', [])
    }
    
    # TAB 5: Code Intelligence
    code_intelligence = {
        "suspicious_functions": suspicious_functions,
        "total_suspicious": len(suspicious_functions),
        "high_risk_count": len([f for f in suspicious_functions if f.get('severity') == 'HIGH']),
        "medium_risk_count": len([f for f in suspicious_functions if f.get('severity') == 'MEDIUM']),
        "api_usage": api_usage,
        "accessibility_abuse": _has_api_category(api_usage, 'accessibility'),
        "sms_interception": _has_api_category(api_usage, 'sms'),
        "dynamic_code_execution": _has_api_category(api_usage, 'dynamic_loading'),
        "reflection_usage": _has_api_category(api_usage, 'reflection')
    }
    
    # TAB 6: Obfuscation Analysis
    # (Already built above)
    
    # TAB 7: Network Intelligence
    network_intelligence = {
        "urls": urls,
        "domains": domains,
        "ip_addresses": network_artifacts.get('ip_addresses', []),
        "url_count": len(urls),
        "domain_count": len(domains),
        "ip_count": len(network_artifacts.get('ip_addresses', [])),
        "has_network_permission": any(p.get('category') == 'network' for p in permissions),
        "network_apis": [api for api in api_usage if api.get('category') == 'network']
    }
    
    # TAB 8: Security Weaknesses
    security_weaknesses = _detect_security_weaknesses(
        apk_analysis=apk_analysis,
        strings=apk_analysis.get('strings', []),
        manifest=manifest
    )
    
    # TAB 9: Banking Trojan Detection
    # (Already built above)
    
    # TAB 10: Attack Chain
    # (Already built above)
    
    # TAB 11: AI Investigator
    # (Already generated above)
    
    # TAB 12: Investigation Graph
    # (Already built above)
    
    total_time = extraction_time + analysis_time
    logger.info(f"[BuildResult] STEP J complete: {int((time.time() - step_start) * 1000)}ms")
    
    return {
        "success": True,
        "package": package,
        "sha256": sha256_hash,
        "apk_analysis": apk_analysis,
        
        # Tab 1
        "executive_summary": executive_summary,
        
        # Tab 2
        "permission_intelligence": permission_intelligence,
        
        # Tab 3
        "manifest_intelligence": manifest_intelligence,
        
        # Tab 4
        "dex_intelligence": dex_intelligence,
        
        # Tab 5
        "code_intelligence": code_intelligence,
        
        # Tab 6
        "obfuscation_analysis": obfuscation_analysis,
        
        # Tab 7
        "network_intelligence": network_intelligence,
        
        # Tab 8
        "security_weaknesses": security_weaknesses,
        
        # Tab 9
        "banking_trojan_detection": banking_indicators,
        
        # Tab 10
        "attack_chain": attack_chain,
        
        # Tab 11
        "ai_assessment": security_assessment,
        "security_assessment": security_assessment,
        "automated_security_assessment": security_assessment,
        "risk_assessment": risk_assessment,
        "risk_assessment_internal": risk_assessment,
        
        # Tab 12
        "investigation_graph": graph_data,
        
        # Performance metrics
        "performance": {
            "extraction_time": round(extraction_time, 2),
            "analysis_time": round(analysis_time, 2),
            "total_time": round(total_time, 2),
            "cache_hit": False
        }
    }




# ============================================================================
# HELPER FUNCTIONS - Evidence-based analysis builders
# ============================================================================

def _categorize_permissions(permissions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Categorize permissions by risk and type"""
    if not permissions or not isinstance(permissions, list):
        return {
            "dangerous": [], "network": [], "storage": [], "sms": [], "phone": [],
            "location": [], "camera_mic": [], "contacts": [], "accessibility": [],
            "device_admin": [], "system": [], "normal": []
        }
    
    categories = {
        "dangerous": [],
        "network": [],
        "storage": [],
        "sms": [],
        "phone": [],
        "location": [],
        "camera_mic": [],
        "contacts": [],
        "accessibility": [],
        "device_admin": [],
        "system": [],
        "normal": []
    }
    
    for perm in permissions:
        if not isinstance(perm, dict):
            continue
        perm_name = perm.get('name', '')
        category = perm.get('category', 'normal')
        
        # Further categorize dangerous permissions
        if 'SMS' in perm_name or 'MMS' in perm_name:
            categories['sms'].append(perm)
        elif 'LOCATION' in perm_name:
            categories['location'].append(perm)
        elif 'CAMERA' in perm_name or 'RECORD_AUDIO' in perm_name:
            categories['camera_mic'].append(perm)
        elif 'CONTACTS' in perm_name or 'GET_ACCOUNTS' in perm_name:
            categories['contacts'].append(perm)
        elif 'PHONE' in perm_name or 'CALL' in perm_name:
            categories['phone'].append(perm)
        elif 'ACCESSIBILITY' in perm_name:
            categories['accessibility'].append(perm)
        elif 'DEVICE_ADMIN' in perm_name or 'BIND_DEVICE_ADMIN' in perm_name:
            categories['device_admin'].append(perm)
        elif 'STORAGE' in perm_name:
            categories['storage'].append(perm)
        elif category == 'network':
            categories['network'].append(perm)
        elif category == 'system':
            categories['system'].append(perm)
        elif category == 'dangerous':
            categories['dangerous'].append(perm)
        else:
            categories['normal'].append(perm)
    
    return categories


def _calculate_risk_score(
    permissions: List[Dict],
    suspicious_functions: List[Dict],
    api_usage: List[Dict],
    dex_analysis: Dict,
    domains: List[str]
) -> Dict[str, Any]:
    """
    SMART RISK SCORING - Evidence-based, runs before the assessment engine
    
    SCORING SYSTEM:
    - SYSTEM_ALERT_WINDOW = +25
    - BIND_ACCESSIBILITY_SERVICE = +30
    - SEND_SMS/READ_SMS = +20/+15
    - REQUEST_INSTALL_PACKAGES = +15
    - DexClassLoader/Runtime.exec = +20 each
    - High suspicious functions = +35
    - Dangerous permissions > 15 = +30
    """
    import time
    step_start = time.time()
    
    # Ensure all inputs are valid
    permissions = permissions if isinstance(permissions, list) else []
    suspicious_functions = suspicious_functions if isinstance(suspicious_functions, list) else []
    api_usage = api_usage if isinstance(api_usage, list) else []
    domains = domains if isinstance(domains, list) else []
    dex_analysis = dex_analysis if isinstance(dex_analysis, dict) else {}
    
    score = 0
    risk_factors = []
    
    # Critical permission checks (exact matching)
    perm_names = [p.get('name', '') for p in permissions]
    
    if any('SYSTEM_ALERT_WINDOW' in p for p in perm_names):
        score += 25
        risk_factors.append("SYSTEM_ALERT_WINDOW (+25): Can draw overlay screens")
    
    if any('BIND_ACCESSIBILITY_SERVICE' in p for p in perm_names):
        score += 30
        risk_factors.append("BIND_ACCESSIBILITY_SERVICE (+30): Accessibility abuse")
    
    if any('SEND_SMS' in p for p in perm_names):
        score += 20
        risk_factors.append("SEND_SMS (+20): Can send SMS messages")
    
    if any('READ_SMS' in p for p in perm_names):
        score += 15
        risk_factors.append("READ_SMS (+15): Can read SMS/OTP")
    
    if any('REQUEST_INSTALL_PACKAGES' in p for p in perm_names):
        score += 15
        risk_factors.append("REQUEST_INSTALL_PACKAGES (+15): Can install APKs")
    
    # API-based scoring
    for api in api_usage:
        category = api.get('category', '')
        if category == 'dynamic_loading':
            score += 20
            risk_factors.append("DexClassLoader detected (+20): Dynamic code loading")
            break
    
    # Check for Runtime.exec in suspicious functions
    for func in suspicious_functions:
        func_name = func.get('name', '').lower()
        if 'runtime.exec' in func_name or 'processbuilder' in func_name:
            score += 20
            risk_factors.append("Runtime.exec (+20): Can execute shell commands")
            break
    
    # Bulk permission risk
    dangerous_perms = [p for p in permissions if p.get('category') == 'dangerous']
    if len(dangerous_perms) > 15:
        score += 30
        risk_factors.append(f"Excessive permissions (+30): {len(dangerous_perms)} dangerous")
    elif len(dangerous_perms) > 10:
        score += 20
        risk_factors.append(f"Many permissions (+20): {len(dangerous_perms)} dangerous")
    elif len(dangerous_perms) > 5:
        score += 10
        risk_factors.append(f"Moderate permissions (+10): {len(dangerous_perms)} dangerous")
    
    # Suspicious function risk
    high_risk_funcs = [f for f in suspicious_functions if f.get('severity') in ['HIGH', 'CRITICAL']]
    if len(high_risk_funcs) > 10:
        score += 35
        risk_factors.append(f"High-risk functions (+35): {len(high_risk_funcs)} detected")
    elif len(high_risk_funcs) > 5:
        score += 25
        risk_factors.append(f"High-risk functions (+25): {len(high_risk_funcs)} detected")
    elif len(high_risk_funcs) > 0:
        score += 15
        risk_factors.append(f"High-risk functions (+15): {len(high_risk_funcs)} detected")
    
    # API abuse patterns
    risky_apis = ['accessibility', 'sms', 'reflection', 'dynamic_loading']
    detected_risky_apis = [api for api in api_usage if api.get('category') in risky_apis]
    if len(detected_risky_apis) > 2:
        score += 15
        risk_factors.append(f"Multiple risky APIs (+15): {len(detected_risky_apis)} categories")
    elif len(detected_risky_apis) > 0:
        score += 10
        api_cats = ', '.join([a.get('category') for a in detected_risky_apis])
        risk_factors.append(f"Risky APIs (+10): {api_cats}")
    
    # Obfuscation indicator
    if dex_analysis.get('class_count', 0) > 10000:
        score += 10
        risk_factors.append(f"Large codebase (+10): {dex_analysis.get('class_count')} classes")
    
    # Network risk
    suspicious_domains = [d for d in domains if not any(safe in d.lower() for safe in ['google', 'android', 'firebase'])]
    if len(suspicious_domains) > 10:
        score += 10
        risk_factors.append(f"Unknown domains (+10): {len(suspicious_domains)} domains")
    elif len(suspicious_domains) > 5:
        score += 5
        risk_factors.append(f"Several unknown domains (+5): {len(suspicious_domains)}")
    
    # Determine risk level with the public Sentinel score bands.
    bounded_score = min(100, score)
    if bounded_score <= 25:
        threat_level = "LOW"
    elif bounded_score <= 50:
        threat_level = "MEDIUM"
    elif bounded_score <= 75:
        threat_level = "HIGH"
    else:
        threat_level = "CRITICAL"
    confidence = bounded_score
    
    risk_time = int((time.time() - step_start) * 1000)
    logger.info(f"[PERF] Risk Scoring: {risk_time}ms (Score: {score}/100, Level: {threat_level})")
    
    return {
        "overall_score": bounded_score,
        "threat_level": threat_level,
        "malicious_confidence": confidence,
        "risk_factors": risk_factors,
        "_risk_time_ms": risk_time
    }


def _analyze_permission_risks(permissions: List[Dict]) -> List[Dict[str, Any]]:
    """Analyze individual permission risks with abuse potential"""
    if not permissions or not isinstance(permissions, list):
        return []
    
    risk_analysis = []
    
    risk_map = {
        "READ_SMS": {"risk": "HIGH", "abuse": "OTP theft, banking 2FA bypass", "confidence": 95},
        "RECEIVE_SMS": {"risk": "HIGH", "abuse": "SMS interception for OTP theft", "confidence": 95},
        "SEND_SMS": {"risk": "HIGH", "abuse": "Premium SMS fraud, spam", "confidence": 90},
        "BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "abuse": "Overlay attacks, credential theft, screen reading", "confidence": 98},
        "SYSTEM_ALERT_WINDOW": {"risk": "HIGH", "abuse": "Overlay attacks, phishing screens", "confidence": 90},
        "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {"risk": "MEDIUM", "abuse": "Persistent background execution", "confidence": 75},
        "READ_PHONE_STATE": {"risk": "MEDIUM", "abuse": "Device fingerprinting, tracking", "confidence": 70},
        "READ_CONTACTS": {"risk": "MEDIUM", "abuse": "Contact harvesting, spam targeting", "confidence": 75},
        "ACCESS_FINE_LOCATION": {"risk": "MEDIUM", "abuse": "Location tracking, stalking", "confidence": 70},
        "CAMERA": {"risk": "MEDIUM", "abuse": "Unauthorized photo/video capture", "confidence": 80},
        "RECORD_AUDIO": {"risk": "MEDIUM", "abuse": "Eavesdropping, audio recording", "confidence": 80},
        "INTERNET": {"risk": "LOW", "abuse": "Data exfiltration (requires other perms)", "confidence": 60},
    }
    
    for perm in permissions:
        if not isinstance(perm, dict):
            continue
        perm_name = perm.get('name', '').replace('android.permission.', '')
        if perm_name in risk_map:
            risk_info = risk_map[perm_name]
            risk_analysis.append({
                "permission": perm_name,
                "risk_level": risk_info["risk"],
                "abuse_potential": risk_info["abuse"],
                "confidence": risk_info["confidence"],
                "category": perm.get('category', 'unknown')
            })
    
    return risk_analysis


def _analyze_obfuscation(dex_analysis: Dict, apk_analysis: Dict) -> Dict[str, Any]:
    """Detect obfuscation techniques"""
    score = 0
    techniques = []
    
    class_count = dex_analysis.get('class_count', 0)
    method_count = dex_analysis.get('method_count', 0)
    classes = dex_analysis.get('classes', [])
    
    # Check for ProGuard/R8 obfuscation
    obfuscated_classes = [c for c in classes if '/a.java' in c or '/b.java' in c or len(c.split('.')[-1]) <= 2]
    if len(obfuscated_classes) > class_count * 0.3:
        score += 40
        techniques.append("ProGuard/R8 class name obfuscation detected")
    
    # Check for excessive reflection
    api_usage = apk_analysis.get('api_usage', [])
    has_reflection = any(api.get('category') == 'reflection' for api in api_usage)
    if has_reflection:
        score += 20
        techniques.append("Reflection API usage detected")
    
    # Check for dynamic loading
    has_dynamic_loading = any(api.get('category') == 'dynamic_loading' for api in api_usage)
    if has_dynamic_loading:
        score += 25
        techniques.append("Dynamic code loading detected")
    
    # Check for string encryption (long hex strings)
    strings = apk_analysis.get('strings', [])
    hex_strings = [s for s in strings if len(s) > 32 and all(c in '0123456789abcdefABCDEF' for c in s)]
    if len(hex_strings) > 20:
        score += 15
        techniques.append(f"Potential string encryption: {len(hex_strings)} hex strings")
    
    return {
        "obfuscation_score": min(100, score),
        "is_obfuscated": score > 30,
        "techniques_detected": techniques,
        "obfuscated_class_ratio": round(len(obfuscated_classes) / max(1, class_count) * 100, 1) if class_count > 0 else 0
    }


def _detect_banking_trojan_indicators(
    permissions: List[Dict],
    suspicious_functions: List[Dict],
    api_usage: List[Dict],
    apk_analysis: Dict
) -> Dict[str, Any]:
    """Detect banking trojan indicators"""
    # Ensure valid inputs
    permissions = permissions if isinstance(permissions, list) else []
    suspicious_functions = suspicious_functions if isinstance(suspicious_functions, list) else []
    api_usage = api_usage if isinstance(api_usage, list) else []
    
    indicators = []
    confidence = 0
    
    # Accessibility abuse
    has_accessibility = any('ACCESSIBILITY' in p.get('name', '') for p in permissions)
    if has_accessibility:
        indicators.append({
            "type": "Accessibility Abuse",
            "severity": "CRITICAL",
            "evidence": "BIND_ACCESSIBILITY_SERVICE permission",
            "description": "Can read screen content and perform automated actions"
        })
        confidence += 35
    
    # Overlay attacks
    has_overlay = any('SYSTEM_ALERT_WINDOW' in p.get('name', '') for p in permissions)
    if has_overlay:
        indicators.append({
            "type": "Overlay Attack Capability",
            "severity": "HIGH",
            "evidence": "SYSTEM_ALERT_WINDOW permission",
            "description": "Can draw phishing screens over banking apps"
        })
        confidence += 25
    
    # SMS interception (OTP theft)
    has_sms = any('SMS' in p.get('name', '') for p in permissions)
    if has_sms:
        indicators.append({
            "type": "SMS Interception",
            "severity": "HIGH",
            "evidence": "SMS permissions detected",
            "description": "Can intercept OTP codes for 2FA bypass"
        })
        confidence += 25
    
    # Screen capture
    has_screen_capture = any(f.get('name', '') in ['captureScreen', 'takeScreenshot', 'MediaProjection'] for f in suspicious_functions)
    if has_screen_capture:
        indicators.append({
            "type": "Screen Capture",
            "severity": "HIGH",
            "evidence": "Screen capture APIs detected",
            "description": "Can capture sensitive banking information"
        })
        confidence += 15
    
    return {
        "is_banking_trojan": confidence > 50,
        "confidence": min(100, confidence),
        "indicators": indicators,
        "indicator_count": len(indicators)
    }


def _build_attack_chain(
    permissions: List[Dict],
    suspicious_functions: List[Dict],
    api_usage: List[Dict],
    banking_indicators: Dict
) -> Dict[str, Any]:
    """Build attack chain from evidence"""
    # Ensure valid inputs
    permissions = permissions if isinstance(permissions, list) else []
    suspicious_functions = suspicious_functions if isinstance(suspicious_functions, list) else []
    api_usage = api_usage if isinstance(api_usage, list) else []
    banking_indicators = banking_indicators if isinstance(banking_indicators, dict) else {}
    
    stages = []
    
    # Persistence
    has_background = any('FOREGROUND_SERVICE' in p.get('name', '') for p in permissions)
    has_boot = any('BOOT_COMPLETED' in str(item) for item in api_usage)
    if has_background or has_boot:
        stages.append({
            "stage": "Persistence",
            "description": "Maintains presence after reboot",
            "evidence": [
                "FOREGROUND_SERVICE permission" if has_background else None,
                "BOOT_COMPLETED receiver" if has_boot else None
            ],
            "risk": "MEDIUM"
        })
    
    # Privilege Escalation
    if banking_indicators.get('confidence', 0) > 50:
        accessibility_indicator = next((i for i in banking_indicators.get('indicators', []) if i.get('type') == 'Accessibility Abuse'), None)
        if accessibility_indicator:
            stages.append({
                "stage": "Privilege Escalation",
                "description": "Gains powerful accessibility permissions",
                "evidence": [accessibility_indicator.get('evidence')],
                "risk": "HIGH"
            })
    
    # Data Collection
    collection_evidence = []
    for func in suspicious_functions:
        if any(keyword in func.get('name', '').lower() for keyword in ['read', 'get', 'collect', 'harvest']):
            collection_evidence.append(func.get('name'))
    
    if collection_evidence:
        stages.append({
            "stage": "Data Collection",
            "description": "Collects sensitive data from device",
            "evidence": collection_evidence[:5],
            "risk": "HIGH"
        })
    
    # Exfiltration requires network API evidence, not only the INTERNET permission.
    network_api_evidence = [
        api.get("name") or api.get("api") or api.get("method") or str(api)
        for api in api_usage
        if api.get("category") == "network"
    ]
    if network_api_evidence:
        stages.append({
            "stage": "Exfiltration",
            "description": "Uses extracted network API references that can transmit collected data",
            "evidence": network_api_evidence[:5],
            "risk": "CRITICAL"
        })
    
    return {
        "stages": stages,
        "total_stages": len(stages),
        "max_risk": "CRITICAL" if any(s.get('risk') == 'CRITICAL' for s in stages) else "HIGH" if stages else "LOW"
    }


def _build_investigation_graph(
    package: str,
    permissions: List[Dict],
    suspicious_functions: List[Dict],
    api_usage: List[Dict],
    attack_chain: Dict
) -> Dict[str, Any]:
    """Build investigation graph data"""
    # Ensure valid inputs
    permissions = permissions if isinstance(permissions, list) else []
    suspicious_functions = suspicious_functions if isinstance(suspicious_functions, list) else []
    api_usage = api_usage if isinstance(api_usage, list) else []
    attack_chain = attack_chain if isinstance(attack_chain, dict) else {}
    
    nodes = []
    edges = []
    
    # Root node: APK
    nodes.append({"id": "apk", "label": package, "type": "apk", "risk": "root"})
    
    # Permission nodes
    dangerous_perms = [p for p in permissions if p.get('category') == 'dangerous'][:10]
    for i, perm in enumerate(dangerous_perms):
        node_id = f"perm_{i}"
        nodes.append({
            "id": node_id,
            "label": perm.get('name', '').split('.')[-1],
            "type": "permission",
            "risk": "high" if perm.get('category') == 'dangerous' else "medium"
        })
        edges.append({"from": "apk", "to": node_id, "label": "requires"})
    
    # Function nodes
    high_risk_funcs = [f for f in suspicious_functions if f.get('severity') == 'HIGH'][:5]
    for i, func in enumerate(high_risk_funcs):
        node_id = f"func_{i}"
        nodes.append({
            "id": node_id,
            "label": func.get('name', '')[:30],
            "type": "function",
            "risk": "critical"
        })
        edges.append({"from": "apk", "to": node_id, "label": "contains"})
    
    # Threat nodes
    for i, stage in enumerate(attack_chain.get('stages', [])[:4]):
        node_id = f"threat_{i}"
        nodes.append({
            "id": node_id,
            "label": stage.get('stage', ''),
            "type": "threat",
            "risk": stage.get('risk', 'medium').lower()
        })
        edges.append({"from": "apk", "to": node_id, "label": "enables"})
    
    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges)
    }


def _detect_manifest_misconfigurations(apk_analysis: Dict) -> List[Dict[str, Any]]:
    """Detect dangerous manifest configurations"""
    misconfigs = []
    
    # Check debuggable
    if 'DEBUGGABLE' in str(apk_analysis.get('files', {})):
        misconfigs.append({
            "type": "Debuggable Application",
            "severity": "MEDIUM",
            "description": "Application can be debugged, exposing internal logic"
        })
    
    # Check backup allowed
    if 'ALLOW_BACKUP' in str(apk_analysis.get('files', {})):
        misconfigs.append({
            "type": "Backup Enabled",
            "severity": "LOW",
            "description": "Application data can be backed up via ADB"
        })
    
    # Check exported components
    exported = apk_analysis.get('exported_components', [])
    if len(exported) > 5:
        misconfigs.append({
            "type": "Many Exported Components",
            "severity": "MEDIUM",
            "description": f"{len(exported)} components exposed to other apps"
        })
    
    return misconfigs


def _detect_security_weaknesses(apk_analysis: Dict, strings: List[str], manifest: Dict) -> Dict[str, Any]:
    """Detect security weaknesses from strings and code"""
    # Ensure valid inputs
    strings = strings if isinstance(strings, list) else []
    manifest = manifest if isinstance(manifest, dict) else {}
    apk_analysis = apk_analysis if isinstance(apk_analysis, dict) else {}
    
    weaknesses = {
        "hardcoded_secrets": [],
        "api_keys": [],
        "tokens": [],
        "passwords": [],
        "sensitive_strings": []
    }
    
    # Patterns for detection
    patterns = {
        "api_keys": [r'api[_-]?key', r'apikey', r'api[_-]?secret'],
        "tokens": [r'token', r'auth[_-]?token', r'access[_-]?token'],
        "passwords": [r'password\s*=', r'pwd\s*=', r'pass\s*=']
    }
    
    import re
    
    # Check strings for secrets
    for string in strings[:1000]:  # Limit to first 1000 strings
        string_lower = string.lower()
        
        # Check for API keys (long alphanumeric strings)
        if len(string) > 20 and string.isalnum() and not string.isdigit():
            if any(re.search(pattern, string_lower) for pattern in patterns['api_keys']):
                weaknesses['api_keys'].append(string[:50])
        
        # Check for tokens
        if any(re.search(pattern, string_lower) for pattern in patterns['tokens']):
            weaknesses['tokens'].append(string[:50])
        
        # Check for passwords
        if any(re.search(pattern, string_lower) for pattern in patterns['passwords']):
            weaknesses['passwords'].append(string[:50])
    
    # Limit results
    for key in weaknesses:
        weaknesses[key] = weaknesses[key][:10]
    
    total_weaknesses = sum(len(v) for v in weaknesses.values())
    
    return {
        **weaknesses,
        "total_weaknesses": total_weaknesses,
        "has_secrets": total_weaknesses > 0
    }


def _has_api_category(api_usage: List[Dict], category: str) -> bool:
    """Check if API category is present"""
    return any(api.get('category') == category for api in api_usage)


@router.get("/package/{package_name}")
async def analyze_package(
    package_name: str,
    serial: str = Query(..., description="Device serial number")
):
    """
    Analyze application package with real APK extraction and analysis
    NO MOCK DATA - Everything extracted from actual APK
    
    Args:
        package_name: Android package name (e.g., com.android.chrome)
        serial: Device serial number
        
    Returns:
        Complete analysis results with real data from APK
    """
    logger.info(f"[AppAnalysis] Starting real analysis for {package_name} on device {serial}")
    
    try:
        result = await _extract_and_analyze_apk(package_name, serial)
        return result
        
    except HTTPException as e:
        if e.status_code >= 500:
            logger.error(traceback.format_exc())
            logger.error(f"[AppAnalysis] HTTPException type: {type(e).__name__}")
            logger.error(f"[AppAnalysis] HTTPException message: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"[AppAnalysis] Error: {e}", exc_info=True)
        logger.error(traceback.format_exc())
        logger.error(f"[AppAnalysis] Exception type: {type(e).__name__}")
        logger.error(f"[AppAnalysis] Exception message: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
@router.delete("/cache")
async def clear_analysis_cache():
    """Clear analysis cache"""
    global _analysis_cache, _cache_timestamps
    cache_size = len(_analysis_cache)
    _analysis_cache.clear()
    _cache_timestamps.clear()
    return {
        "success": True,
        "message": f"Cleared {cache_size} cached analyses"
    }

