from pathlib import Path
from typing import Any, Dict, List, Optional
from androguard.core.apk import APK
from androguard.core.axml import AXMLPrinter
from androguard.core.dex import DEX
from lxml import etree
import logging
import hashlib
import re
import shutil
import zipfile
import traceback

from app.services.suspicious_function_engine import SuspiciousFunctionDiscovery

logger = logging.getLogger(__name__)

try:
    from loguru import logger as _loguru_logger
    _loguru_logger.disable("androguard")
    _loguru_logger.disable("androguard.core")
except Exception:
    pass


class APKAnalyzer:
    """Service for static APK analysis using Androguard - OPTIMIZED FOR SPEED"""
    
    # Performance limits
    MAX_CLASSES = 100
    MAX_METHODS_PER_CLASS = 25
    MAX_STRINGS = 1000
    MAX_URLS = 100
    MAX_DOMAINS = 100
    MAX_DEX_PARSE_BYTES = 4 * 1024 * 1024

    @staticmethod
    def _safe_apk_value(label: str, getter, default: Any = None) -> Any:
        try:
            return getter()
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error(f"[APKAnalyzer] {label} exception type: {type(e).__name__}")
            logger.error(f"[APKAnalyzer] {label} exception message: {str(e)}")
            return default

    @staticmethod
    def _decode_manifest_from_zip(apk_path: Path) -> etree._Element:
        with zipfile.ZipFile(apk_path) as apk_zip:
            manifest_data = apk_zip.read("AndroidManifest.xml")
        return AXMLPrinter(manifest_data).get_xml_obj()

    @staticmethod
    def _manifest_sdk_attr(manifest: etree._Element, name: str) -> Optional[str]:
        uses_sdk = manifest.find("uses-sdk")
        if uses_sdk is None:
            return None
        return APKAnalyzer._android_attr(uses_sdk, name)
    
    @staticmethod
    async def analyze(apk_path: Path) -> Dict:
        """
        Perform static analysis on an APK file - OPTIMIZED
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary containing analysis results
        """
        import time
        timings = {}
        total_start = time.time()
        
        try:
            # Check if file is actually an APK
            if not str(apk_path).endswith('.apk'):
                return {
                    "package_name": "N/A",
                    "app_name": "Non-APK file",
                    "permissions": [],
                    "activities": [],
                    "services": [],
                    "receivers": [],
                    "providers": [],
                    "urls": [],
                    "domains": [],
                    "native_libraries": [],
                    "is_apk": False,
                    "file_type": str(apk_path).split('.')[-1]
                }
            
            # STEP 1: Load APK container without heavyweight manifest/resource analysis
            step_start = time.time()
            apk = APK(str(apk_path), skip_analysis=True)
            timings['apk_load'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] APK Load: {timings['apk_load']}ms")
            
            # STEP 2: Manifest (fast)
            step_start = time.time()
            manifest_xml = APKAnalyzer._decode_manifest_from_zip(Path(apk_path))
            package_name = manifest_xml.get("package") or APKAnalyzer._safe_apk_value("package_name", apk.get_package, "")
            version_name = APKAnalyzer._android_attr(manifest_xml, "versionName")
            version_code = APKAnalyzer._android_attr(manifest_xml, "versionCode")
            min_sdk_version = APKAnalyzer._manifest_sdk_attr(manifest_xml, "minSdkVersion")
            target_sdk_version = APKAnalyzer._manifest_sdk_attr(manifest_xml, "targetSdkVersion")
            max_sdk_version = APKAnalyzer._manifest_sdk_attr(manifest_xml, "maxSdkVersion")
            timings['manifest_parse'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] Manifest Parse: {timings['manifest_parse']}ms")
            
            # STEP 3: Components (fast)
            step_start = time.time()
            components = APKAnalyzer._extract_components(apk, manifest_xml)
            timings['components'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] Components: {timings['components']}ms")
            
            # STEP 4: Permissions (fast)
            step_start = time.time()
            permissions = APKAnalyzer._extract_permissions(apk, manifest_xml)
            timings['permissions'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] Permissions: {timings['permissions']}ms")
            
            # STEP 5: DEX Analysis (LIMITED - MOST EXPENSIVE)
            step_start = time.time()
            dex_analysis = APKAnalyzer._extract_dex_analysis_limited(apk)
            timings['dex_analysis'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] DEX Analysis (LIMITED): {timings['dex_analysis']}ms")
            
            # STEP 6: Strings (LIMITED)
            step_start = time.time()
            strings = APKAnalyzer._extract_strings_limited(apk, dex_analysis)
            timings['strings'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] Strings (LIMITED): {timings['strings']}ms")
            
            # STEP 7: URLs/Domains (from limited strings)
            step_start = time.time()
            urls = APKAnalyzer._extract_urls_from_strings(strings)
            domains = APKAnalyzer._extract_domains(urls, strings)
            timings['urls_domains'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] URLs/Domains: {timings['urls_domains']}ms")
            
            # STEP 8: Certificates (fast)
            step_start = time.time()
            certificates = APKAnalyzer._extract_certificates(apk)
            timings['certificates'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] Certificates: {timings['certificates']}ms")
            
            # STEP 9: API Usage (from limited data)
            step_start = time.time()
            api_usage = APKAnalyzer._extract_api_usage(strings, dex_analysis)
            timings['api_usage'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] API Usage: {timings['api_usage']}ms")
            
            # STEP 10: Suspicious Functions (from limited methods)
            step_start = time.time()
            suspicious_functions = SuspiciousFunctionDiscovery.analyze_methods(dex_analysis)
            timings['suspicious_functions'] = int((time.time() - step_start) * 1000)
            logger.info(f"[PERF] Suspicious Functions: {timings['suspicious_functions']}ms")

            results = {
                "package_name": package_name,
                "app_name": APKAnalyzer._safe_apk_value("app_name", apk.get_app_name, package_name) or package_name,
                "version_name": version_name,
                "version_code": version_code,
                "min_sdk_version": min_sdk_version,
                "target_sdk_version": target_sdk_version,
                "max_sdk_version": max_sdk_version,
                
                # Permissions
                "permissions": permissions,
                
                # Components
                "activities": components["activities"],
                "services": components["services"],
                "receivers": components["receivers"],
                "providers": components["providers"],
                "exported_components": components["exported_components"],
                
                # URLs and domains
                "urls": urls,
                "domains": domains,
                
                # Native libraries
                "native_libraries": apk.get_libraries(),
                
                # Additional metadata
                "is_signed": apk.is_signed(),
                "is_valid_apk": apk.is_valid_APK(),
                "main_activity": apk.get_main_activity(),
                "libraries": apk.get_libraries(),
                "files": APKAnalyzer._extract_file_info(apk),
                "manifest": APKAnalyzer._extract_manifest_details(apk, manifest_xml),
                "strings": strings[:500],  # Limited
                "string_count": len(strings),
                "certificates": certificates,
                "dex_analysis": dex_analysis,
                "api_usage": api_usage,
                "network_artifacts": APKAnalyzer._extract_network_artifacts(urls, domains, strings),
                "decompiled_artifacts": APKAnalyzer._extract_decompiled_artifacts(dex_analysis),
                "suspicious_functions": suspicious_functions,
                "is_apk": True
            }
            
            total_time = int((time.time() - total_start) * 1000)
            timings['total'] = total_time
            logger.info(f"[PERF] ===== TOTAL ANALYSIS TIME: {total_time}ms =====")
            logger.info(f"[PERF] Breakdown: {timings}")
            
            results['_performance_timings'] = timings
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing APK: {str(e)}")
            import traceback
            logger.error(f"Full traceback:\n{traceback.format_exc()}")
            return {
                "error": str(e),
                "analysis_failed": True
            }
    
    @staticmethod
    def _extract_dex_analysis_limited(apk: APK) -> Dict[str, Any]:
        """
        LIMITED DEX Analysis - Only suspicious patterns
        MAX 100 classes, MAX 25 methods per class
        Target patterns:
        - AccessibilityService
        - SmsManager
        - WebView
        - DexClassLoader
        - Runtime.exec
        - ProcessBuilder
        - Reflection
        - Overlay APIs
        """
        SUSPICIOUS_PATTERNS = [
            'AccessibilityService', 'SmsManager', 'WebView', 
            'DexClassLoader', 'PathClassLoader', 'Runtime',
            'ProcessBuilder', 'java/lang/reflect', 'WindowManager',
            'SYSTEM_ALERT_WINDOW', 'addJavascriptInterface'
        ]
        
        classes = []
        methods = []
        strings = set()
        dex_files = list(apk.get_dex_names())
        classes_parsed = 0
        
        for dex_index, dex_data in enumerate(apk.get_all_dex()):
            if classes_parsed >= APKAnalyzer.MAX_CLASSES:
                break
                
            try:
                if len(dex_data) > APKAnalyzer.MAX_DEX_PARSE_BYTES:
                    printable_re = re.compile(rb"[\x20-\x7e]{4,}")
                    scan_window = dex_data[:APKAnalyzer.MAX_DEX_PARSE_BYTES]
                    for match in printable_re.finditer(scan_window):
                        value = match.group(0).decode("utf-8", errors="ignore")
                        strings.add(value)
                        if any(pattern in value for pattern in SUSPICIOUS_PATTERNS):
                            methods.append({
                                "class_name": "DEX byte scan",
                                "name": value[:160],
                                "descriptor": "matched in DEX string data",
                                "access_flags": "No Data Available",
                                "dex_index": dex_index,
                            })
                        if len(strings) >= APKAnalyzer.MAX_STRINGS:
                            break
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern.encode("utf-8") in scan_window:
                            classes.append(f"dex{dex_index}:{pattern}")
                    classes_parsed += max(1, len(classes))
                    continue

                dex = DEX(dex_data)
                for item in dex.get_strings():
                    if item:
                        strings.add(str(item))
                    if len(strings) >= APKAnalyzer.MAX_STRINGS:
                        break

                for cls in dex.get_classes():
                    if classes_parsed >= APKAnalyzer.MAX_CLASSES:
                        break
                    
                    class_name = cls.get_name()
                    
                    # Only process suspicious classes
                    is_suspicious = any(pattern in class_name for pattern in SUSPICIOUS_PATTERNS)
                    if not is_suspicious:
                        # Still count it, but don't extract methods
                        classes.append(class_name)
                        classes_parsed += 1
                        continue
                    
                    classes.append(class_name)
                    classes_parsed += 1
                    
                    # Extract methods (limited)
                    methods_in_class = 0
                    for method in cls.get_methods():
                        if methods_in_class >= APKAnalyzer.MAX_METHODS_PER_CLASS:
                            break
                        methods.append({
                            "class_name": class_name,
                            "name": method.get_name(),
                            "descriptor": method.get_descriptor(),
                            "access_flags": method.get_access_flags_string(),
                            "dex_index": dex_index,
                        })
                        methods_in_class += 1
                        
            except Exception as exc:
                logger.warning("DEX analysis failed for index %s: %s", dex_index, exc)

        return {
            "dex_files": dex_files,
            "dex_count": len(dex_files),
            "classes": classes[:APKAnalyzer.MAX_CLASSES],
            "class_count": len(classes),
            "methods": methods,
            "method_count": len(methods),
            "is_multidex": apk.is_multidex(),
            "_limited": True,
            "_max_classes_limit": APKAnalyzer.MAX_CLASSES,
            "_max_methods_per_class_limit": APKAnalyzer.MAX_METHODS_PER_CLASS,
            "_strings_sample": sorted(strings)[:APKAnalyzer.MAX_STRINGS],
        }
    
    @staticmethod
    def _extract_strings_limited(apk: APK, dex_analysis: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        LIMITED String extraction - Only from DEX, skip assets/resources
        MAX 1000 strings
        """
        if dex_analysis and dex_analysis.get("_strings_sample"):
            return dex_analysis["_strings_sample"][:APKAnalyzer.MAX_STRINGS]

        strings = set()

        try:
            # Only extract from DEX (fastest)
            for dex_data in apk.get_all_dex():
                dex = DEX(dex_data)
                for item in dex.get_strings():
                    if item:
                        strings.add(str(item))
                    if len(strings) >= APKAnalyzer.MAX_STRINGS:
                        break
                if len(strings) >= APKAnalyzer.MAX_STRINGS:
                    break
        except Exception as exc:
            logger.error("String extraction failed: %s", exc)
            import traceback
            logger.error(traceback.format_exc())
            logger.error("String extraction error type: %s", type(exc).__name__)
            logger.error("String extraction error message: %s", str(exc))

        # Skip resources and assets for speed
        return sorted(list(strings))[:APKAnalyzer.MAX_STRINGS]
    
    @staticmethod
    def _extract_permissions(apk: APK, manifest: Optional[etree._Element] = None) -> List[Dict[str, str]]:
        """Extract permissions with categorization."""
        permissions = []

        if manifest is not None:
            raw_permissions = [
                APKAnalyzer._android_attr(element, "name")
                for element in manifest.findall(".//uses-permission")
            ]
            raw_permissions = [perm for perm in raw_permissions if perm]
        else:
            raw_permissions = apk.get_permissions()

        for perm in raw_permissions:
            perm_info = {
                "name": perm,
                "category": APKAnalyzer._categorize_permission(perm)
            }
            permissions.append(perm_info)
        
        return permissions
    
    @staticmethod
    def _categorize_permission(permission: str) -> str:
        """Categorize permission by risk level."""
        dangerous_permissions = [
            "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
            "READ_CALENDAR", "WRITE_CALENDAR",
            "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
            "CAMERA",
            "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_PHONE_STATE", "CALL_PHONE", "READ_PHONE_NUMBERS",
            "ANSWER_PHONE_CALLS", "ADD_VOICEMAIL", "USE_SIP",
            "BODY_SENSORS",
            "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH",
            "RECEIVE_MMS",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        ]
        
        # Extract permission name without package prefix
        perm_name = permission.split(".")[-1]
        
        if perm_name in dangerous_permissions:
            return "dangerous"
        elif "INTERNET" in perm_name or "NETWORK" in perm_name:
            return "network"
        elif "SYSTEM" in perm_name or "ADMIN" in perm_name:
            return "system"
        else:
            return "normal"
    
    @staticmethod
    def _android_attr(element: etree._Element, name: str) -> Optional[str]:
        return element.get(f"{{http://schemas.android.com/apk/res/android}}{name}")

    @staticmethod
    def _normalize_component_name(package_name: str, name: Optional[str]) -> str:
        if not name:
            return ""
        if name.startswith("."):
            return f"{package_name}{name}"
        if "." not in name:
            return f"{package_name}.{name}"
        return name

    @staticmethod
    def _bool_attr(value: Optional[str]) -> Optional[bool]:
        if value is None:
            return None
        return str(value).lower() == "true"

    @staticmethod
    def _component_entry(package_name: str, tag: str, element: etree._Element) -> Dict[str, Any]:
        name = APKAnalyzer._normalize_component_name(package_name, APKAnalyzer._android_attr(element, "name"))
        explicit_exported = APKAnalyzer._bool_attr(APKAnalyzer._android_attr(element, "exported"))
        enabled = APKAnalyzer._bool_attr(APKAnalyzer._android_attr(element, "enabled"))
        permission = APKAnalyzer._android_attr(element, "permission")
        intent_filters = element.findall("intent-filter")
        actions = [
            APKAnalyzer._android_attr(action, "name") or ""
            for action in element.findall(".//action")
        ]
        categories = [
            APKAnalyzer._android_attr(category, "name") or ""
            for category in element.findall(".//category")
        ]
        data_schemes = [
            APKAnalyzer._android_attr(data, "scheme") or ""
            for data in element.findall(".//data")
            if APKAnalyzer._android_attr(data, "scheme")
        ]

        # Android defaults exported=true for components with intent filters when
        # the manifest omits the explicit flag; otherwise false. Provider defaults
        # varied on old Android versions, so unknown providers are treated as false
        # unless the manifest states otherwise.
        inferred_exported = bool(intent_filters) if tag != "provider" else False
        is_exported = explicit_exported if explicit_exported is not None else inferred_exported

        return {
            "name": name,
            "type": tag,
            "is_exported": is_exported,
            "exported_source": "manifest" if explicit_exported is not None else "inferred_from_intent_filters",
            "enabled": True if enabled is None else enabled,
            "permission": permission,
            "intent_filter_count": len(intent_filters),
            "actions": sorted(set(item for item in actions if item)),
            "categories": sorted(set(item for item in categories if item)),
            "data_schemes": sorted(set(data_schemes)),
        }

    @staticmethod
    def _extract_components(apk: APK, manifest: etree._Element) -> Dict[str, List[Dict[str, Any]]]:
        """Extract component metadata directly from AndroidManifest.xml."""
        package_name = manifest.get("package") or apk.get_package() or ""
        buckets = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        tag_map = {
            "activity": "activities",
            "activity-alias": "activities",
            "service": "services",
            "receiver": "receivers",
            "provider": "providers",
        }

        for tag, bucket in tag_map.items():
            for element in manifest.findall(f".//{tag}"):
                entry = APKAnalyzer._component_entry(package_name, tag, element)
                if entry["name"]:
                    buckets[bucket].append(entry)

        exported_components = [
            component
            for bucket in buckets.values()
            for component in bucket
            if component.get("is_exported")
        ]

        return {**buckets, "exported_components": exported_components}

    @staticmethod
    def _extract_manifest_details(apk: APK, manifest: etree._Element) -> Dict[str, Any]:
        """Extract manifest-level attributes and intent filter evidence."""
        try:
            xml_text = etree.tostring(manifest, encoding="unicode", pretty_print=True)
        except Exception:
            xml_text = ""

        uses_features = []
        for feature in manifest.findall(".//uses-feature"):
            uses_features.append({
                "name": APKAnalyzer._android_attr(feature, "name"),
                "required": APKAnalyzer._bool_attr(APKAnalyzer._android_attr(feature, "required")),
            })

        intent_actions = []
        for action in manifest.findall(".//action"):
            name = APKAnalyzer._android_attr(action, "name")
            if name:
                intent_actions.append(name)

        application = manifest.find("application")
        uses_cleartext_traffic = (
            APKAnalyzer._bool_attr(APKAnalyzer._android_attr(application, "usesCleartextTraffic"))
            if application is not None
            else None
        )

        return {
            "package": manifest.get("package") or apk.get_package(),
            "raw_xml": xml_text,
            "raw_xml_sha256": hashlib.sha256(xml_text.encode("utf-8")).hexdigest() if xml_text else None,
            "uses_features": uses_features,
            "intent_actions": sorted(set(intent_actions)),
            "declared_permissions": [
                APKAnalyzer._android_attr(element, "name")
                for element in manifest.findall(".//permission")
                if APKAnalyzer._android_attr(element, "name")
            ],
            "requested_aosp_permissions": [
                APKAnalyzer._android_attr(element, "name")
                for element in manifest.findall(".//uses-permission")
                if (APKAnalyzer._android_attr(element, "name") or "").startswith("android.permission.")
            ],
            "effective_target_sdk_version": APKAnalyzer._manifest_sdk_attr(manifest, "targetSdkVersion"),
            "uses_cleartext_traffic": uses_cleartext_traffic,
        }
    
    @staticmethod
    def _extract_file_info(apk: APK) -> Dict[str, Any]:
        """Extract file information from APK."""
        files = apk.get_files()
        
        file_info = {
            "total_files": len(files),
            "dex_files": [f for f in files if f.endswith('.dex')],
            "so_files": [f for f in files if f.endswith('.so')],
            "has_native_code": any(f.endswith('.so') for f in files),
            "has_assets": any(f.startswith('assets/') for f in files),
            "has_resources": any(f.startswith('res/') for f in files),
        }
        
        return file_info

    @staticmethod
    def _extract_strings(apk: APK) -> List[str]:
        """Extract strings from DEX, resources, XML, and printable asset bytes."""
        strings = set()

        try:
            for dex_data in apk.get_all_dex():
                dex = DEX(dex_data)
                strings.update(str(item) for item in dex.get_strings() if item)
        except Exception:
            pass

        try:
            resources = apk.get_android_resources()
            for value in resources.get_strings_resources().values():
                strings.add(str(value))
        except Exception:
            pass

        printable_re = re.compile(rb"[\x20-\x7e]{4,}")
        for filename in apk.get_files():
            if filename.endswith((".dex", ".so", ".arsc")):
                continue
            if not (
                filename.startswith(("assets/", "res/", "META-INF/"))
                or filename.endswith((".xml", ".json", ".txt", ".properties"))
            ):
                continue
            try:
                data = apk.get_file(filename)
                if not data:
                    continue
                for match in printable_re.findall(data[:1024 * 1024]):
                    strings.add(match.decode("utf-8", errors="ignore"))
            except Exception:
                continue

        return sorted(value for value in strings if value)

    @staticmethod
    def _extract_urls_from_strings(strings: List[str]) -> List[str]:
        urls = set()
        url_pattern = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+")
        for string in strings:
            urls.update(url_pattern.findall(string))
        return sorted(urls)[:250]

    @staticmethod
    def _extract_domains(urls: List[str], strings: List[str]) -> List[str]:
        """Extract domains from URLs and hardcoded domain-like strings."""
        from urllib.parse import urlparse
        domains = set()
        domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.add(parsed.netloc)
            except Exception:
                pass

        safe_suffixes = ("android.com", "google.com", "googleapis.com", "w3.org", "schemas.android.com")
        for string in strings:
            for match in domain_pattern.findall(string):
                lowered = match.lower()
                if not lowered.endswith(safe_suffixes):
                    domains.add(match)

        return sorted(domains)[:250]

    @staticmethod
    def _extract_certificates(apk: APK) -> List[Dict[str, Any]]:
        certificates = []
        certs = apk.get_certificates() or []
        der_certs = []
        for getter_name in ("get_certificates_der_v3", "get_certificates_der_v2", "get_certificates_der_v1"):
            getter = getattr(apk, getter_name, None)
            if not getter:
                continue
            try:
                der_certs = getter() or []
            except Exception:
                der_certs = []
            if der_certs:
                break

        if not der_certs:
            try:
                der_certs = [apk.get_certificate_der(filename) for filename in apk.get_signature_names()]
            except Exception:
                der_certs = []

        for index, cert in enumerate(certs):
            der = der_certs[index] if index < len(der_certs) else None
            entry = {
                "index": index,
                "sha256": hashlib.sha256(der).hexdigest() if der else None,
                "subject": getattr(getattr(cert, "subject", None), "human_friendly", None),
                "issuer": getattr(getattr(cert, "issuer", None), "human_friendly", None),
                "serial_number": str(getattr(cert, "serial_number", "")),
                "not_before": str(getattr(cert, "not_valid_before", "")),
                "not_after": str(getattr(cert, "not_valid_after", "")),
            }
            certificates.append(entry)

        return certificates

    @staticmethod
    def _extract_dex_analysis(apk: APK) -> Dict[str, Any]:
        """DEPRECATED - Use _extract_dex_analysis_limited instead"""
        return APKAnalyzer._extract_dex_analysis_limited(apk)

    @staticmethod
    def _extract_strings(apk: APK) -> List[str]:
        """DEPRECATED - Use _extract_strings_limited instead"""
        return APKAnalyzer._extract_strings_limited(apk)
    
    @staticmethod
    def _extract_api_usage(strings: List[str], dex_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """OPTIMIZED - Fast API pattern matching"""
        api_patterns = {
            "webview": ["WebView", "loadUrl", "addJavascriptInterface", "evaluateJavascript"],
            "sms": ["SmsManager", "TelephonyManager", "SMS_RECEIVED", "READ_SMS", "SEND_SMS"],
            "accessibility": ["AccessibilityService", "AccessibilityEvent", "BIND_ACCESSIBILITY_SERVICE"],
            "reflection": ["Class.forName", "Method.invoke", "getDeclaredMethod", "java/lang/reflect"],
            "dynamic_loading": ["DexClassLoader", "PathClassLoader", "loadClass"],
            "crypto": ["Cipher", "SecretKeySpec", "MessageDigest", "AES", "RSA"],
            "network": ["HttpURLConnection", "OkHttp", "Retrofit", "Socket", "WebSocket"],
            "filesystem": ["FileOutputStream", "SharedPreferences", "SQLiteDatabase"],
        }
        
        # Limited corpus for speed
        corpus = "\n".join(strings[:500])  # Reduced from 5000
        corpus += "\n" + "\n".join(
            f"{m.get('class_name')}.{m.get('name')}"
            for m in dex_analysis.get("methods", [])[:500]  # Limited
        )
        
        usage = []
        lowered = corpus.lower()
        for category, tokens in api_patterns.items():
            matches = [token for token in tokens if token.lower() in lowered]
            if matches:
                usage.append({
                    "category": category,
                    "matched_tokens": sorted(set(matches)),
                    "evidence_count": len(matches),
                })
        return usage

    @staticmethod
    def _extract_network_artifacts(urls: List[str], domains: List[str], strings: List[str]) -> Dict[str, Any]:
        """OPTIMIZED - Limited IP extraction"""
        ips = set()
        # Only check first 500 strings for IPs
        for string in strings[:500]:
            for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", string):
                parts = match.split(".")
                try:
                    if all(0 <= int(part) <= 255 for part in parts):
                        ips.add(match)
                except:
                    pass
                if len(ips) >= 50:
                    break

        return {
            "urls": urls,
            "domains": domains,
            "ip_addresses": sorted(ips)[:50],
        }

    @staticmethod
    def _extract_decompiled_artifacts(dex_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """OPTIMIZED - Minimal metadata"""
        return {
            "jadx_available": False,  # Skip check for speed
            "apktool_available": False,  # Skip check for speed
            "class_count": dex_analysis.get("class_count", 0),
            "method_count": dex_analysis.get("method_count", 0),
            "sample_classes": dex_analysis.get("classes", [])[:10],  # Reduced
            "sample_methods": dex_analysis.get("methods", [])[:20],  # Reduced
            "note": "Limited extraction for performance",
        }
