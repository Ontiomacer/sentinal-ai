"""
Advanced Reverse Engineering Pipeline
Orchestrates multiple RE tools for comprehensive malware analysis
Integrates Androguard, JADX, apktool, YARA scanner, and IOC extraction.
"""

from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import subprocess
import json
import re
import logging
from dataclasses import dataclass, asdict
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

from app.services.yara_scanner import YaraScanner
from app.services.ai_cognition import AICognitionEngine

logger = logging.getLogger(__name__)


@dataclass
class SuspiciousFunction:
    """Represents a suspicious function detected during analysis."""
    name: str
    class_name: str
    signature: str
    threat_indicators: List[str]
    decompiled_code: Optional[str] = None
    call_count: int = 0
    called_by: List[str] = None
    calls_to: List[str] = None
    risk_score: int = 0
    
    def __post_init__(self):
        if self.called_by is None:
            self.called_by = []
        if self.calls_to is None:
            self.calls_to = []


@dataclass
class MalwareIndicator:
    """Represents a malware indicator found in the APK."""
    type: str  # url, ip_address, sensitive_string, reflection, native_lib, domain, email, wallet, etc.
    value: str
    context: str
    severity: str  # low, medium, high, critical
    description: str
    locations: List[str] = None
    
    def __post_init__(self):
        if self.locations is None:
            self.locations = []


@dataclass
class BehavioralPattern:
    """Represents a behavioral pattern indicating malicious intent."""
    pattern_name: str
    confidence: float
    evidence: List[str]
    attack_chain: List[str]
    fraud_indicators: List[str]
    ai_explanation: str


class ReverseEngineeringPipeline:
    """
    Orchestrates multiple reverse engineering tools for comprehensive analysis.
    Integrates JADX, apktool, Androguard, and prepares for Ghidra headless.
    """
    
    def __init__(self, apk_path: Path, output_dir: Path):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Analysis results
        self.suspicious_functions: List[SuspiciousFunction] = []
        self.malware_indicators: List[MalwareIndicator] = []
        self.behavioral_patterns: List[BehavioralPattern] = []
        self.decompiled_sources: Dict[str, str] = {}
        self.call_graph: Dict[str, List[str]] = {}
        self.ghidra_results: Dict = {}
        self.yara_matches: List[Any] = []
        self.manifest_details: Dict[str, Any] = {}
        self.extracted_strings: List[str] = []
        
        # Initialize Ghidra analyzer
        from app.services.ghidra_integration import get_ghidra_analyzer
        self.ghidra_analyzer = get_ghidra_analyzer()
        
    async def run_full_analysis(self) -> Dict:
        """Execute complete reverse engineering pipeline."""
        logger.info(f"Starting reverse engineering analysis for {self.apk_path}")
        
        results = {
            "status": "analyzing",
            "stages_completed": []
        }
        
        try:
            # Stage 1: JADX Decompilation
            await self._run_jadx_decompilation()
            results["stages_completed"].append("jadx_decompilation")
            
            # Stage 2: Apktool Disassembly
            await self._run_apktool_disassembly()
            results["stages_completed"].append("apktool_disassembly")
            
            # Stage 3: Androguard Deep Analysis
            await self._run_androguard_analysis()
            results["stages_completed"].append("androguard_analysis")
            
            # Stage 4: String and URL Extraction + IOC Parsing
            await self._extract_strings_and_urls()
            results["stages_completed"].append("string_extraction")
            
            # Stage 5: YARA Rule Scanning
            await self._run_yara_scan()
            results["stages_completed"].append("yara_scan")

            # Stage 6: API and Permission Correlation
            await self._correlate_apis_and_permissions()
            results["stages_completed"].append("api_correlation")
            
            # Stage 7: Obfuscation Detection
            await self._detect_obfuscation()
            results["stages_completed"].append("obfuscation_detection")
            
            # Stage 8: Reflection and Dynamic Loading Analysis
            await self._analyze_reflection_and_dynamic_loading()
            results["stages_completed"].append("reflection_analysis")
            
            # Stage 9: Native Library Analysis
            await self._analyze_native_libraries()
            results["stages_completed"].append("native_analysis")
            
            # Stage 10: Build Call Graph
            await self._build_call_graph()
            results["stages_completed"].append("call_graph")
            
            # Stage 11: Behavioral Threat Mapping
            await self._map_behavioral_threats()
            results["stages_completed"].append("threat_mapping")
            
            # Stage 12: Ghidra Advanced Analysis
            await self._run_ghidra_analysis()
            results["stages_completed"].append("ghidra_analysis")
            
            # Stage 13: AI Cognition Layer & Risk Score Heuristics
            await self._apply_ai_cognition()
            results["stages_completed"].append("ai_cognition")
            
            results["status"] = "complete"
            results["analysis"] = self._compile_results()
            
            return results
            
        except Exception as e:
            logger.error(f"Reverse engineering analysis failed: {str(e)}")
            results["status"] = "failed"
            results["error"] = str(e)
            return results
    
    async def _run_jadx_decompilation(self):
        """Run JADX to decompile APK to Java source."""
        logger.info("Running JADX decompilation...")
        
        jadx_output = self.output_dir / "jadx_output"
        jadx_output.mkdir(exist_ok=True)
        
        try:
            # Check if JADX is available
            result = subprocess.run(
                ["jadx", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Run JADX decompilation
                subprocess.run(
                    [
                        "jadx",
                        "-d", str(jadx_output),
                        "--no-res",  # Skip resources for faster processing
                        "--no-imports",  # Simplify output
                        str(self.apk_path)
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                # Index decompiled sources
                self._index_decompiled_sources(jadx_output)
                logger.info("JADX decompilation completed")
            else:
                logger.warning("JADX not available, skipping decompilation")
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"JADX execution failed: {str(e)}")
    
    async def _run_apktool_disassembly(self):
        """Run apktool to disassemble APK to smali."""
        logger.info("Running apktool disassembly...")
        
        apktool_output = self.output_dir / "apktool_output"
        
        try:
            # Check if apktool is available
            result = subprocess.run(
                ["apktool", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Run apktool disassembly
                subprocess.run(
                    [
                        "apktool",
                        "d",
                        str(self.apk_path),
                        "-o", str(apktool_output),
                        "-f"  # Force overwrite
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                # Extract and parse manifest
                manifest_path = apktool_output / "AndroidManifest.xml"
                if manifest_path.exists():
                    manifest_content = manifest_path.read_text(encoding='utf-8')
                    self.ghidra_results["manifest"] = manifest_content
                    self._parse_manifest_content(manifest_content)
                
                logger.info("Apktool disassembly completed")
            else:
                logger.warning("Apktool not available, skipping disassembly")
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Apktool execution failed: {str(e)}")
            
    def _parse_manifest_content(self, manifest_content: str):
        """Analyze AndroidManifest for exported components and custom intent filters."""
        # Simple regex extracts
        exported_components = []
        intent_filters = []
        
        # Check exported activities, services, receivers
        matches = re.finditer(r'<(activity|service|receiver)[^>]*android:exported="true"[^>]*name="([^"]+)"', manifest_content)
        for m in matches:
            exported_components.append({
                "type": m.group(1),
                "name": m.group(2)
            })
            
        # Detect intent filters (e.g. BOOT_COMPLETED, SMS_RECEIVED)
        filter_matches = re.findall(r'<action[^>]*android:name="([^"]+)"', manifest_content)
        for action in filter_matches:
            intent_filters.append(action)
            
        self.manifest_details = {
            "exported_components": exported_components,
            "intent_filters": list(set(intent_filters)),
            "raw_manifest_size": len(manifest_content)
        }
    
    async def _run_androguard_analysis(self):
        """Run deep Androguard analysis."""
        logger.info("Running Androguard deep analysis...")
        
        try:
            apk = APK(str(self.apk_path))
            
            # Get all DEX files
            dex_files = apk.get_all_dex()
            
            for idx, dex_data in enumerate(dex_files):
                dex = DEX(dex_data)
                analysis = Analysis()
                
                # Analyze DEX
                dex.set_decompiler("dad")  # Use DAD decompiler
                analysis.add(dex)
                
                # Extract classes and methods
                for cls in dex.get_classes():
                    class_name = cls.get_name()
                    
                    for method in cls.get_methods():
                        method_name = method.get_name()
                        
                        # Check for suspicious patterns
                        if self._is_suspicious_method(method_name, class_name):
                            self._analyze_suspicious_method(method, class_name, analysis)
                
                logger.info(f"Analyzed DEX file {idx + 1}/{len(dex_files)}")
                
        except Exception as e:
            logger.error(f"Androguard analysis failed: {str(e)}")
    
    async def _extract_strings_and_urls(self):
        """Extract strings, URLs, domains, and IOCs from APK."""
        logger.info("Extracting strings and URLs...")
        
        try:
            apk = APK(str(self.apk_path))
            
            # Extract strings from DEX files
            all_strings = set()
            for dex_data in apk.get_all_dex():
                dex = DEX(dex_data)
                all_strings.update(dex.get_strings())
                
            self.extracted_strings = sorted(list(all_strings))
            
            # Pattern matching for IOCs
            url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[a-zA-Z]{2,6}\b')
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
            btc_wallet_pattern = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
            
            for string in all_strings:
                # URL detection
                urls = url_pattern.findall(string)
                for url in urls:
                    self.malware_indicators.append(MalwareIndicator(
                        type="url",
                        value=url,
                        context=string[:100],
                        severity=self._assess_url_severity(url),
                        description="Embedded URL detected"
                    ))
                
                # IP address detection
                ips = ip_pattern.findall(string)
                for ip in ips:
                    self.malware_indicators.append(MalwareIndicator(
                        type="ip_address",
                        value=ip,
                        context=string[:100],
                        severity="medium",
                        description="Hardcoded IP address"
                    ))
                    
                # Domain detection (exclude typical Android/Google services)
                domains = domain_pattern.findall(string)
                for domain in domains:
                    d_lower = domain.lower()
                    if not any(x in d_lower for x in ['google', 'android', 'androidx', 'schema', 'w3.org']):
                        self.malware_indicators.append(MalwareIndicator(
                            type="domain",
                            value=domain,
                            context=string[:100],
                            severity="medium",
                            description="External domain candidate"
                        ))

                # Email detection
                emails = email_pattern.findall(string)
                for email in emails:
                    self.malware_indicators.append(MalwareIndicator(
                        type="email",
                        value=email,
                        context=string[:100],
                        severity="low",
                        description="Embedded developer/C2 email address"
                    ))

                # Bitcoin wallet
                wallets = btc_wallet_pattern.findall(string)
                for wallet in wallets:
                    self.malware_indicators.append(MalwareIndicator(
                        type="crypto_wallet",
                        value=wallet,
                        context=string[:100],
                        severity="high",
                        description="Bitcoin wallet address (potential ransom/payment indicator)"
                    ))
                
                # Suspicious string patterns
                if any(keyword in string.lower() for keyword in [
                    'password', 'credit', 'card', 'bank', 'account',
                    'token', 'secret', 'api_key', 'private_key', 'overlay_layout'
                ]):
                    self.malware_indicators.append(MalwareIndicator(
                        type="sensitive_string",
                        value=string[:100],
                        context="Sensitive data reference",
                        severity="high",
                        description="Potential sensitive data harvesting or overlay hook"
                    ))
            
            logger.info(f"Extracted {len(self.malware_indicators)} indicators")
            
        except Exception as e:
            logger.error(f"String extraction failed: {str(e)}")
            
    async def _run_yara_scan(self):
        """Run YARA rules scanning on extracted strings and manifest."""
        logger.info("Executing YARA scan stage...")
        try:
            from app.config import settings
            scanner = YaraScanner(rules_dir=Path(settings.STORAGE_DIR) / "yara_rules")
            
            manifest_content = self.ghidra_results.get("manifest", "")
            
            # Perform scan
            matches = scanner.scan_apk_artifacts(
                manifest=manifest_content,
                strings=self.extracted_strings
            )
            self.yara_matches = [asdict(m) for m in matches]
            logger.info("YARA scan completed with %d rule matches", len(self.yara_matches))
        except Exception as e:
            logger.error("YARA scan execution failed: %s", e)
            self.yara_matches = []
    
    async def _correlate_apis_and_permissions(self):
        """Correlate API calls with declared permissions."""
        logger.info("Correlating APIs and permissions...")
        try:
            apk = APK(str(self.apk_path))
            permissions = {perm.split(".")[-1].upper() for perm in apk.get_permissions()}
            corpus = "\n".join(self.extracted_strings[:5000]).lower()
            corpus += "\n" + "\n".join(self.decompiled_sources.values())[:500000].lower()

            correlation_rules = [
                {
                    "name": "SMS API with SMS permissions",
                    "permissions": {"READ_SMS", "RECEIVE_SMS", "SEND_SMS"},
                    "tokens": ["smsmanager", "telephonymanager", "sms_received", "pdus", "sendtextmessage"],
                    "severity": "high",
                    "description": "SMS permissions correlate with SMS handling APIs.",
                },
                {
                    "name": "Overlay API with overlay permission",
                    "permissions": {"SYSTEM_ALERT_WINDOW"},
                    "tokens": ["windowmanager", "addview", "type_application_overlay", "layoutparams"],
                    "severity": "high",
                    "description": "Overlay permission correlates with Android window overlay APIs.",
                },
                {
                    "name": "Accessibility API with accessibility service",
                    "permissions": {"BIND_ACCESSIBILITY_SERVICE"},
                    "tokens": ["accessibilityservice", "accessibilityevent", "performaction", "rootinactivewindow"],
                    "severity": "critical",
                    "description": "Accessibility service permission correlates with UI inspection or automation APIs.",
                },
                {
                    "name": "Location collection APIs with location permissions",
                    "permissions": {"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"},
                    "tokens": ["locationmanager", "fusedlocationproviderclient", "getlastlocation"],
                    "severity": "medium",
                    "description": "Location permissions correlate with location access APIs.",
                },
                {
                    "name": "Dynamic loading or reflection",
                    "permissions": set(),
                    "tokens": ["dexclassloader", "pathclassloader", "class.forname", "method.invoke", "getdeclaredmethod"],
                    "severity": "high",
                    "description": "Dynamic loading or reflection APIs were referenced.",
                },
                {
                    "name": "WebView script bridge",
                    "permissions": {"INTERNET"},
                    "tokens": ["addjavascriptinterface", "evaluatejavascript", "webview", "loadurl"],
                    "severity": "medium",
                    "description": "Network capability correlates with WebView JavaScript bridge or remote content APIs.",
                },
            ]

            seen = {
                (indicator.type, indicator.value)
                for indicator in self.malware_indicators
            }
            for rule in correlation_rules:
                matched_permissions = sorted(rule["permissions"] & permissions) if rule["permissions"] else []
                if rule["permissions"] and not matched_permissions:
                    continue
                matched_tokens = sorted(token for token in rule["tokens"] if token in corpus)
                if not matched_tokens:
                    continue

                key = ("api_permission_correlation", rule["name"])
                if key in seen:
                    continue
                seen.add(key)
                evidence = []
                if matched_permissions:
                    evidence.append(f"permissions={', '.join(matched_permissions)}")
                evidence.append(f"api_tokens={', '.join(matched_tokens[:8])}")
                self.malware_indicators.append(MalwareIndicator(
                    type="api_permission_correlation",
                    value=rule["name"],
                    context="; ".join(evidence),
                    severity=rule["severity"],
                    description=rule["description"],
                    locations=[],
                ))

            logger.info("API correlation complete: indicators=%s", len(self.malware_indicators))
        except Exception as exc:
            logger.error("API correlation failed: %s", exc)
    
    async def _detect_obfuscation(self):
        """Detect code obfuscation techniques."""
        logger.info("Detecting obfuscation...")
        
        try:
            apk = APK(str(self.apk_path))
            obfuscation_indicators = []
            
            for dex_data in apk.get_all_dex():
                dex = DEX(dex_data)
                
                obfuscated_classes = 0
                total_classes = 0
                
                for cls in dex.get_classes():
                    total_classes += 1
                    class_name = cls.get_name()
                    
                    if self._is_obfuscated_name(class_name):
                        obfuscated_classes += 1
                
                if total_classes > 0:
                    obfuscation_ratio = obfuscated_classes / total_classes
                    if obfuscation_ratio > 0.3:
                        obfuscation_indicators.append(
                            f"High obfuscation detected: {obfuscation_ratio:.1%} of classes"
                        )
            
            if obfuscation_indicators:
                self.malware_indicators.append(MalwareIndicator(
                    type="obfuscation",
                    value="; ".join(obfuscation_indicators),
                    context="Code structure analysis",
                    severity="medium",
                    description="Code obfuscation detected"
                ))
            
        except Exception as e:
            logger.error(f"Obfuscation detection failed: {str(e)}")
    
    async def _analyze_reflection_and_dynamic_loading(self):
        """Analyze reflection usage and dynamic DEX loading."""
        logger.info("Analyzing reflection and dynamic loading...")
        
        # Simple string-based heuristics
        reflection_keywords = ['Class.forName', 'getDeclaredMethod', 'DexClassLoader', 'PathClassLoader']
        count = sum(1 for s in self.extracted_strings if any(k in s for k in reflection_keywords))
        
        if count > 0:
            self.malware_indicators.append(MalwareIndicator(
                type="reflection",
                value=f"{count} reflection/dynamic loading hooks found",
                context="String metrics",
                severity="high",
                description="Reflection and dynamic dex classloading suggests runtime evasion"
            ))
    
    async def _analyze_native_libraries(self):
        """Analyze native libraries (.so files)."""
        logger.info("Analyzing native libraries...")
        
        try:
            apk = APK(str(self.apk_path))
            files = apk.get_files()
            
            so_files = [f for f in files if f.endswith('.so')]
            
            if so_files:
                self.malware_indicators.append(MalwareIndicator(
                    type="native_library",
                    value=f"{len(so_files)} native libraries found",
                    context=", ".join(so_files[:5]),
                    severity="medium",
                    description="Native code detected - requires deeper analysis",
                    locations=so_files
                ))
            
        except Exception as e:
            logger.error(f"Native library analysis failed: {str(e)}")
    
    async def _build_call_graph(self):
        """Build call relationship graph."""
        logger.info("Building call graph...")
        
        # Build relationships between suspicious functions
        for func in self.suspicious_functions:
            if func.name not in self.call_graph:
                self.call_graph[func.name] = []
            
            self.call_graph[func.name].extend(func.calls_to)
    
    async def _map_behavioral_threats(self):
        """Map behavioral patterns to threat categories."""
        logger.info("Mapping behavioral threats...")
        
        fraud_patterns = self._detect_fraud_patterns()
        for pattern in fraud_patterns:
            self.behavioral_patterns.append(pattern)
    
    async def _run_ghidra_analysis(self):
        """Run comprehensive Ghidra analysis."""
        logger.info("Running Ghidra advanced analysis...")
        
        if not self.ghidra_analyzer.is_available:
            logger.warning("Ghidra not available, skipping advanced analysis")
            self.ghidra_results = {
                "status": "unavailable",
                "message": "Ghidra not installed or not found"
            }
            return
        
        try:
            self.ghidra_results = await self.ghidra_analyzer.analyze_apk(
                self.apk_path,
                self.output_dir
            )
            
            if self.ghidra_results.get('status') == 'complete':
                self._integrate_ghidra_results()
            
            logger.info("Ghidra analysis completed")
            
        except Exception as e:
            logger.error(f"Ghidra analysis failed: {str(e)}")
            self.ghidra_results = {
                "status": "failed",
                "error": str(e)
            }
    
    def _integrate_ghidra_results(self):
        """Integrate Ghidra analysis results into main findings."""
        ghidra_functions = self.ghidra_results.get('function_analysis', {}).get('functions', [])
        
        for func in ghidra_functions:
            if func.get('suspicious'):
                self.suspicious_functions.append(SuspiciousFunction(
                    name=func['name'],
                    class_name='Native',
                    signature=f"Native.{func['name']}",
                    threat_indicators=['Native code', 'Ghidra analysis'],
                    risk_score=70
                ))
        
        ghidra_strings = self.ghidra_results.get('string_analysis', {})
        for url in ghidra_strings.get('urls', []):
            self.malware_indicators.append(MalwareIndicator(
                type="url",
                value=url.get('value', ''),
                context="Ghidra native analysis",
                severity="medium",
                description="URL found in native code"
            ))
        
        logger.info(f"Integrated {len(ghidra_functions)} Ghidra functions")
    
    async def _apply_ai_cognition(self):
        """Apply AI cognition layer for risk calculations."""
        logger.info("Applying AI cognition layer...")
        
        for func in self.suspicious_functions:
            func.risk_score = self._calculate_risk_score(func)
        
        self.suspicious_functions.sort(key=lambda x: x.risk_score, reverse=True)
    
    def _compile_results(self) -> Dict:
        """Compile all analysis results into structured format."""
        return {
            "suspicious_functions": [asdict(f) for f in self.suspicious_functions[:50]],
            "malware_indicators": [asdict(i) for i in self.malware_indicators],
            "behavioral_patterns": [asdict(p) for p in self.behavioral_patterns],
            "call_graph": self.call_graph,
            "ghidra_analysis": self.ghidra_results,
            "manifest_details": self.manifest_details,
            "yara_scan": {
                "total_matches": len(self.yara_matches),
                "matches": self.yara_matches
            },
            "statistics": {
                "total_suspicious_functions": len(self.suspicious_functions),
                "total_indicators": len(self.malware_indicators),
                "total_patterns": len(self.behavioral_patterns),
                "decompiled_classes": len(self.decompiled_sources),
                "ghidra_available": self.ghidra_analyzer.is_available,
                "ghidra_status": self.ghidra_results.get('status', 'not_run')
            }
        }
    
    # Helper methods
    
    def _index_decompiled_sources(self, jadx_output: Path):
        """Index decompiled Java sources."""
        sources_dir = jadx_output / "sources"
        if sources_dir.exists():
            for java_file in sources_dir.rglob("*.java"):
                relative_path = java_file.relative_to(sources_dir)
                try:
                    self.decompiled_sources[str(relative_path)] = java_file.read_text(encoding='utf-8')
                except Exception as e:
                    logger.warning(f"Failed to read {java_file}: {str(e)}")
    
    def _is_suspicious_method(self, method_name: str, class_name: str) -> bool:
        """Check if a method is potentially suspicious."""
        suspicious_keywords = [
            'decrypt', 'encrypt', 'obfuscate', 'hide', 'root',
            'su', 'exec', 'runtime', 'reflection', 'invoke',
            'load', 'download', 'upload', 'send', 'steal',
            'password', 'credit', 'bank', 'sms', 'call'
        ]
        
        method_lower = method_name.lower()
        return any(keyword in method_lower for keyword in suspicious_keywords)
    
    def _analyze_suspicious_method(self, method, class_name: str, analysis: Analysis):
        """Analyze a suspicious method in detail."""
        method_name = method.get_name()
        signature = f"{class_name}->{method_name}{method.get_descriptor()}"
        
        threat_indicators = []
        
        if 'native' in method.get_access_flags_string():
            threat_indicators.append("Native method")
            
        # Detect simple intent / reflection within smali/bytecode if dynamic
        if any(x in method_name.lower() for x in ['overlay', 'alert', 'window']):
            threat_indicators.append("Overlay view manipulator")
        if any(x in method_name.lower() for x in ['sms', 'receiver', 'mms']):
            threat_indicators.append("SMS receiver interceptor")
        if any(x in method_name.lower() for x in ['decrypt', 'cipher', 'crypt']):
            threat_indicators.append("Cryptographic operation")
        if any(x in method_name.lower() for x in ['exec', 'runtime']):
            threat_indicators.append("System command execution")
        
        # Get call relationships from Androguard Analysis object
        calls_to = []
        called_by = []
        
        try:
            # Find the method analysis object
            for meth_analysis in analysis.get_methods():
                if meth_analysis.get_method() == method:
                    # Get xrefs from (who calls this method)
                    for _, call, _ in meth_analysis.get_xref_from():
                        called_by.append(f"{call.class_name}->{call.name}")
                    
                    # Get xrefs to (who this method calls)
                    for _, call, _ in meth_analysis.get_xref_to():
                        calls_to.append(f"{call.class_name}->{call.name}")
                    break
        except Exception as e:
            logger.warning(f"Failed to extract xrefs for {method_name}: {e}")

        # Add to suspicious functions list
        func = SuspiciousFunction(
            name=method_name,
            class_name=class_name,
            signature=signature,
            threat_indicators=threat_indicators,
            decompiled_code=self._find_decompiled_context(class_name, method_name),
            calls_to=list(set(calls_to)),
            called_by=list(set(called_by)),
            call_count=len(called_by)
        )
        
        # Calculate a basic risk score for the function
        func.risk_score = self._calculate_risk_score(func)
        
        self.suspicious_functions.append(func)
    
    def _is_obfuscated_name(self, name: str) -> bool:
        """Check if a class/method name appears obfuscated."""
        simple_name = name.split('/')[-1].rstrip(';')
        
        if len(simple_name) == 1:
            return True
        
        if re.match(r'^[a-z]{1,3}$', simple_name):
            return True
        
        return False

    def _find_decompiled_context(self, class_name: str, method_name: str) -> Optional[str]:
        """Return a cached JADX source excerpt for the class/method when available."""
        if not self.decompiled_sources:
            return None

        simple_class = class_name.strip("L;").replace("/", ".").split(".")[-1]
        candidates = [
            (path, source)
            for path, source in self.decompiled_sources.items()
            if path.endswith(f"{simple_class}.java") or f"/{simple_class}.java" in path.replace("\\", "/")
        ]
        if not candidates:
            return None

        _, source = candidates[0]
        index = source.find(method_name)
        if index < 0:
            return source[:4000]

        start = max(0, source.rfind("\n", 0, max(0, index - 1200)))
        end = min(len(source), index + 3200)
        return source[start:end].strip()
    
    def _assess_url_severity(self, url: str) -> str:
        """Assess the severity of a detected URL."""
        url_lower = url.lower()
        
        if any(keyword in url_lower for keyword in ['admin', 'api', 'login', 'auth', 'token', 'c2']):
            return "high"
        
        if not any(safe in url_lower for safe in ['google.com', 'android.com', 'googleapis.com']):
            return "medium"
        
        return "low"
    
    def _detect_fraud_patterns(self) -> List[BehavioralPattern]:
        """Detect fraud-related behavioral patterns."""
        patterns = []
        
        # SMS fraud pattern
        sms_indicators = [i for i in self.malware_indicators if 'sms' in i.value.lower()]
        if len(sms_indicators) >= 2 or any('sms' in m['rule_name'].lower() for m in self.yara_matches):
            attack_chain = [
                "SMS permission/API evidence identified",
                "Incoming message access capability present",
            ]
            if any(ind.type in {"url", "domain", "ip_address"} for ind in self.malware_indicators):
                attack_chain.append("Remote artifact exists for follow-up review")
            patterns.append(BehavioralPattern(
                pattern_name="SMS Interception & OTP Fraud",
                confidence=0.85,
                evidence=[i.value for i in sms_indicators[:3]],
                attack_chain=attack_chain,
                fraud_indicators=["SMS permission/API evidence", "One-Time-Password interception capability"],
                ai_explanation="SMS-related evidence can support OTP interception. The pipeline does not claim forwarding or theft without matching code or network evidence."
            ))
        
        # Financial data theft pattern
        financial_indicators = [i for i in self.malware_indicators 
                               if any(k in i.value.lower() for k in ['bank', 'credit', 'card', 'payment'])]
        if financial_indicators or any('overlay' in m['rule_name'].lower() for m in self.yara_matches):
            patterns.append(BehavioralPattern(
                pattern_name="Overlay Banking Trojan Activity",
                confidence=0.90,
                evidence=[i.value for i in financial_indicators[:3]],
                attack_chain=["Financial/credential tokens identified", "Overlay or UI evidence requires code-level validation"],
                fraud_indicators=["Financial data references", "Overlay-capability evidence when present"],
                ai_explanation="The application contains financial or overlay-related evidence. Credential capture is treated as a hypothesis until validated against code paths."
            ))
        
        return patterns
    
    def _calculate_risk_score(self, func: SuspiciousFunction) -> int:
        """Calculate risk score for a suspicious function."""
        score = 0
        
        score += 10
        score += len(func.threat_indicators) * 15
        score += min(func.call_count * 5, 30)
        
        return min(score, 100)
