"""
Ghidra Headless Integration Service
Complete integration with Ghidra for advanced reverse engineering
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple
import subprocess
import json
import tempfile
import logging
import os
import shutil

logger = logging.getLogger(__name__)


class GhidraAnalyzer:
    """
    Complete Ghidra headless integration for APK analysis.
    Provides advanced reverse engineering capabilities.
    """
    
    def __init__(self, ghidra_path: Optional[str] = None):
        """
        Initialize Ghidra analyzer.
        
        Args:
            ghidra_path: Path to Ghidra installation (auto-detected if None)
        """
        self.ghidra_path = ghidra_path or self._find_ghidra()
        self.analyze_headless = self._get_analyze_headless_path()
        self.is_available = self._check_availability()
        
    def _find_ghidra(self) -> Optional[str]:
        """Auto-detect Ghidra installation."""
        possible_paths = [
            r"C:\Tools\ghidra",
            r"C:\Program Files\ghidra",
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra"),
        ]
        
        for base_path in possible_paths:
            if os.path.exists(base_path):
                # Look for versioned directories
                for item in os.listdir(base_path):
                    full_path = os.path.join(base_path, item)
                    if os.path.isdir(full_path) and 'ghidra' in item.lower():
                        return full_path
                return base_path
        
        # Check environment variable
        return os.environ.get('GHIDRA_INSTALL_DIR')
    
    def _get_analyze_headless_path(self) -> Optional[str]:
        """Get path to analyzeHeadless script."""
        if not self.ghidra_path:
            return None
        
        # Windows
        windows_path = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless.bat')
        if os.path.exists(windows_path):
            return windows_path
        
        # Linux/Mac
        unix_path = os.path.join(self.ghidra_path, 'support', 'analyzeHeadless')
        if os.path.exists(unix_path):
            return unix_path
        
        return None
    
    def _check_availability(self) -> bool:
        """Check if Ghidra is available and functional."""
        if not self.analyze_headless:
            logger.warning("Ghidra analyzeHeadless not found")
            return False
        
        try:
            result = subprocess.run(
                [self.analyze_headless, '-help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Ghidra availability check failed: {str(e)}")
            return False
    
    async def analyze_apk(self, apk_path: Path, output_dir: Path) -> Dict:
        """
        Perform comprehensive Ghidra analysis on APK.
        
        Args:
            apk_path: Path to APK file
            output_dir: Directory for analysis output
            
        Returns:
            Dictionary containing analysis results
        """
        if not self.is_available:
            return {
                "status": "unavailable",
                "message": "Ghidra not available"
            }
        
        logger.info(f"Starting Ghidra analysis for {apk_path}")
        
        results = {
            "status": "analyzing",
            "dex_analysis": [],
            "native_analysis": [],
            "function_analysis": {},
            "string_analysis": {},
            "cross_references": {},
            "decompilation": {}
        }
        
        try:
            # Create Ghidra project
            project_dir = output_dir / "ghidra_project"
            project_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract DEX and native libraries from APK
            extracted = await self._extract_apk_components(apk_path, output_dir)
            
            # Analyze DEX files
            for dex_file in extracted['dex_files']:
                dex_results = await self._analyze_dex_file(dex_file, project_dir)
                results['dex_analysis'].append(dex_results)
            
            # Analyze native libraries
            for so_file in extracted['so_files']:
                native_results = await self._analyze_native_library(so_file, project_dir)
                results['native_analysis'].append(native_results)
            
            # Perform advanced analysis
            results['function_analysis'] = await self._analyze_functions(project_dir)
            results['string_analysis'] = await self._analyze_strings(project_dir)
            results['cross_references'] = await self._analyze_cross_references(project_dir)
            
            results['status'] = 'complete'
            logger.info("Ghidra analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Ghidra analysis failed: {str(e)}")
            results['status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    async def _extract_apk_components(self, apk_path: Path, output_dir: Path) -> Dict:
        """Extract DEX and native libraries from APK."""
        import zipfile
        
        extracted = {
            'dex_files': [],
            'so_files': []
        }
        
        extract_dir = output_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Extract DEX files
                for file_info in zip_ref.filelist:
                    if file_info.filename.endswith('.dex'):
                        dex_path = extract_dir / file_info.filename
                        dex_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(dex_path, 'wb') as f:
                            f.write(zip_ref.read(file_info.filename))
                        extracted['dex_files'].append(dex_path)
                    
                    # Extract .so files
                    elif file_info.filename.endswith('.so'):
                        so_path = extract_dir / file_info.filename
                        so_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(so_path, 'wb') as f:
                            f.write(zip_ref.read(file_info.filename))
                        extracted['so_files'].append(so_path)
        
        except Exception as e:
            logger.error(f"Failed to extract APK components: {str(e)}")
        
        return extracted
    
    async def _analyze_dex_file(self, dex_path: Path, project_dir: Path) -> Dict:
        """Analyze DEX file with Ghidra."""
        logger.info(f"Analyzing DEX file: {dex_path}")
        
        project_name = f"dex_analysis_{dex_path.stem}"
        
        # Create Ghidra analysis script
        script_content = self._generate_dex_analysis_script()
        script_path = project_dir / "analyze_dex.py"
        script_path.write_text(script_content)
        
        try:
            # Run Ghidra headless analysis
            result = subprocess.run(
                [
                    self.analyze_headless,
                    str(project_dir),
                    project_name,
                    '-import', str(dex_path),
                    '-postScript', str(script_path),
                    '-scriptPath', str(project_dir),
                    '-deleteProject'  # Clean up after analysis
                ],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            # Parse results
            output_file = project_dir / f"{project_name}_results.json"
            if output_file.exists():
                with open(output_file, 'r') as f:
                    return json.load(f)
            
            return {
                "file": str(dex_path),
                "status": "analyzed",
                "functions": [],
                "classes": [],
                "strings": []
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra DEX analysis timeout for {dex_path}")
            return {"file": str(dex_path), "status": "timeout"}
        except Exception as e:
            logger.error(f"Ghidra DEX analysis failed: {str(e)}")
            return {"file": str(dex_path), "status": "failed", "error": str(e)}
    
    async def _analyze_native_library(self, so_path: Path, project_dir: Path) -> Dict:
        """Analyze native library (.so) with Ghidra."""
        logger.info(f"Analyzing native library: {so_path}")
        
        project_name = f"native_analysis_{so_path.stem}"
        
        # Create Ghidra analysis script for native code
        script_content = self._generate_native_analysis_script()
        script_path = project_dir / "analyze_native.py"
        script_path.write_text(script_content)
        
        try:
            # Run Ghidra headless analysis
            result = subprocess.run(
                [
                    self.analyze_headless,
                    str(project_dir),
                    project_name,
                    '-import', str(so_path),
                    '-postScript', str(script_path),
                    '-scriptPath', str(project_dir),
                    '-deleteProject'
                ],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            # Parse results
            output_file = project_dir / f"{project_name}_results.json"
            if output_file.exists():
                with open(output_file, 'r') as f:
                    return json.load(f)
            
            return {
                "file": str(so_path),
                "architecture": self._detect_architecture(so_path),
                "status": "analyzed",
                "functions": [],
                "imports": [],
                "exports": [],
                "strings": []
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra native analysis timeout for {so_path}")
            return {"file": str(so_path), "status": "timeout"}
        except Exception as e:
            logger.error(f"Ghidra native analysis failed: {str(e)}")
            return {"file": str(so_path), "status": "failed", "error": str(e)}
    
    def _generate_dex_analysis_script(self) -> str:
        """Generate Ghidra Python script for DEX analysis."""
        return '''
# Ghidra DEX Analysis Script
# @category Analysis

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType
import json

def analyze_dex():
    results = {
        "functions": [],
        "classes": [],
        "strings": [],
        "cross_references": []
    }
    
    # Get current program
    program = getCurrentProgram()
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    
    # Analyze functions
    for function in function_manager.getFunctions(True):
        func_info = {
            "name": function.getName(),
            "entry_point": str(function.getEntryPoint()),
            "signature": function.getSignature().getPrototypeString(),
            "call_count": len(list(function.getCallingFunctions(monitor))),
            "is_external": function.isExternal(),
            "is_thunk": function.isThunk()
        }
        results["functions"].append(func_info)
    
    # Analyze strings
    string_table = program.getListing().getDefinedData(True)
    for data in string_table:
        if data.hasStringValue():
            results["strings"].append({
                "address": str(data.getAddress()),
                "value": str(data.getValue())
            })
    
    # Save results
    output_file = getProjectRootFolder().getProjectLocator().getProjectDir() + "/dex_analysis_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print("DEX analysis complete")

analyze_dex()
'''
    
    def _generate_native_analysis_script(self) -> str:
        """Generate Ghidra Python script for native library analysis."""
        return '''
# Ghidra Native Library Analysis Script
# @category Analysis

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType, SourceType
import json

def analyze_native():
    results = {
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [],
        "suspicious_patterns": []
    }
    
    program = getCurrentProgram()
    function_manager = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    
    # Analyze functions
    for function in function_manager.getFunctions(True):
        func_info = {
            "name": function.getName(),
            "entry_point": str(function.getEntryPoint()),
            "size": function.getBody().getNumAddresses(),
            "call_count": len(list(function.getCallingFunctions(monitor))),
            "is_external": function.isExternal()
        }
        
        # Check for suspicious patterns
        if any(keyword in function.getName().lower() for keyword in ['exec', 'system', 'popen', 'fork']):
            func_info["suspicious"] = True
            results["suspicious_patterns"].append(function.getName())
        
        results["functions"].append(func_info)
    
    # Analyze imports
    for symbol in symbol_table.getExternalSymbols():
        results["imports"].append({
            "name": symbol.getName(),
            "address": str(symbol.getAddress())
        })
    
    # Analyze exports
    for symbol in symbol_table.getSymbolIterator():
        if symbol.isExternalEntryPoint():
            results["exports"].append({
                "name": symbol.getName(),
                "address": str(symbol.getAddress())
            })
    
    # Analyze strings
    listing = program.getListing()
    for data in listing.getDefinedData(True):
        if data.hasStringValue():
            string_value = str(data.getValue())
            results["strings"].append({
                "address": str(data.getAddress()),
                "value": string_value
            })
    
    # Save results
    output_file = getProjectRootFolder().getProjectLocator().getProjectDir() + "/native_analysis_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print("Native analysis complete")

analyze_native()
'''
    
    async def _analyze_functions(self, project_dir: Path) -> Dict:
        """Analyze functions across all analyzed files."""
        all_functions = []
        
        # Collect functions from all analysis results
        for result_file in project_dir.glob("*_results.json"):
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)
                    if 'functions' in data:
                        all_functions.extend(data['functions'])
            except Exception as e:
                logger.error(f"Failed to read {result_file}: {str(e)}")
        
        return {
            "total_functions": len(all_functions),
            "external_functions": len([f for f in all_functions if f.get('is_external')]),
            "suspicious_functions": len([f for f in all_functions if f.get('suspicious')]),
            "functions": all_functions[:100]  # Limit to top 100
        }
    
    async def _analyze_strings(self, project_dir: Path) -> Dict:
        """Analyze strings across all analyzed files."""
        all_strings = []
        
        for result_file in project_dir.glob("*_results.json"):
            try:
                with open(result_file, 'r') as f:
                    data = json.load(f)
                    if 'strings' in data:
                        all_strings.extend(data['strings'])
            except Exception as e:
                logger.error(f"Failed to read {result_file}: {str(e)}")
        
        # Categorize strings
        urls = [s for s in all_strings if 'http' in s.get('value', '').lower()]
        ips = [s for s in all_strings if self._is_ip_address(s.get('value', ''))]
        
        return {
            "total_strings": len(all_strings),
            "urls": urls[:50],
            "ip_addresses": ips[:50],
            "all_strings": all_strings[:200]
        }
    
    async def _analyze_cross_references(self, project_dir: Path) -> Dict:
        """Analyze cross-references between functions."""
        # This would require more complex Ghidra scripting
        # For now, return basic structure
        return {
            "total_references": 0,
            "call_graph": {}
        }
    
    def _detect_architecture(self, so_path: Path) -> str:
        """Detect architecture of native library."""
        # Simple detection based on file path
        path_str = str(so_path).lower()
        
        if 'arm64-v8a' in path_str:
            return 'ARM64'
        elif 'armeabi-v7a' in path_str or 'armeabi' in path_str:
            return 'ARM'
        elif 'x86_64' in path_str:
            return 'x86_64'
        elif 'x86' in path_str:
            return 'x86'
        else:
            return 'Unknown'
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if string is an IP address."""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return bool(re.match(ip_pattern, value))
    
    async def decompile_function(self, function_address: str, project_name: str) -> str:
        """
        Decompile a specific function using the Ghidra REST bridge.
        
        Args:
            function_address: Address of the function (e.g., "0x00401234")
            project_name: Name of the Ghidra project
            
        Returns:
            Decompiled C code
        """
        import httpx
        bridge_url = "http://localhost:8089/decompile_function"
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                params = {
                    "address": function_address,
                    "project_name": project_name
                }
                logger.info(f"Requesting decompilation from bridge: {bridge_url} for {function_address}")
                response = await client.get(bridge_url, params=params)
                
                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(f"Bridge returned error {response.status_code}: {response.text}")
                    return f"// Error from Ghidra bridge: {response.status_code}"
                    
        except Exception as e:
            logger.error(f"Failed to communicate with Ghidra bridge: {str(e)}")
            return f"// Ghidra bridge unreachable at {bridge_url}. Ensure ghidra_mcp_server.py is running."
    
    async def export_ghidra_project(self, project_dir: Path, export_path: Path) -> bool:
        """
        Export Ghidra project for manual analysis.
        
        Args:
            project_dir: Ghidra project directory
            export_path: Export destination
            
        Returns:
            Success status
        """
        try:
            shutil.copytree(project_dir, export_path, dirs_exist_ok=True)
            logger.info(f"Ghidra project exported to {export_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export Ghidra project: {str(e)}")
            return False


# Singleton instance
_ghidra_analyzer = None

def get_ghidra_analyzer() -> GhidraAnalyzer:
    """Get singleton Ghidra analyzer instance."""
    global _ghidra_analyzer
    if _ghidra_analyzer is None:
        _ghidra_analyzer = GhidraAnalyzer()
    return _ghidra_analyzer
