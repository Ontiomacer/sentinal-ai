"""
Application Inventory Service
Enumerate and analyze installed applications on connected device
"""

import logging
import re
import traceback
from typing import List, Dict, Optional
from .adb_controller import get_adb_controller

logger = logging.getLogger(__name__)


def _log_exception(context: str, exc: BaseException) -> None:
    logger.error(traceback.format_exc())
    logger.error(f"{context} exception type: {type(exc).__name__}")
    logger.error(f"{context} exception message: {str(exc)}")


class AppInventoryService:
    """Manages application inventory on connected devices"""
    
    def __init__(self):
        self.adb = get_adb_controller()
        # Simple in-memory cache: device_serial -> {packages: [], timestamp: float}
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes
        self.last_pull_error: Optional[str] = None
    
    def _get_cache_key(self, serial: str, include_system: bool) -> str:
        """Generate cache key"""
        return f"{serial}:{'all' if include_system else 'user'}"
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache is still valid"""
        import time
        if cache_key not in self._cache:
            return False
        
        cache_entry = self._cache[cache_key]
        age = time.time() - cache_entry['timestamp']
        return age < self._cache_ttl
    
    def _set_cache(self, cache_key: str, data: List[Dict]):
        """Store data in cache"""
        import time
        self._cache[cache_key] = {
            'data': data,
            'timestamp': time.time()
        }
    
    def _get_cache(self, cache_key: str) -> Optional[List[Dict]]:
        """Retrieve data from cache"""
        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]['data']
        return None
    
    def clear_cache(self, serial: str = None):
        """Clear cache for device or all devices"""
        if serial:
            # Clear specific device cache
            keys_to_remove = [k for k in self._cache.keys() if k.startswith(serial)]
            for key in keys_to_remove:
                del self._cache[key]
        else:
            # Clear all cache
            self._cache.clear()

    def _set_pull_error(self, message: str) -> bool:
        self.last_pull_error = message
        logger.error(f"[AppInventory] Pull error source: {message}")
        return False
    
    async def get_installed_apps(self, serial: str, include_system: bool = False) -> List[Dict]:
        """
        Get all installed applications - STAGE 1 ONLY (Fast)
        
        Returns minimal app info for quick UI rendering:
        - package name
        - label
        - system flag
        
        Stage 2 metadata loaded separately on demand
        Uses cache to avoid repeated enumeration
        
        Args:
            serial: Device serial
            include_system: Include system apps
            
        Returns:
            List of minimal app dictionaries
        """
        logger.info(f"[AppInventory] Stage 1: Getting installed apps for {serial}")
        
        # Check cache first
        cache_key = self._get_cache_key(serial, include_system)
        cached_data = self._get_cache(cache_key)
        if cached_data:
            logger.info(f"[AppInventory] Cache hit for {cache_key}")
            return cached_data
        
        try:
            import time
            start_time = time.time()
            
            # Get package list only - fast operation
            flag = "-3" if not include_system else ""
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", f"pm list packages {flag}"]
            )
            
            if returncode != 0:
                logger.error(f"[AppInventory] Failed to list packages: {stderr}")
                return []
            
            packages = [line.replace("package:", "").strip() 
                       for line in stdout.split('\n') if line.startswith('package:')]
            
            enum_time = time.time() - start_time
            logger.info(f"[AppInventory] Stage 1: Found {len(packages)} packages in {enum_time:.2f}s")
            
            # Stage 1 must stay fast: list packages only. Pulling labels or
            # metadata here creates one ADB call per app and makes Device Lab
            # take 10+ seconds on mid-range hardware.
            apps = []
            for package in packages:
                apps.append({
                    "package": package,
                    "label": package,
                    "is_system": False,  # Will be determined in stage 2
                    "stage1_only": True
                })
            
            # Store in cache
            self._set_cache(cache_key, apps)
            
            total_time = time.time() - start_time
            logger.info(f"[AppInventory] Stage 1: Completed in {total_time:.2f}s (cached)")
            
            return apps
            
        except Exception as e:
            _log_exception("[AppInventory] Installed apps", e)
            logger.error(f"[AppInventory] Error getting installed apps: {e}", exc_info=True)
            return []
    
    async def _get_app_label_fast(self, serial: str, package: str) -> str:
        """Fast label extraction without full dumpsys"""
        try:
            # Try to get label from package manager (faster than dumpsys)
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "pm", "list", "packages", "-f", package]
            )
            
            # Extract label from path if available
            for line in stdout.split('\n'):
                if package in line:
                    # Use package name as fallback
                    return package.split('.')[-1].capitalize()
            
            return package.split('.')[-1].capitalize()
        except Exception as e:
            _log_exception("[AppInventory] Label lookup", e)
            return package.split('.')[-1].capitalize()
    
    async def get_app_details(self, serial: str, package: str) -> Optional[Dict]:
        """
        Get detailed information for a specific app
        
        Args:
            serial: Device serial
            package: Package name
            
        Returns:
            App details dictionary
        """
        try:
            # Get package info
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "package", package]
            )
            
            if returncode != 0:
                return None
            
            # Parse dumpsys output
            app_info = {
                "package": package,
                "version_name": self._extract_field(stdout, r"versionName=([^\s]+)"),
                "version_code": self._extract_field(stdout, r"versionCode=(\d+)"),
                "installer": self._extract_field(stdout, r"installerPackageName=([^\s]+)"),
                "first_install": self._extract_field(stdout, r"firstInstallTime=([^\n]+)"),
                "last_update": self._extract_field(stdout, r"lastUpdateTime=([^\n]+)"),
                "target_sdk": self._extract_field(stdout, r"targetSdk=(\d+)"),
                "permissions": self._extract_permissions(stdout),
                "flags": self._extract_flags(stdout),
                "is_system": "SYSTEM" in stdout or "privileged" in stdout.lower(),
                "enabled": "enabled=true" in stdout.lower()
            }
            
            # Get app label/name
            returncode, label_stdout, _ = await self.adb.execute_command_async(
                ["-s", serial, "shell", "pm", "dump", package, "|", "grep", "ApplicationInfo"]
            )
            app_info["label"] = self._extract_field(label_stdout, r"name=([^\s]+)") or package
            
            return app_info
            
        except Exception as e:
            _log_exception(f"[AppInventory] Details for {package}", e)
            logger.error(f"[AppInventory] Error getting details for {package}: {e}")
            return None
    
    async def get_dangerous_permissions(self, serial: str, package: str) -> List[Dict]:
        """
        Get dangerous permissions for an app
        
        Args:
            serial: Device serial
            package: Package name
            
        Returns:
            List of dangerous permissions with status
        """
        dangerous_perms = [
            "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
            "READ_CALENDAR", "WRITE_CALENDAR",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS", "ANSWER_PHONE_CALLS",
            "READ_SMS", "RECEIVE_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS", "SEND_SMS",
            "CAMERA",
            "RECORD_AUDIO",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
            "ACCESS_MEDIA_LOCATION",
            "ACTIVITY_RECOGNITION",
            "BODY_SENSORS",
            "READ_PHONE_NUMBERS"
        ]
        
        try:
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "package", package]
            )
            
            if returncode != 0:
                return []
            
            result = []
            for perm in dangerous_perms:
                full_perm = f"android.permission.{perm}"
                if full_perm in stdout:
                    granted = f"{full_perm}: granted=true" in stdout
                    result.append({
                        "permission": perm,
                        "granted": granted,
                        "dangerous": True
                    })
            
            return result
            
        except Exception as e:
            _log_exception("[AppInventory] Dangerous permissions", e)
            logger.error(f"[AppInventory] Error getting dangerous permissions: {e}")
            return []
    
    async def pull_apk(self, serial: str, package: str, output_path: str) -> bool:
        """
        Pull APK from device (handles both single and split APKs)
        
        For split APKs, only pulls base.apk as it contains the main manifest and code.
        
        Args:
            serial: Device serial
            package: Package name
            output_path: Local path to save APK
            
        Returns:
            Success status
        """
        logger.info(f"[AppInventory] ========== EXTRACTION START ==========")
        logger.info(f"[AppInventory] Package: {package}")
        logger.info(f"[AppInventory] Serial: {serial}")
        logger.info(f"[AppInventory] Output: {output_path}")
        self.last_pull_error = None
        
        try:
            # Get APK path(s) on device
            logger.info(f"[AppInventory] Step 1: Running 'adb -s {serial} shell pm path {package}'")
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "pm", "path", package]
            )
            
            logger.info(f"[AppInventory] pm path returncode: {returncode}")
            logger.info(f"[AppInventory] pm path stdout: {repr(stdout)}")
            logger.info(f"[AppInventory] pm path stderr: {repr(stderr)}")
            
            if returncode != 0 or not stdout:
                logger.error(f"[AppInventory] ❌ Failed to get APK path")
                logger.error(f"[AppInventory] Return code: {returncode}")
                logger.error(f"[AppInventory] Stderr: {stderr}")
                return self._set_pull_error(f"pm path failed: returncode={returncode}, stderr={stderr or 'empty'}, stdout={stdout or 'empty'}")
            
            # Parse APK paths (may be multiple for split APKs)
            apk_paths = [
                line.replace("package:", "").strip() 
                for line in stdout.split('\n') 
                if line.startswith('package:')
            ]
            
            logger.info(f"[AppInventory] Step 2: Parsed APK paths")
            logger.info(f"[AppInventory] Total APK files found: {len(apk_paths)}")
            for i, path in enumerate(apk_paths):
                logger.info(f"[AppInventory]   [{i+1}] {path}")
            
            if not apk_paths:
                logger.error(f"[AppInventory] ❌ No APK paths found in output")
                logger.error(f"[AppInventory] Raw stdout: {repr(stdout)}")
                return self._set_pull_error(f"pm path returned no package paths: stdout={stdout!r}")
            
            # For split APKs, prefer base.apk; otherwise use first APK
            base_apk = None
            for path in apk_paths:
                if 'base.apk' in path:
                    base_apk = path
                    logger.info(f"[AppInventory] ✓ Found base.apk: {base_apk}")
                    break
            
            apk_path = base_apk if base_apk else apk_paths[0]
            
            logger.info(f"[AppInventory] Step 3: Selected APK for extraction")
            logger.info(f"[AppInventory] Selected path: {apk_path}")
            if len(apk_paths) > 1:
                logger.info(f"[AppInventory] Split APK detected ({len(apk_paths)} files)")
                logger.info(f"[AppInventory] Using: {'base.apk' if base_apk else 'first APK'}")
            
            # Pull APK
            logger.info(f"[AppInventory] Step 4: Pulling APK from device")
            logger.info(f"[AppInventory] Running: adb -s {serial} pull {apk_path} {output_path}")
            returncode, pull_stdout, pull_stderr = await self.adb.execute_command_async(
                ["-s", serial, "pull", apk_path, output_path]
            )
            
            logger.info(f"[AppInventory] pull returncode: {returncode}")
            logger.info(f"[AppInventory] pull stdout: {repr(pull_stdout)}")
            logger.info(f"[AppInventory] pull stderr: {repr(pull_stderr)}")
            
            if returncode == 0:
                # Verify file exists and has content
                import os
                from pathlib import Path
                # Normalize path for Windows compatibility (handles both / and \)
                normalized_path = os.path.normpath(output_path)
                output_file = Path(normalized_path)
                if not output_file.exists():
                    logger.error(f"[AppInventory] ❌ File not found after pull: {normalized_path}")
                    logger.error(f"[AppInventory] Original path: {output_path}")
                    return self._set_pull_error(f"adb pull succeeded but output file is missing: {normalized_path}")
                
                file_size = output_file.stat().st_size
                logger.info(f"[AppInventory] Step 5: Verification")
                logger.info(f"[AppInventory] ✓ File exists: {normalized_path}")
                logger.info(f"[AppInventory] ✓ File size: {file_size} bytes ({file_size / (1024*1024):.2f} MB)")
                
                if file_size == 0:
                    logger.error(f"[AppInventory] ❌ File is empty (0 bytes)")
                    return self._set_pull_error(f"adb pull produced an empty file: {normalized_path}")
                
                logger.info(f"[AppInventory] ========== EXTRACTION SUCCESS ==========")
                return True
            else:
                logger.error(f"[AppInventory] ❌ ADB pull failed")
                logger.error(f"[AppInventory] Return code: {returncode}")
                logger.error(f"[AppInventory] Stderr: {pull_stderr}")
                logger.error(f"[AppInventory] ========== EXTRACTION FAILED ==========")
                return self._set_pull_error(f"adb pull failed: returncode={returncode}, stderr={pull_stderr or 'empty'}, stdout={pull_stdout or 'empty'}")
                
        except Exception as e:
            _log_exception("[AppInventory] Pull APK", e)
            logger.error(f"[AppInventory] ❌ Exception during extraction")
            logger.error(f"[AppInventory] Exception type: {type(e).__name__}")
            logger.error(f"[AppInventory] Exception message: {str(e)}")
            logger.error(f"[AppInventory] Full traceback:\n{traceback.format_exc()}")
            logger.error(f"[AppInventory] ========== EXTRACTION FAILED ==========")
            return self._set_pull_error(f"{type(e).__name__}: {str(e)}")
    
    def _extract_field(self, text: str, pattern: str) -> Optional[str]:
        """Extract field using regex pattern"""
        match = re.search(pattern, text)
        return match.group(1) if match else None
    
    def _extract_permissions(self, text: str) -> List[str]:
        """Extract requested permissions"""
        perms = []
        in_perm_section = False
        
        for line in text.split('\n'):
            if 'requested permissions:' in line.lower():
                in_perm_section = True
                continue
            elif in_perm_section:
                if line.strip().startswith('android.permission.'):
                    perm = line.strip().split(':')[0]
                    perms.append(perm.replace('android.permission.', ''))
                elif not line.strip() or 'install permissions:' in line.lower():
                    break
        
        return perms
    
    def _extract_flags(self, text: str) -> List[str]:
        """Extract app flags"""
        flags = []
        if "FLAG_SYSTEM" in text:
            flags.append("SYSTEM")
        if "FLAG_DEBUGGABLE" in text:
            flags.append("DEBUGGABLE")
        if "FLAG_HAS_CODE" in text:
            flags.append("HAS_CODE")
        if "FLAG_ALLOW_BACKUP" in text:
            flags.append("ALLOW_BACKUP")
        return flags


# Global service instance
_app_inventory_service: Optional[AppInventoryService] = None


def get_app_inventory_service() -> AppInventoryService:
    """Get or create app inventory service singleton"""
    global _app_inventory_service
    if _app_inventory_service is None:
        _app_inventory_service = AppInventoryService()
    return _app_inventory_service
