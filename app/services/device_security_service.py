"""
Device Security Assessment Service
Comprehensive security analysis of connected Android device
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime
from .app_inventory_service import get_app_inventory_service
from .advanced_runtime_service import get_advanced_runtime_service
from .adb_controller import get_adb_controller

logger = logging.getLogger(__name__)


class DeviceSecurityService:
    """Analyze device security posture"""
    
    def __init__(self):
        self.adb = get_adb_controller()
        self.app_inventory = get_app_inventory_service()
        self.runtime = get_advanced_runtime_service()
    
    async def assess_device_security(self, serial: str) -> Dict:
        """
        Perform comprehensive device security assessment
        
        Args:
            serial: Device serial
            
        Returns:
            Security assessment report
        """
        logger.info(f"[DeviceSecurity] Starting security assessment for {serial}")
        
        assessment = {
            "device_serial": serial,
            "timestamp": datetime.now().isoformat(),
            "risk_score": 0,
            "max_score": 100,
            "findings": [],
            "categories": {}
        }
        
        # 1. Check for sideloaded apps
        sideloaded = await self._detect_sideloaded_apps(serial)
        assessment["categories"]["sideloaded_apps"] = {
            "count": len(sideloaded),
            "apps": sideloaded,
            "risk_points": len(sideloaded) * 10
        }
        assessment["risk_score"] += min(len(sideloaded) * 10, 30)
        
        # 2. Check for dangerous permissions
        dangerous_apps = await self._detect_dangerous_permissions(serial)
        assessment["categories"]["dangerous_permissions"] = {
            "count": len(dangerous_apps),
            "apps": dangerous_apps,
            "risk_points": len(dangerous_apps) * 5
        }
        assessment["risk_score"] += min(len(dangerous_apps) * 5, 20)
        
        # 3. Check for accessibility abuse
        accessibility_services = await self.runtime.detect_accessibility_abuse(serial)
        third_party_acc = [s for s in accessibility_services if not s['package'].startswith('com.android') and not s['package'].startswith('com.google')]
        assessment["categories"]["accessibility_services"] = {
            "count": len(third_party_acc),
            "services": third_party_acc,
            "risk_points": len(third_party_acc) * 15
        }
        assessment["risk_score"] += min(len(third_party_acc) * 15, 30)
        
        # 4. Check for overlay abuse
        overlays = await self.runtime.detect_overlay_abuse(serial)
        assessment["categories"]["overlay_windows"] = {
            "count": len(overlays),
            "apps": overlays,
            "risk_points": len(overlays) * 10
        }
        assessment["risk_score"] += min(len(overlays) * 10, 20)
        
        # 5. Check device encryption
        encryption_status = await self._check_encryption(serial)
        assessment["categories"]["encryption"] = encryption_status
        if not encryption_status.get("encrypted", False):
            assessment["risk_score"] += 10
        
        # 6. Check for debuggable apps
        debuggable = await self._detect_debuggable_apps(serial)
        assessment["categories"]["debuggable_apps"] = {
            "count": len(debuggable),
            "apps": debuggable,
            "risk_points": len(debuggable) * 5
        }
        assessment["risk_score"] += min(len(debuggable) * 5, 10)
        
        # Calculate trust score (inverse of risk)
        assessment["trust_score"] = max(0, 100 - assessment["risk_score"])
        
        # Determine risk level
        if assessment["risk_score"] < 20:
            assessment["risk_level"] = "LOW"
        elif assessment["risk_score"] < 50:
            assessment["risk_level"] = "MEDIUM"
        elif assessment["risk_score"] < 75:
            assessment["risk_level"] = "HIGH"
        else:
            assessment["risk_level"] = "CRITICAL"
        
        # Generate findings summary
        assessment["findings"] = self._generate_findings(assessment)
        
        logger.info(f"[DeviceSecurity] Assessment complete. Risk Score: {assessment['risk_score']}/100")
        return assessment
    
    async def _detect_sideloaded_apps(self, serial: str) -> List[Dict]:
        """Detect apps installed from unknown sources"""
        logger.info(f"[DeviceSecurity] Detecting sideloaded apps")
        
        apps = await self.app_inventory.get_installed_apps(serial, include_system=False)
        
        sideloaded = []
        known_stores = ['com.android.vending', 'com.google.android.packageinstaller', 
                       'com.amazon.venezia', 'com.sec.android.app.samsungapps']
        
        for app in apps:
            installer = app.get('installer', '')
            if installer and installer not in known_stores and installer != 'null':
                sideloaded.append({
                    "package": app['package'],
                    "installer": installer,
                    "version": app.get('version_name', 'Unknown')
                })
            elif not installer or installer == 'null':
                # No installer = likely sideloaded
                sideloaded.append({
                    "package": app['package'],
                    "installer": "Unknown (Sideloaded)",
                    "version": app.get('version_name', 'Unknown')
                })
        
        return sideloaded
    
    async def _detect_dangerous_permissions(self, serial: str) -> List[Dict]:
        """Detect apps with dangerous permissions"""
        logger.info(f"[DeviceSecurity] Detecting dangerous permissions")
        
        apps = await self.app_inventory.get_installed_apps(serial, include_system=False)
        
        dangerous_apps = []
        high_risk_perms = ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CONTACTS', 
                          'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE',
                          'REQUEST_INSTALL_PACKAGES']
        
        for app in apps:
            perms = app.get('permissions', [])
            risky_perms = [p for p in perms if any(risk in p for risk in high_risk_perms)]
            
            if risky_perms:
                dangerous_apps.append({
                    "package": app['package'],
                    "permissions": risky_perms,
                    "count": len(risky_perms)
                })
        
        return dangerous_apps
    
    async def _check_encryption(self, serial: str) -> Dict:
        """Check device encryption status"""
        try:
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "getprop", "ro.crypto.state"]
            )
            
            encrypted = "encrypted" in stdout.lower()
            
            return {
                "encrypted": encrypted,
                "status": stdout.strip() if stdout else "Unknown"
            }
        except Exception as e:
            logger.error(f"[DeviceSecurity] Error checking encryption: {e}")
            return {"encrypted": False, "status": "Unknown"}
    
    async def _detect_debuggable_apps(self, serial: str) -> List[str]:
        """Detect debuggable apps (security risk)"""
        apps = await self.app_inventory.get_installed_apps(serial, include_system=False)
        
        debuggable = []
        for app in apps:
            flags = app.get('flags', [])
            if 'DEBUGGABLE' in flags:
                debuggable.append(app['package'])
        
        return debuggable
    
    def _generate_findings(self, assessment: Dict) -> List[Dict]:
        """Generate human-readable findings"""
        findings = []
        
        # Sideloaded apps
        sideloaded_count = assessment["categories"]["sideloaded_apps"]["count"]
        if sideloaded_count > 0:
            findings.append({
                "severity": "HIGH" if sideloaded_count > 3 else "MEDIUM",
                "category": "Sideloaded Apps",
                "description": f"Found {sideloaded_count} app(s) installed from unknown sources",
                "recommendation": "Review and remove untrusted applications"
            })
        
        # Accessibility abuse
        acc_count = assessment["categories"]["accessibility_services"]["count"]
        if acc_count > 0:
            findings.append({
                "severity": "HIGH",
                "category": "Accessibility Abuse",
                "description": f"Found {acc_count} third-party accessibility service(s) enabled",
                "recommendation": "Accessibility services can be used by banking malware. Review and disable suspicious services"
            })
        
        # Overlays
        overlay_count = assessment["categories"]["overlay_windows"]["count"]
        if overlay_count > 0:
            findings.append({
                "severity": "HIGH",
                "category": "Overlay Windows",
                "description": f"Found {overlay_count} app(s) with overlay permission",
                "recommendation": "Overlay windows can be used for phishing attacks. Review permissions"
            })
        
        # Encryption
        if not assessment["categories"]["encryption"]["encrypted"]:
            findings.append({
                "severity": "MEDIUM",
                "category": "Device Encryption",
                "description": "Device storage is not encrypted",
                "recommendation": "Enable device encryption in Settings > Security"
            })
        
        # Dangerous permissions
        dangerous_count = assessment["categories"]["dangerous_permissions"]["count"]
        if dangerous_count > 5:
            findings.append({
                "severity": "MEDIUM",
                "category": "Dangerous Permissions",
                "description": f"Found {dangerous_count} apps with high-risk permissions",
                "recommendation": "Review app permissions and revoke unnecessary access"
            })
        
        return findings


# Global service instance
_device_security_service: Optional[DeviceSecurityService] = None


def get_device_security_service() -> DeviceSecurityService:
    """Get or create device security service singleton"""
    global _device_security_service
    if _device_security_service is None:
        _device_security_service = DeviceSecurityService()
    return _device_security_service
