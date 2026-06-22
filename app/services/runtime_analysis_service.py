"""
Runtime Analysis Service
Collects runtime information from running apps
"""

import logging
import re
from typing import Optional, Dict, List
from .adb_controller import get_adb_controller

logger = logging.getLogger(__name__)


class RuntimeAnalysisService:
    """Collects runtime information from devices"""
    
    def __init__(self):
        self.adb = get_adb_controller()
    
    async def get_runtime_info(
        self, 
        serial: str, 
        package_name: Optional[str] = None
    ) -> Dict:
        """
        Get comprehensive runtime information
        
        Args:
            serial: Device serial
            package_name: Optional package name to filter
            
        Returns:
            Runtime information dictionary
        """
        runtime_info = {
            "activities": await self.get_activities(serial, package_name),
            "services": await self.get_services(serial, package_name),
            "receivers": await self.get_receivers(serial, package_name),
            "permissions": await self.get_permissions(serial, package_name) if package_name else []
        }
        
        return runtime_info
    
    async def get_activities(
        self, 
        serial: str, 
        package_name: Optional[str] = None
    ) -> List[Dict]:
        """
        Get running activities
        
        Args:
            serial: Device serial
            package_name: Optional package to filter
            
        Returns:
            List of activity dictionaries
        """
        returncode, stdout, stderr = await self.adb.execute_command_async(
            ["-s", serial, "shell", "dumpsys", "activity", "activities"],
            timeout=10
        )
        
        if returncode != 0:
            logger.error(f"Failed to get activities: {stderr}")
            return []
        
        activities = []
        current_activity = None
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Look for activity patterns
            # Example: "* TaskRecord{abc123 #456 A=com.example.app U=0 StackId=1 sz=1}"
            if 'TaskRecord' in line and 'A=' in line:
                match = re.search(r'A=([^\s]+)', line)
                if match:
                    activity_name = match.group(1)
                    if not package_name or activity_name.startswith(package_name):
                        current_activity = activity_name
            
            # Look for activity state
            if current_activity and 'state=' in line.lower():
                match = re.search(r'state=([^\s]+)', line, re.IGNORECASE)
                if match:
                    state = match.group(1).lower()
                    activities.append({
                        "name": current_activity,
                        "state": state if state in ["running", "paused", "stopped"] else "unknown",
                        "timestamp": ""  # Could extract from dumpsys if needed
                    })
                    current_activity = None
        
        # If we found activities but no explicit state, assume running
        if not activities and package_name:
            # Try simpler approach - check if package is in foreground
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "window", "windows"],
                timeout=5
            )
            if returncode == 0 and package_name in stdout:
                activities.append({
                    "name": f"{package_name}.MainActivity",
                    "state": "running",
                    "timestamp": ""
                })
        
        logger.info(f"Found {len(activities)} activities")
        return activities
    
    async def get_services(
        self, 
        serial: str, 
        package_name: Optional[str] = None
    ) -> List[Dict]:
        """
        Get running services
        
        Args:
            serial: Device serial
            package_name: Optional package to filter
            
        Returns:
            List of service dictionaries
        """
        returncode, stdout, stderr = await self.adb.execute_command_async(
            ["-s", serial, "shell", "dumpsys", "activity", "services"],
            timeout=10
        )
        
        if returncode != 0:
            logger.error(f"Failed to get services: {stderr}")
            return []
        
        services = []
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Look for service patterns
            # Example: "ServiceRecord{abc123 u0 com.example.app/.MyService}"
            if 'ServiceRecord' in line:
                match = re.search(r'([a-zA-Z0-9.]+/[a-zA-Z0-9$.]+)', line)
                if match:
                    service_name = match.group(1)
                    if not package_name or service_name.startswith(package_name):
                        # Try to extract PID
                        pid_match = re.search(r'pid=(\d+)', line)
                        pid = int(pid_match.group(1)) if pid_match else 0
                        
                        services.append({
                            "name": service_name,
                            "pid": pid,
                            "startTime": ""  # Could extract if needed
                        })
        
        logger.info(f"Found {len(services)} services")
        return services
    
    async def get_receivers(
        self, 
        serial: str, 
        package_name: Optional[str] = None
    ) -> List[Dict]:
        """
        Get broadcast receivers
        
        Args:
            serial: Device serial
            package_name: Optional package to filter
            
        Returns:
            List of receiver dictionaries
        """
        returncode, stdout, stderr = await self.adb.execute_command_async(
            ["-s", serial, "shell", "dumpsys", "activity", "broadcasts"],
            timeout=10
        )
        
        if returncode != 0:
            logger.error(f"Failed to get receivers: {stderr}")
            return []
        
        receivers = []
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Look for receiver patterns
            if 'BroadcastRecord' in line or 'Receiver' in line:
                if not package_name or (package_name and package_name in line):
                    # Extract receiver info
                    receiver_match = re.search(r'([a-zA-Z0-9.]+/[a-zA-Z0-9$.]+)', line)
                    action_match = re.search(r'act=([^\s]+)', line)
                    
                    if receiver_match:
                        receivers.append({
                            "name": receiver_match.group(1),
                            "action": action_match.group(1) if action_match else "unknown",
                            "timestamp": ""
                        })
        
        logger.info(f"Found {len(receivers)} receivers")
        return receivers[:10]  # Limit to recent
    
    async def get_permissions(self, serial: str, package_name: str) -> List[Dict]:
        """
        Get granted permissions for package
        
        Args:
            serial: Device serial
            package_name: Package name
            
        Returns:
            List of permission dictionaries
        """
        returncode, stdout, stderr = await self.adb.execute_command_async(
            ["-s", serial, "shell", "dumpsys", "package", package_name],
            timeout=10
        )
        
        if returncode != 0:
            logger.error(f"Failed to get permissions: {stderr}")
            return []
        
        permissions = []
        in_permissions_section = False
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            if 'granted permissions:' in line.lower():
                in_permissions_section = True
                continue
            
            if in_permissions_section:
                if line.startswith('android.permission.'):
                    perm_name = line.split(':')[0].replace('android.permission.', '')
                    permissions.append({
                        "name": perm_name,
                        "granted": True,
                        "timestamp": ""
                    })
                elif not line or line.startswith('User'):
                    break
        
        logger.info(f"Found {len(permissions)} permissions")
        return permissions
    
    async def get_foreground_app(self, serial: str) -> Optional[str]:
        """
        Get currently foreground app package
        
        Args:
            serial: Device serial
            
        Returns:
            Package name or None
        """
        returncode, stdout, stderr = await self.adb.execute_command_async(
            ["-s", serial, "shell", "dumpsys", "window", "windows"],
            timeout=5
        )
        
        if returncode != 0:
            return None
        
        # Look for mCurrentFocus or mFocusedApp
        for line in stdout.split('\n'):
            if 'mCurrentFocus' in line or 'mFocusedApp' in line:
                match = re.search(r'([a-zA-Z0-9.]+)/([a-zA-Z0-9$.]+)', line)
                if match:
                    return match.group(1)
        
        return None


# Global service instance
_runtime_analysis: Optional[RuntimeAnalysisService] = None


def get_runtime_analysis_service() -> RuntimeAnalysisService:
    """Get or create runtime analysis service singleton"""
    global _runtime_analysis
    if _runtime_analysis is None:
        _runtime_analysis = RuntimeAnalysisService()
    return _runtime_analysis
