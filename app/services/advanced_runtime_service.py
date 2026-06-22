"""
Advanced Runtime Monitoring Service
Real-time monitoring of permissions, overlays, intents, services, and processes
"""

import logging
import re
import asyncio
from typing import List, Dict, Optional, Set
from datetime import datetime
from .adb_controller import get_adb_controller

logger = logging.getLogger(__name__)


class AdvancedRuntimeService:
    """Advanced runtime analysis and monitoring"""
    
    def __init__(self):
        self.adb = get_adb_controller()
        self._monitoring_tasks = {}
    
    async def monitor_runtime_permissions(self, serial: str, package: str) -> Dict:
        """
        Monitor runtime permission requests and grants
        
        Args:
            serial: Device serial
            package: Package name to monitor
            
        Returns:
            Permission monitoring data
        """
        logger.info(f"[AdvancedRuntime] Monitoring runtime permissions for {package}")
        
        try:
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "package", package]
            )
            
            if returncode != 0:
                return {"error": stderr}
            
            # Extract runtime permissions
            runtime_perms = []
            in_runtime_section = False
            
            for line in stdout.split('\n'):
                if 'runtime permissions:' in line.lower():
                    in_runtime_section = True
                    continue
                elif in_runtime_section:
                    if line.strip().startswith('android.permission.'):
                        parts = line.strip().split(':')
                        perm_name = parts[0].replace('android.permission.', '')
                        granted = 'granted=true' in line
                        flags = []
                        if 'REVOKE_ON_UPGRADE' in line:
                            flags.append('REVOKE_ON_UPGRADE')
                        if 'USER_SET' in line:
                            flags.append('USER_SET')
                        
                        runtime_perms.append({
                            "permission": perm_name,
                            "granted": granted,
                            "flags": flags,
                            "timestamp": datetime.now().isoformat()
                        })
                    elif not line.strip():
                        break
            
            return {
                "package": package,
                "runtime_permissions": runtime_perms,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error monitoring permissions: {e}", exc_info=True)
            return {"error": str(e)}
    
    async def detect_overlay_abuse(self, serial: str) -> List[Dict]:
        """
        Detect overlay window abuse (banking malware technique)
        
        Args:
            serial: Device serial
            
        Returns:
            List of detected overlays
        """
        logger.info(f"[AdvancedRuntime] Detecting overlay abuse")
        
        try:
            # Check for SYSTEM_ALERT_WINDOW permission grants
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "window", "|", "grep", "-A", "20", "mCurrentFocus"]
            )
            
            overlays = []
            
            # Get apps with overlay permission
            returncode2, perm_stdout, _ = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "package", "|", "grep", "-B", "5", "SYSTEM_ALERT_WINDOW"]
            )
            
            # Parse packages with overlay permission
            packages_with_overlay = set()
            for line in perm_stdout.split('\n'):
                if 'package:' in line.lower():
                    match = re.search(r'package:\s*(\S+)', line, re.IGNORECASE)
                    if match:
                        packages_with_overlay.add(match.group(1))
            
            # Check active windows
            for package in packages_with_overlay:
                if package in stdout:
                    overlays.append({
                        "package": package,
                        "type": "SYSTEM_ALERT_WINDOW",
                        "active": True,
                        "timestamp": datetime.now().isoformat()
                    })
            
            logger.info(f"[AdvancedRuntime] Detected {len(overlays)} active overlays")
            return overlays
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error detecting overlays: {e}", exc_info=True)
            return []
    
    async def detect_accessibility_abuse(self, serial: str) -> List[Dict]:
        """
        Detect accessibility service abuse (banking malware technique)
        
        Args:
            serial: Device serial
            
        Returns:
            List of accessibility services
        """
        logger.info(f"[AdvancedRuntime] Detecting accessibility abuse")
        
        try:
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "accessibility"]
            )
            
            if returncode != 0:
                return []
            
            services = []
            current_service = None
            
            for line in stdout.split('\n'):
                # Parse service info
                if 'id=' in line and 'componentName=' in line:
                    match = re.search(r'componentName=([^,\s}]+)', line)
                    if match:
                        current_service = {
                            "component": match.group(1),
                            "package": match.group(1).split('/')[0],
                            "enabled": 'enabled=true' in line.lower() or 'bound=true' in line.lower(),
                            "capabilities": [],
                            "timestamp": datetime.now().isoformat()
                        }
                
                # Parse capabilities
                if current_service:
                    if 'canRetrieveWindowContent' in line:
                        current_service["capabilities"].append("RETRIEVE_WINDOW_CONTENT")
                    if 'canRequestTouchExploration' in line:
                        current_service["capabilities"].append("TOUCH_EXPLORATION")
                    if 'canRequestEnhancedWebAccessibility' in line:
                        current_service["capabilities"].append("ENHANCED_WEB_ACCESSIBILITY")
                    if 'canPerformGestures' in line:
                        current_service["capabilities"].append("PERFORM_GESTURES")
                    
                    # Add completed service
                    if line.strip() == '' and current_service not in services:
                        services.append(current_service)
                        current_service = None
            
            logger.info(f"[AdvancedRuntime] Detected {len(services)} accessibility services")
            return services
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error detecting accessibility abuse: {e}", exc_info=True)
            return []
    
    async def monitor_intents(self, serial: str, package: str) -> List[Dict]:
        """
        Monitor broadcast intents and receivers
        
        Args:
            serial: Device serial
            package: Package name
            
        Returns:
            List of intents
        """
        logger.info(f"[AdvancedRuntime] Monitoring intents for {package}")
        
        try:
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "dumpsys", "package", package]
            )
            
            if returncode != 0:
                return []
            
            intents = []
            in_receiver_section = False
            
            for line in stdout.split('\n'):
                if 'Receiver Resolver Table:' in line:
                    in_receiver_section = True
                    continue
                elif in_receiver_section:
                    if line.strip().startswith('android.intent.action.'):
                        intent_action = line.strip().split()[0]
                        intents.append({
                            "action": intent_action,
                            "package": package,
                            "type": "broadcast_receiver",
                            "timestamp": datetime.now().isoformat()
                        })
                    elif 'Activity Resolver Table:' in line:
                        break
            
            logger.info(f"[AdvancedRuntime] Found {len(intents)} registered intents")
            return intents
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error monitoring intents: {e}", exc_info=True)
            return []
    
    async def get_running_services(self, serial: str, package: Optional[str] = None) -> List[Dict]:
        """
        Get running services
        
        Args:
            serial: Device serial
            package: Optional package filter
            
        Returns:
            List of running services
        """
        logger.info(f"[AdvancedRuntime] Getting running services")
        
        try:
            cmd = ["dumpsys", "activity", "services"]
            if package:
                cmd.extend([package])
            
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell"] + cmd
            )
            
            if returncode != 0:
                return []
            
            services = []
            current_service = None
            
            for line in stdout.split('\n'):
                if 'ServiceRecord{' in line:
                    match = re.search(r'(\S+)/(\S+)', line)
                    if match:
                        current_service = {
                            "package": match.group(1),
                            "service": match.group(2),
                            "pid": None,
                            "timestamp": datetime.now().isoformat()
                        }
                
                if current_service:
                    if 'pid=' in line:
                        pid_match = re.search(r'pid=(\d+)', line)
                        if pid_match:
                            current_service["pid"] = int(pid_match.group(1))
                    
                    if line.strip() == '' and current_service not in services:
                        services.append(current_service)
                        current_service = None
            
            logger.info(f"[AdvancedRuntime] Found {len(services)} running services")
            return services
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error getting services: {e}", exc_info=True)
            return []
    
    async def get_network_connections(self, serial: str) -> List[Dict]:
        """
        Get active network connections
        
        Args:
            serial: Device serial
            
        Returns:
            List of connections
        """
        logger.info(f"[AdvancedRuntime] Getting network connections")
        
        try:
            # Get TCP connections
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "cat", "/proc/net/tcp"]
            )
            
            if returncode != 0:
                return []
            
            connections = []
            lines = stdout.split('\n')[1:]  # Skip header
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                try:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3]
                    
                    # Parse hex addresses
                    local = self._parse_hex_address(local_addr)
                    remote = self._parse_hex_address(remote_addr)
                    
                    if remote['ip'] != '0.0.0.0' and remote['port'] != 0:
                        connections.append({
                            "local": local,
                            "remote": remote,
                            "state": state,
                            "protocol": "TCP",
                            "timestamp": datetime.now().isoformat()
                        })
                except Exception as e:
                    continue
            
            logger.info(f"[AdvancedRuntime] Found {len(connections)} network connections")
            return connections
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error getting network connections: {e}", exc_info=True)
            return []
    
    async def get_process_list(self, serial: str) -> List[Dict]:
        """
        Get running processes
        
        Args:
            serial: Device serial
            
        Returns:
            List of processes
        """
        logger.info(f"[AdvancedRuntime] Getting process list")
        
        try:
            returncode, stdout, stderr = await self.adb.execute_command_async(
                ["-s", serial, "shell", "ps", "-A"]
            )
            
            if returncode != 0:
                return []
            
            processes = []
            lines = stdout.split('\n')[1:]  # Skip header
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 9:
                    continue
                
                try:
                    processes.append({
                        "user": parts[0],
                        "pid": int(parts[1]),
                        "ppid": int(parts[2]),
                        "vsz": parts[4],
                        "rss": parts[5],
                        "name": parts[8],
                        "timestamp": datetime.now().isoformat()
                    })
                except Exception as e:
                    continue
            
            logger.info(f"[AdvancedRuntime] Found {len(processes)} processes")
            return processes
            
        except Exception as e:
            logger.error(f"[AdvancedRuntime] Error getting processes: {e}", exc_info=True)
            return []
    
    def _parse_hex_address(self, hex_addr: str) -> Dict:
        """Parse hex IP:Port address"""
        try:
            addr, port = hex_addr.split(':')
            
            # Convert hex IP to dotted decimal (reverse byte order)
            ip_bytes = [addr[i:i+2] for i in range(0, len(addr), 2)]
            ip = '.'.join(str(int(b, 16)) for b in reversed(ip_bytes))
            
            # Convert hex port
            port_dec = int(port, 16)
            
            return {
                "ip": ip,
                "port": port_dec
            }
        except:
            return {"ip": "unknown", "port": 0}


# Global service instance
_advanced_runtime_service: Optional[AdvancedRuntimeService] = None


def get_advanced_runtime_service() -> AdvancedRuntimeService:
    """Get or create advanced runtime service singleton"""
    global _advanced_runtime_service
    if _advanced_runtime_service is None:
        _advanced_runtime_service = AdvancedRuntimeService()
    return _advanced_runtime_service
