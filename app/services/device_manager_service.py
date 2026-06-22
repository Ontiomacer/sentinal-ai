"""
Device Manager Service
Manages Android device connections and information
"""

import logging
from typing import Optional, Dict, List
from datetime import datetime
from .adb_controller import get_adb_controller

logger = logging.getLogger(__name__)


class DeviceManagerService:
    """Manages Android device connections"""
    
    def __init__(self):
        self.adb = get_adb_controller()
        self._device_cache = {}
        self._cache_ttl = 5  # seconds
    
    def get_connected_devices(self) -> List[Dict]:
        """
        Get all connected devices with full information
        
        Returns:
            List of device information dictionaries
        """
        devices = self.adb.get_devices()
        
        device_info_list = []
        for device in devices:
            if device["status"] == "device":
                info = self.get_device_info(device["serial"])
                if info:
                    device_info_list.append(info)
        
        return device_info_list
    
    def get_device_info(self, serial: str) -> Optional[Dict]:
        """
        Get detailed device information
        
        Args:
            serial: Device serial number
            
        Returns:
            Device information dictionary or None
        """
        # Check cache
        if serial in self._device_cache:
            cached = self._device_cache[serial]
            age = (datetime.now() - cached["cached_at"]).seconds
            if age < self._cache_ttl:
                return cached["data"]
        
        # Fetch fresh data
        try:
            model = self.adb.get_device_property(serial, "ro.product.model")
            android_version = self.adb.get_device_property(serial, "ro.build.version.release")
            sdk_version = self.adb.get_device_property(serial, "ro.build.version.sdk")
            manufacturer = self.adb.get_device_property(serial, "ro.product.manufacturer")
            
            # Get battery info
            battery_info = self._get_battery_info(serial)
            
            device_info = {
                "serial": serial,
                "model": model or "Unknown",
                "androidVersion": android_version or "Unknown",
                "sdkVersion": sdk_version or "Unknown",
                "manufacturer": manufacturer or "Unknown",
                "battery": battery_info.get("level", 0),
                "batteryStatus": battery_info.get("status", "Unknown"),
                "status": "connected",
                "adbReady": True,
                "timestamp": datetime.now().isoformat()
            }
            
            # Cache it
            self._device_cache[serial] = {
                "data": device_info,
                "cached_at": datetime.now()
            }
            
            logger.info(f"Device info fetched: {model} ({serial})")
            return device_info
            
        except Exception as e:
            logger.error(f"Failed to get device info for {serial}: {e}")
            return None
    
    def _get_battery_info(self, serial: str) -> Dict:
        """
        Get battery information
        
        Args:
            serial: Device serial
            
        Returns:
            Battery info dictionary
        """
        returncode, stdout, stderr = self.adb.execute_shell_command(
            serial,
            "dumpsys battery"
        )
        
        if returncode != 0:
            return {"level": 0, "status": "Unknown"}
        
        battery_info = {}
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith("level:"):
                battery_info["level"] = int(line.split(":")[1].strip())
            elif line.startswith("status:"):
                status_code = int(line.split(":")[1].strip())
                battery_info["status"] = self._battery_status_name(status_code)
        
        return battery_info
    
    def _battery_status_name(self, status_code: int) -> str:
        """Convert battery status code to name"""
        status_map = {
            1: "Unknown",
            2: "Charging",
            3: "Discharging",
            4: "Not Charging",
            5: "Full"
        }
        return status_map.get(status_code, "Unknown")
    
    def check_device_health(self, serial: str) -> Dict:
        """
        Check device health status
        
        Args:
            serial: Device serial
            
        Returns:
            Health status dictionary
        """
        health = {
            "serial": serial,
            "connected": False,
            "adb_responsive": False,
            "storage_available": False,
            "timestamp": datetime.now().isoformat()
        }
        
        # Check if device is in device list
        devices = self.adb.get_devices()
        for device in devices:
            if device["serial"] == serial and device["status"] == "device":
                health["connected"] = True
                break
        
        if not health["connected"]:
            return health
        
        # Check ADB responsiveness
        returncode, stdout, stderr = self.adb.execute_shell_command(serial, "echo test")
        if returncode == 0 and "test" in stdout:
            health["adb_responsive"] = True
        
        # Check storage
        returncode, stdout, stderr = self.adb.execute_shell_command(serial, "df /data")
        if returncode == 0:
            health["storage_available"] = True
            # Parse storage info if needed
        
        return health
    
    def get_first_available_device(self) -> Optional[Dict]:
        """
        Get first available connected device
        
        Returns:
            Device info or None
        """
        devices = self.get_connected_devices()
        return devices[0] if devices else None


# Global service instance
_device_manager: Optional[DeviceManagerService] = None


def get_device_manager() -> DeviceManagerService:
    """Get or create device manager singleton"""
    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManagerService()
    return _device_manager
