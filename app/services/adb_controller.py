"""
ADB Controller - Low-level ADB command execution
Handles all communication with Android devices via ADB
"""

import subprocess
import asyncio
import logging
from typing import Optional, List, Dict, Tuple
import shlex

logger = logging.getLogger(__name__)


class ADBController:
    """Low-level ADB command execution controller"""
    
    def __init__(self, adb_path: str = r"C:\platform-tools\adb.exe"):
        """
        Initialize ADB Controller
        
        Args:
            adb_path: Path to adb executable (default: C:\\platform-tools\\adb.exe)
        """
        self.adb_path = adb_path
        self._verify_adb()
    
    def _verify_adb(self) -> bool:
        """Verify ADB is available"""
        try:
            result = self.execute_command(["version"])
            if result[0] == 0:
                logger.info(f"ADB available: {result[1][:50]}")
                return True
            else:
                logger.error("ADB verification failed")
                return False
        except Exception as e:
            logger.error(f"ADB not found: {e}")
            raise RuntimeError(
                "ADB not found. Install Android Platform Tools and add to PATH. "
                "Download: https://developer.android.com/studio/releases/platform-tools"
            )
    
    def execute_command(
        self, 
        args: List[str], 
        timeout: int = 30,
        capture_output: bool = True
    ) -> Tuple[int, str, str]:
        """
        Execute ADB command synchronously
        
        Args:
            args: Command arguments (e.g., ["devices", "-l"])
            timeout: Command timeout in seconds
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        cmd = [self.adb_path] + args
        
        try:
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout
            )
            
            return (result.returncode, result.stdout, result.stderr)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {' '.join(cmd)}")
            return (-1, "", "Command timeout")
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return (-1, "", str(e))
    
    def execute_shell_command(
        self, 
        serial: str, 
        shell_cmd: str, 
        timeout: int = 30
    ) -> Tuple[int, str, str]:
        """
        Execute shell command on device
        
        Args:
            serial: Device serial number
            shell_cmd: Shell command to execute
            timeout: Command timeout
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        args = ["-s", serial, "shell", shell_cmd]
        return self.execute_command(args, timeout)
    
    async def execute_command_async(
        self, 
        args: List[str], 
        timeout: int = 30,
        binary_output: bool = False
    ) -> Tuple[int, bytes | str, str]:
        """
        Execute ADB command asynchronously using thread pool
        
        Args:
            args: Command arguments
            timeout: Command timeout
            binary_output: If True, return stdout as bytes (for screencap)
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        import concurrent.futures
        
        logger.info(f"[ADBController ASYNC] Executing via thread pool: {' '.join([self.adb_path] + args)}")
        
        def _run_command():
            """Run command in thread pool"""
            cmd = [self.adb_path] + args
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout
                )
                
                # Handle binary vs text output
                if binary_output:
                    stdout_result = result.stdout
                else:
                    stdout_result = result.stdout.decode('utf-8', errors='replace').strip()
                
                stderr_str = result.stderr.decode('utf-8', errors='replace').strip()
                
                logger.info(f"[ADBController ASYNC] Command completed: returncode={result.returncode}, stdout_len={len(stdout_result)}, stderr='{stderr_str}'")
                
                return (result.returncode, stdout_result, stderr_str)
                
            except subprocess.TimeoutExpired:
                logger.error(f"[ADBController ASYNC] ✗ Command timeout")
                return (-1, b"" if binary_output else "", "Command timeout")
            except Exception as e:
                logger.error(f"[ADBController ASYNC] ✗ Command failed: {e}", exc_info=True)
                return (-1, b"" if binary_output else "", str(e))
        
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(pool, _run_command)
        
        return result
    
    async def execute_shell_command_async(
        self, 
        serial: str, 
        shell_cmd: str, 
        timeout: int = 30
    ) -> Tuple[int, str, str]:
        """
        Execute shell command on device asynchronously
        
        Args:
            serial: Device serial number
            shell_cmd: Shell command to execute
            timeout: Command timeout
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        args = ["-s", serial, "shell", shell_cmd]
        return await self.execute_command_async(args, timeout)
    
    async def stream_command(
        self, 
        args: List[str]
    ) -> asyncio.subprocess.Process:
        """
        Start streaming command (e.g., logcat)
        
        Args:
            args: Command arguments
            
        Returns:
            Subprocess handle for streaming
        """
        cmd = [self.adb_path] + args
        
        logger.info(f"Starting stream: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        return process
    
    def get_devices(self) -> List[Dict[str, str]]:
        """
        Get list of connected devices
        
        Returns:
            List of device dictionaries with serial and status
        """
        returncode, stdout, stderr = self.execute_command(["devices", "-l"])
        
        if returncode != 0:
            logger.error(f"Failed to get devices: {stderr}")
            return []
        
        devices = []
        lines = stdout.strip().split('\n')[1:]  # Skip "List of devices attached"
        
        for line in lines:
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                
                device = {
                    "serial": serial,
                    "status": status
                }
                
                # Parse additional properties
                for part in parts[2:]:
                    if ':' in part:
                        key, value = part.split(':', 1)
                        device[key] = value
                
                devices.append(device)
        
        logger.info(f"Found {len(devices)} device(s)")
        return devices
    
    def get_device_property(self, serial: str, prop: str) -> Optional[str]:
        """
        Get device property via getprop
        
        Args:
            serial: Device serial
            prop: Property name (e.g., "ro.product.model")
            
        Returns:
            Property value or None
        """
        returncode, stdout, stderr = self.execute_shell_command(
            serial,
            f"getprop {prop}"
        )
        
        if returncode == 0:
            return stdout.strip()
        else:
            logger.error(f"Failed to get property {prop}: {stderr}")
            return None
    
    def install_apk(
        self, 
        serial: str, 
        apk_path: str, 
        replace: bool = True
    ) -> Tuple[bool, str]:
        """
        Install APK on device
        
        Args:
            serial: Device serial
            apk_path: Path to APK file
            replace: Replace existing app if installed
            
        Returns:
            Tuple of (success, message)
        """
        args = ["-s", serial, "install"]
        if replace:
            args.append("-r")
        args.append(apk_path)
        
        returncode, stdout, stderr = self.execute_command(args, timeout=60)
        
        if returncode == 0 and "Success" in stdout:
            logger.info(f"APK installed successfully: {apk_path}")
            return (True, "Installation successful")
        else:
            error_msg = stderr or stdout
            logger.error(f"APK installation failed: {error_msg}")
            return (False, error_msg)
    
    def uninstall_package(self, serial: str, package_name: str) -> Tuple[bool, str]:
        """
        Uninstall package from device
        
        Args:
            serial: Device serial
            package_name: Package name to uninstall
            
        Returns:
            Tuple of (success, message)
        """
        args = ["-s", serial, "uninstall", package_name]
        returncode, stdout, stderr = self.execute_command(args, timeout=30)
        
        if returncode == 0:
            logger.info(f"Package uninstalled: {package_name}")
            return (True, "Uninstall successful")
        else:
            logger.error(f"Uninstall failed: {stderr}")
            return (False, stderr or stdout)
    
    def launch_app(
        self, 
        serial: str, 
        package_name: str
    ) -> Tuple[bool, str]:
        """
        Launch application using monkey
        
        Args:
            serial: Device serial
            package_name: Package to launch
            
        Returns:
            Tuple of (success, message)
        """
        shell_cmd = f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1"
        returncode, stdout, stderr = self.execute_shell_command(serial, shell_cmd)
        
        if returncode == 0:
            logger.info(f"App launched: {package_name}")
            return (True, "Launch successful")
        else:
            logger.error(f"Launch failed: {stderr}")
            return (False, stderr or stdout)
    
    def force_stop_app(self, serial: str, package_name: str) -> Tuple[bool, str]:
        """
        Force stop application
        
        Args:
            serial: Device serial
            package_name: Package to stop
            
        Returns:
            Tuple of (success, message)
        """
        shell_cmd = f"am force-stop {package_name}"
        returncode, stdout, stderr = self.execute_shell_command(serial, shell_cmd)
        
        if returncode == 0:
            logger.info(f"App stopped: {package_name}")
            return (True, "Stop successful")
        else:
            logger.error(f"Stop failed: {stderr}")
            return (False, stderr or stdout)
    
    async def capture_screenshot(self, serial: str) -> Optional[bytes]:
        """
        Capture screenshot from device
        
        Args:
            serial: Device serial number
            
        Returns:
            PNG image bytes or None if failed
        """
        logger.info(f"[ADBController] Capturing screenshot from {serial}")
        
        try:
            # Use exec-out screencap -p to get PNG screenshot
            args = ["-s", serial, "exec-out", "screencap", "-p"]
            returncode, stdout, stderr = await self.execute_command_async(
                args, 
                timeout=10,
                binary_output=True
            )
            
            if returncode != 0:
                logger.error(f"[ADBController] Screenshot failed: {stderr}")
                return None
            
            if not isinstance(stdout, bytes) or len(stdout) < 1000:
                logger.error(f"[ADBController] Screenshot data invalid: {len(stdout) if isinstance(stdout, bytes) else 0} bytes")
                return None
            
            logger.info(f"[ADBController] Screenshot captured: {len(stdout)} bytes")
            return stdout
            
        except Exception as e:
            logger.error(f"[ADBController] Screenshot exception: {e}", exc_info=True)
            return None


# Global ADB controller instance
_adb_controller: Optional[ADBController] = None


def get_adb_controller() -> ADBController:
    """Get or create ADB controller singleton"""
    global _adb_controller
    if _adb_controller is None:
        _adb_controller = ADBController()
    return _adb_controller
