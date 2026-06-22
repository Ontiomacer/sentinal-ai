"""
Logcat Service
Streams and parses Android logcat output
"""

import logging
import asyncio
import re
from typing import Optional, Dict, AsyncIterator
from datetime import datetime
from .adb_controller import get_adb_controller

logger = logging.getLogger(__name__)


class LogcatService:
    """Handles logcat streaming and parsing"""
    
    # Logcat format: MM-DD HH:MM:SS.mmm PID TID LEVEL TAG: MESSAGE
    LOGCAT_PATTERN = re.compile(
        r'(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+'  # timestamp
        r'(\d+)\s+'  # pid
        r'(\d+)\s+'  # tid
        r'([VDIWEF])\s+'  # level
        r'([^:]+):\s*'  # tag
        r'(.*)'  # message
    )
    
    def __init__(self):
        self.adb = get_adb_controller()
        self._active_streams = {}
    
    async def stream_logcat(
        self, 
        serial: str,
        filter_package: Optional[str] = None
    ) -> AsyncIterator[Dict]:
        """
        Stream logcat output
        
        Args:
            serial: Device serial
            filter_package: Optional package name to filter
            
        Yields:
            Parsed log entry dictionaries
        """
        args = ["-s", serial, "logcat", "-v", "threadtime"]
        
        if filter_package:
            args.extend(["--pid", f"$(pidof -s {filter_package})"])
        
        try:
            process = await self.adb.stream_command(args)
            self._active_streams[serial] = process
            
            logger.info(f"Started logcat stream for {serial}")
            
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode('utf-8', errors='replace').strip()
                
                if not line_str:
                    continue
                
                # Parse log entry
                parsed = self._parse_log_line(line_str)
                if parsed:
                    yield parsed
                    
        except asyncio.CancelledError:
            logger.info(f"Logcat stream cancelled for {serial}")
            if serial in self._active_streams:
                process = self._active_streams[serial]
                process.terminate()
                await process.wait()
                del self._active_streams[serial]
        except Exception as e:
            logger.error(f"Logcat stream error: {e}")
            if serial in self._active_streams:
                del self._active_streams[serial]
    
    def _parse_log_line(self, line: str) -> Optional[Dict]:
        """
        Parse logcat line
        
        Args:
            line: Raw logcat line
            
        Returns:
            Parsed log entry or None
        """
        match = self.LOGCAT_PATTERN.match(line)
        if not match:
            return None
        
        timestamp_str, pid, tid, level, tag, message = match.groups()
        
        # Convert timestamp to ISO format
        try:
            # Parse MM-DD HH:MM:SS.mmm
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year}-{timestamp_str}"
            timestamp = datetime.strptime(timestamp_with_year, "%Y-%m-%d %H:%M:%S.%f")
            iso_timestamp = timestamp.isoformat()
        except:
            iso_timestamp = datetime.now().isoformat()
        
        return {
            "timestamp": iso_timestamp,
            "pid": pid,
            "tid": tid,
            "level": level,
            "tag": tag.strip(),
            "message": message.strip()
        }
    
    async def get_recent_logs(
        self, 
        serial: str, 
        lines: int = 100
    ) -> list[Dict]:
        """
        Get recent log entries
        
        Args:
            serial: Device serial
            lines: Number of recent lines to fetch
            
        Returns:
            List of parsed log entries
        """
        args = ["-s", serial, "logcat", "-v", "threadtime", "-t", str(lines)]
        
        returncode, stdout, stderr = await self.adb.execute_command_async(args, timeout=10)
        
        if returncode != 0:
            logger.error(f"Failed to get recent logs: {stderr}")
            return []
        
        logs = []
        for line in stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            parsed = self._parse_log_line(line)
            if parsed:
                logs.append(parsed)
        
        return logs
    
    async def clear_logcat(self, serial: str) -> bool:
        """
        Clear logcat buffer
        
        Args:
            serial: Device serial
            
        Returns:
            Success status
        """
        args = ["-s", serial, "logcat", "-c"]
        returncode, stdout, stderr = await self.adb.execute_command_async(args)
        
        if returncode == 0:
            logger.info(f"Logcat cleared for {serial}")
            return True
        else:
            logger.error(f"Failed to clear logcat: {stderr}")
            return False
    
    def stop_stream(self, serial: str):
        """
        Stop active logcat stream
        
        Args:
            serial: Device serial
        """
        if serial in self._active_streams:
            process = self._active_streams[serial]
            process.terminate()
            del self._active_streams[serial]
            logger.info(f"Stopped logcat stream for {serial}")


# Global service instance
_logcat_service: Optional[LogcatService] = None


def get_logcat_service() -> LogcatService:
    """Get or create logcat service singleton"""
    global _logcat_service
    if _logcat_service is None:
        _logcat_service = LogcatService()
    return _logcat_service
