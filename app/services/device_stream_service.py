"""
Device Stream Service
Real-time Android device streaming using scrcpy
Provides web-compatible video streaming from physical device
"""

import subprocess
import asyncio
import logging
from typing import Any, AsyncIterator, Optional, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


class DeviceStreamService:
    """
    Manages scrcpy-based device streaming
    Streams device screen to web clients via video file/HLS
    """
    
    def __init__(self, scrcpy_path: str = "scrcpy", ffmpeg_path: str = "ffmpeg"):
        self.scrcpy_path = scrcpy_path
        self.ffmpeg_path = ffmpeg_path
        self._active_streams: Dict[str, Any] = {}
        self._stream_dir = Path("uploads/device_streams")
        self._stream_dir.mkdir(parents=True, exist_ok=True)
        
    def get_device_resolution(self, serial: str) -> tuple[int, int]:
        """
        Get device display resolution
        
        Args:
            serial: Device serial
            
        Returns:
            (width, height) tuple
        """
        try:
            result = subprocess.run(
                [self.scrcpy_path, "-s", serial, "--list-displays"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse output for resolution
            for line in result.stderr.split('\n'):
                if '--display-id=' in line and '(' in line and 'x' in line:
                    # Extract resolution from: --display-id=0    (720x1600)
                    res_str = line.split('(')[1].split(')')[0]
                    width, height = map(int, res_str.split('x'))
                    return (width, height)
            
            # Default for Samsung A06
            return (720, 1600)
            
        except Exception as e:
            logger.error(f"Failed to get resolution: {e}")
            return (720, 1600)
    
    async def start_stream_to_file(
        self,
        serial: str,
        max_size: int = 720,
        bit_rate: str = "2M",
        max_fps: int = 30
    ) -> bool:
        """
        Start scrcpy stream recording to file (for web streaming)
        
        Args:
            serial: Device serial
            max_size: Max screen dimension (720 for web)
            bit_rate: Video bitrate
            max_fps: Max FPS
            
        Returns:
            Success status
        """
        if serial in self._active_streams:
            logger.info(f"Stream already active for {serial}")
            return True
        
        stream_file = self._stream_dir / f"{serial}_stream.mp4"
        
        # Remove old stream file if exists
        if stream_file.exists():
            stream_file.unlink()
        
        cmd = [
            self.scrcpy_path,
            "-s", serial,
            "--no-audio",  # Video only for web
            "--max-size", str(max_size),
            "--video-bit-rate", bit_rate,
            "--max-fps", str(max_fps),
            "--no-playback",  # No local window/playback
            "--record", str(stream_file)
        ]
        
        logger.info(f"Starting scrcpy stream: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self._active_streams[serial] = process
            
            # Wait a moment for stream to start
            await asyncio.sleep(2)
            
            # Check if process is still running
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                logger.error(f"Scrcpy failed: {stderr.decode()}")
                return False
            
            logger.info(f"Stream started for {serial}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start stream: {e}")
            return False
    
    async def start_realtime_stream(
        self,
        serial: str,
        max_size: int = 720,
        bit_rate: str = "2M",
        max_fps: int = 30,
        port: int = 8554  # RTSP port
    ) -> bool:
        """
        Validate that scrcpy can be used for real-time streaming.

        The browser-visible stream is created by stream_mjpeg(). This method is
        intentionally lightweight so /mirror/start does not spawn an unused
        stdout pipe that could block.
        
        Args:
            serial: Device serial
            max_size: Max dimension
            bit_rate: Bitrate
            max_fps: FPS
            port: Streaming port
            
        Returns:
            Success status
        """
        if self.is_streaming(serial):
            logger.info(f"Stream already active for {serial}")
            return True

        try:
            result = subprocess.run(
                [self.scrcpy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                logger.error(f"scrcpy unavailable: {result.stderr}")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to validate scrcpy streaming: {e}")
            return False

    def _process_running(self, process: Any) -> bool:
        if isinstance(process, subprocess.Popen):
            return process.poll() is None
        return getattr(process, "returncode", None) is None

    def _terminate_process(self, process: Any) -> None:
        try:
            process.terminate()
        except ProcessLookupError:
            return
        except Exception:
            try:
                process.kill()
            except Exception:
                return

        if isinstance(process, subprocess.Popen):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    async def stream_mjpeg(
        self,
        serial: str,
        max_size: int = 720,
        bit_rate: str = "2M",
        max_fps: int = 24,
    ) -> AsyncIterator[bytes]:
        """Stream the Android screen as multipart MJPEG.

        Pipeline:
        scrcpy --no-window --record=- (stdout pipe) -> ffmpeg -> multipart JPEG.
        
        This uses scrcpy's direct video pipe (--record -) which outputs MKV/H264
        to stdout, then ffmpeg decodes and re-encodes to Motion JPEG for the browser.
        """
        import subprocess
        import concurrent.futures
        
        key = f"{serial}_mjpeg"
        self.stop_stream(serial)

        # scrcpy: Record H264 to stdout in MKV container, no window needed
        scrcpy_cmd = [
            self.scrcpy_path,
            "-s", serial,
            "--no-audio",
            "--no-window",  # Headless - no GUI window
            "--max-size", str(max_size),
            "--video-bit-rate", bit_rate,
            "--max-fps", str(max_fps),
            "--video-codec=h264",
            "--record", "-",  # Record to stdout
            "--record-format=mkv",  # MKV container for H264
        ]
        
        # ffmpeg: Decode MKV/H264 from stdin, encode to Motion JPEG to stdout
        ffmpeg_cmd = [
            self.ffmpeg_path,
            "-hide_banner",
            "-loglevel", "warning",
            "-probesize", "32",
            "-analyzeduration", "0",
            "-fflags", "nobuffer",
            "-flags", "low_delay",
            "-f", "matroska",  # Input is MKV from scrcpy
            "-i", "pipe:0",  # Read from stdin
            "-vf", f"scale={max_size}:-1:flags=fast_bilinear",  # Resize
            "-f", "image2pipe",  # Output individual JPEG images
            "-vcodec", "mjpeg",  # MJPEG codec
            "-q:v", "5",  # JPEG quality (2=best, 31=worst, 5=high quality)
            "pipe:1",  # Write to stdout
        ]

        logger.info(f"[DeviceStream] Starting scrcpy direct pipe: {' '.join(scrcpy_cmd)}")
        logger.info(f"[DeviceStream] Starting ffmpeg transcoder: {' '.join(ffmpeg_cmd)}")

        # Start scrcpy using Popen (Windows-compatible)
        scrcpy_proc = subprocess.Popen(
            scrcpy_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Start ffmpeg using Popen (Windows-compatible)
        ffmpeg_proc = subprocess.Popen(
            ffmpeg_cmd,
            stdin=scrcpy_proc.stdout,  # Connect scrcpy stdout to ffmpeg stdin
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Close scrcpy stdout in parent so ffmpeg gets EOF when scrcpy exits
        if scrcpy_proc.stdout:
            scrcpy_proc.stdout.close()
        
        self._active_streams[key] = scrcpy_proc
        self._active_streams[f"{key}_ffmpeg"] = ffmpeg_proc

        # Read stderr from both processes asynchronously
        async def drain_stderr(proc: subprocess.Popen, name: str) -> None:
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                try:
                    while proc.poll() is None:
                        line = await loop.run_in_executor(pool, proc.stderr.readline)
                        if not line:
                            break
                        decoded = line.decode(errors='replace').strip()
                        if decoded:
                            logger.info(f"[DeviceStream] {name}: {decoded}")
                except Exception as e:
                    logger.debug(f"[DeviceStream] {name} stderr closed: {e}")

        err_tasks = [
            asyncio.create_task(drain_stderr(scrcpy_proc, "scrcpy")),
            asyncio.create_task(drain_stderr(ffmpeg_proc, "ffmpeg")),
        ]

        try:
            logger.info(f"[DeviceStream] Starting MJPEG stream for {serial}")
            logger.info(f"[DeviceStream] Waiting for first frame...")
            
            # Read from ffmpeg stdout using thread pool executor
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                frame_count = 0
                last_log_time = asyncio.get_event_loop().time()
                first_frame_logged = False
                
                while True:
                    # Read one JPEG frame from ffmpeg
                    # ffmpeg outputs raw JPEG bytes, we need to wrap in multipart
                    frame_data = b""
                    
                    # Read until we find JPEG start marker (FF D8)
                    while True:
                        byte = await loop.run_in_executor(pool, ffmpeg_proc.stdout.read, 1)
                        if not byte:
                            break
                        frame_data += byte
                        if len(frame_data) >= 2 and frame_data[-2:] == b'\xff\xd8':
                            # Found JPEG start, now read until end marker (FF D9)
                            break
                    
                    if not frame_data:
                        logger.warning(f"[DeviceStream] Stream ended for {serial}")
                        break
                    
                    # Read rest of JPEG until end marker
                    while True:
                        byte = await loop.run_in_executor(pool, ffmpeg_proc.stdout.read, 1)
                        if not byte:
                            break
                        frame_data += byte
                        if len(frame_data) >= 2 and frame_data[-2:] == b'\xff\xd9':
                            # Found JPEG end
                            break
                    
                    if len(frame_data) < 100:
                        continue  # Invalid frame
                    
                    frame_count += 1
                    
                    # Log first frame
                    if not first_frame_logged:
                        logger.info(f"[DeviceStream] FIRST FRAME: size={len(frame_data)} bytes, starts_with_FFD8={frame_data[:2] == b'\\xff\\xd8'}")
                        first_frame_logged = True
                    
                    # Log every 30 frames
                    if frame_count % 30 == 0:
                        current_time = asyncio.get_event_loop().time()
                        fps = 30 / (current_time - last_log_time) if frame_count > 30 else 0
                        logger.info(f"[DeviceStream] MJPEG frame={frame_count} size={len(frame_data)} fps={fps:.1f}")
                        last_log_time = current_time
                    
                    # Create multipart MJPEG response
                    yield b'--sentinel\r\n'
                    yield b'Content-Type: image/jpeg\r\n'
                    yield f'Content-Length: {len(frame_data)}\r\n'.encode()
                    yield b'\r\n'
                    yield frame_data
                    yield b'\r\n'
                
        except asyncio.CancelledError:
            logger.info(f"[DeviceStream] Stream cancelled for {serial}")
            raise
        except Exception as e:
            logger.error(f"[DeviceStream] Stream error for {serial}: {e}")
            raise
        finally:
            logger.info(f"[DeviceStream] Cleaning up stream for {serial}")
            for task in err_tasks:
                task.cancel()
            self.stop_stream(serial)
    
    def stop_stream(self, serial: str):
        """Stop active stream and clean up all related processes"""
        import psutil
        
        # Stop tracked processes
        keys_to_remove = []
        for key in list(self._active_streams.keys()):
            if serial in key:
                process = self._active_streams[key]
                try:
                    self._terminate_process(process)
                    logger.info(f"[DeviceStream] Stopped process: {key}")
                except Exception as e:
                    logger.warning(f"[DeviceStream] Error stopping {key}: {e}")
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._active_streams[key]
        
        # Kill any orphaned scrcpy/ffmpeg processes for this device
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline') or []
                    cmdline_str = ' '.join(cmdline).lower()
                    
                    # Kill scrcpy processes for this device
                    if 'scrcpy' in cmdline_str and serial.lower() in cmdline_str:
                        logger.info(f"[DeviceStream] Killing orphaned scrcpy: PID {proc.info['pid']}")
                        proc.kill()
                    
                    # Kill ffmpeg processes that might be related
                    if 'ffmpeg' in cmdline_str and ('matroska' in cmdline_str or 'mpjpeg' in cmdline_str):
                        logger.info(f"[DeviceStream] Killing orphaned ffmpeg: PID {proc.info['pid']}")
                        proc.kill()
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.warning(f"[DeviceStream] Error killing orphaned processes: {e}")
        
        logger.info(f"[DeviceStream] Cleanup complete for {serial}")
    
    def is_streaming(self, serial: str) -> bool:
        """Check if device is currently streaming"""
        for key in (serial, f"{serial}_realtime", f"{serial}_mjpeg", f"{serial}_mjpeg_ffmpeg"):
            if key in self._active_streams:
                process = self._active_streams[key]
                if self._process_running(process):
                    return True
                del self._active_streams[key]
        return False
    
    def get_stream_file(self, serial: str) -> Optional[Path]:
        """Get stream file path for device"""
        stream_file = self._stream_dir / f"{serial}_stream.mp4"
        if stream_file.exists():
            return stream_file
        return None
    
    async def inject_touch(self, serial: str, x: int, y: int, action: str = "tap"):
        """
        Inject touch event (uses ADB, scrcpy control not needed)
        
        Args:
            serial: Device serial
            x, y: Touch coordinates
            action: tap/down/up
        """
        from app.services.adb_controller import get_adb_controller
        adb = get_adb_controller()
        
        if action == "tap":
            cmd = f"input tap {x} {y}"
        elif action == "down":
            cmd = f"input touchscreen down {x} {y}"
        elif action == "up":
            cmd = f"input touchscreen up {x} {y}"
        else:
            cmd = f"input tap {x} {y}"
        
        returncode, stdout, stderr = await adb.execute_command_async(
            ["-s", serial, "shell", cmd]
        )
        
        return returncode == 0
    
    async def inject_swipe(
        self,
        serial: str,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        duration: int = 300
    ):
        """Inject swipe gesture"""
        from app.services.adb_controller import get_adb_controller
        adb = get_adb_controller()
        
        cmd = f"input swipe {x1} {y1} {x2} {y2} {duration}"
        returncode, stdout, stderr = await adb.execute_command_async(
            ["-s", serial, "shell", cmd]
        )
        
        return returncode == 0
    
    async def inject_text(self, serial: str, text: str):
        """Inject text input"""
        from app.services.adb_controller import get_adb_controller
        adb = get_adb_controller()
        
        # Escape special characters
        escaped = text.replace(" ", "%s").replace("'", "\\'")
        cmd = f"input text '{escaped}'"
        
        returncode, stdout, stderr = await adb.execute_command_async(
            ["-s", serial, "shell", cmd]
        )
        
        return returncode == 0
    
    async def inject_key(self, serial: str, keycode: str):
        """
        Inject key event
        
        Args:
            serial: Device serial
            keycode: KEYCODE_HOME, KEYCODE_BACK, etc.
        """
        from app.services.adb_controller import get_adb_controller
        adb = get_adb_controller()
        
        cmd = f"input keyevent {keycode}"
        returncode, stdout, stderr = await adb.execute_command_async(
            ["-s", serial, "shell", cmd]
        )
        
        return returncode == 0


# Global service instance
_stream_service: Optional[DeviceStreamService] = None


def get_stream_service() -> DeviceStreamService:
    """Get or create stream service singleton"""
    global _stream_service
    if _stream_service is None:
        _stream_service = DeviceStreamService()
    return _stream_service
