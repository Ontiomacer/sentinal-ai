"""
Direct screenshot test - bypasses API to test ADB directly
"""
import subprocess
import sys

ADB_PATH = r"C:\platform-tools\adb.exe"
SERIAL = "R9ZY90CPP0K"

print("=" * 60)
print("DIRECT SCREENSHOT TEST")
print("=" * 60)
print()

# Test 1: Device connectivity
print("[1] Testing device connectivity...")
cmd = [ADB_PATH, "-s", SERIAL, "get-state"]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
print(f"  Return code: {result.returncode}")
print(f"  Output: {result.stdout.strip()}")
if result.stderr:
    print(f"  Stderr: {result.stderr.strip()}")

if result.returncode != 0:
    print("  ✗ Device not connected!")
    sys.exit(1)
print("  ✓ Device connected")
print()

# Test 2: Screenshot capture
print("[2] Capturing screenshot with exec-out...")
cmd = [ADB_PATH, "-s", SERIAL, "exec-out", "screencap", "-p"]
print(f"  Command: {' '.join(cmd)}")

result = subprocess.run(cmd, capture_output=True, timeout=10)
print(f"  Return code: {result.returncode}")
print(f"  Stdout size: {len(result.stdout)} bytes")

if result.stderr:
    stderr_text = result.stderr.decode('utf-8', errors='replace')
    print(f"  Stderr: {stderr_text}")

if result.returncode != 0:
    print("  ✗ Screenshot capture failed!")
    sys.exit(1)

if len(result.stdout) < 1000:
    print(f"  ✗ Screenshot data too small: {len(result.stdout)} bytes")
    sys.exit(1)

# Check PNG header
is_png = result.stdout[:8] == b'\x89PNG\r\n\x1a\n'
print(f"  Valid PNG header: {is_png}")
print(f"  First 20 bytes: {result.stdout[:20]}")

if not is_png:
    print("  ✗ Not valid PNG data!")
    sys.exit(1)

# Save to file
output_file = "test_screenshot_direct.png"
with open(output_file, 'wb') as f:
    f.write(result.stdout)

print(f"  ✓ Screenshot saved: {output_file}")
print(f"  ✓ Size: {len(result.stdout)} bytes")
print()

print("=" * 60)
print("ALL TESTS PASSED ✓")
print("Screenshot capture is working correctly!")
print("=" * 60)
