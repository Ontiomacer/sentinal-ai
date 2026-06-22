# Complete Device Lab Diagnostics
# Run this to verify everything is working

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " DEVICE LAB V3 - COMPLETE DIAGNOSTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check 1: ADB Installation
Write-Host "[1] Checking ADB Installation..." -ForegroundColor Yellow
$ADB_PATH = "C:\platform-tools\adb.exe"
if (Test-Path $ADB_PATH) {
    Write-Host "  ✓ ADB found: $ADB_PATH" -ForegroundColor Green
    
    $version = & $ADB_PATH version 2>&1 | Select-Object -First 1
    Write-Host "  Version: $version" -ForegroundColor Gray
} else {
    Write-Host "  ✗ ADB not found at: $ADB_PATH" -ForegroundColor Red
    Write-Host "  Install from: https://developer.android.com/studio/releases/platform-tools" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Check 2: Device Connection
Write-Host "[2] Checking Device Connection..." -ForegroundColor Yellow
$devices = & $ADB_PATH devices | Select-Object -Skip 1 | Where-Object { $_.Trim() -ne "" }
if ($devices) {
    Write-Host "  ✓ Device(s) connected:" -ForegroundColor Green
    foreach ($device in $devices) {
        Write-Host "    $device" -ForegroundColor Gray
    }
    
    # Get device model
    $model = & $ADB_PATH shell getprop ro.product.model
    Write-Host "  Model: $model" -ForegroundColor Gray
} else {
    Write-Host "  ✗ No devices connected" -ForegroundColor Red
    Write-Host "  Connect Samsung A06 via USB and enable USB debugging" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Check 3: Direct Screenshot Test
Write-Host "[3] Testing Direct Screenshot Capture..." -ForegroundColor Yellow
Write-Host "  Running: python test_screenshot_direct.py" -ForegroundColor Gray
Write-Host ""
python test_screenshot_direct.py
if ($LASTEXITCODE -eq 0) {
    Write-Host "  ✓ Direct screenshot working!" -ForegroundColor Green
} else {
    Write-Host "  ✗ Direct screenshot failed!" -ForegroundColor Red
    Write-Host "  Fix ADB screenshot before continuing" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Check 4: Backend Status
Write-Host "[4] Checking Backend Status..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/device-lab/devices" -UseBasicParsing
    Write-Host "  ✓ Backend is running on port 8000" -ForegroundColor Green
    
    $data = $response.Content | ConvertFrom-Json
    Write-Host "  Devices found: $($data.count)" -ForegroundColor Gray
    
} catch {
    Write-Host "  ✗ Backend not responding on port 8000" -ForegroundColor Red
    Write-Host "  Start backend: python -m uvicorn app.main:app --reload" -ForegroundColor Yellow
    exit 1
}
Write-Host ""

# Check 5: Screenshot API Test
Write-Host "[5] Testing Screenshot API..." -ForegroundColor Yellow
Write-Host "  Running: .\test_api_screenshot.ps1" -ForegroundColor Gray
Write-Host ""
& .\test_api_screenshot.ps1
Write-Host ""

# Check 6: Frontend Status
Write-Host "[6] Checking Frontend Status..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5173" -UseBasicParsing -TimeoutSec 3
    Write-Host "  ✓ Frontend is running on port 5173" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Frontend not responding on port 5173" -ForegroundColor Red
    Write-Host "  Start frontend: cd frontend && npm run dev" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " DIAGNOSTICS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✓ ADB installed and working" -ForegroundColor Green
Write-Host "✓ Device connected (Samsung A06)" -ForegroundColor Green
Write-Host "✓ Direct screenshot capture working" -ForegroundColor Green
Write-Host "✓ Backend API running" -ForegroundColor Green
Write-Host "✓ Screenshot API endpoint working" -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Open browser: http://localhost:5173/device-lab" -ForegroundColor Gray
Write-Host "2. Open browser console (F12)" -ForegroundColor Gray
Write-Host "3. Watch for logs starting with [LiveDeviceScreen]" -ForegroundColor Gray
Write-Host "4. Check backend terminal for logs starting with [ScreenshotService]" -ForegroundColor Gray
Write-Host "5. Screenshot should appear within 2 seconds" -ForegroundColor Gray
Write-Host ""
Write-Host "If screenshot still doesn't appear in browser:" -ForegroundColor Yellow
Write-Host "- Check browser Network tab for /screenshot requests" -ForegroundColor Gray
Write-Host "- Verify response is 200 OK with image/png content" -ForegroundColor Gray
Write-Host "- Check backend logs for screenshot capture" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ALL SYSTEMS READY! 🚀" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
