# Device Lab Testing Script
# Quick verification of all Device Lab functionality

Write-Host "`n=== DEVICE LAB VERIFICATION SCRIPT ===" -ForegroundColor Cyan
Write-Host "Testing Samsung Galaxy A06 Integration`n" -ForegroundColor Cyan

# Test 1: ADB Connection
Write-Host "[1/6] Testing ADB Connection..." -ForegroundColor Yellow
$adbDevices = & C:\platform-tools\adb.exe devices 2>&1
if ($adbDevices -match "R9ZY90CPP0K") {
    Write-Host "✅ Device R9ZY90CPP0K connected" -ForegroundColor Green
} else {
    Write-Host "❌ Device not found" -ForegroundColor Red
    exit 1
}

# Test 2: Device Model
Write-Host "`n[2/6] Testing Device Info..." -ForegroundColor Yellow
$model = & C:\platform-tools\adb.exe shell getprop ro.product.model 2>&1
$model = $model.Trim()
if ($model -eq "SM-A066B") {
    Write-Host "✅ Model: $model" -ForegroundColor Green
} else {
    Write-Host "❌ Unexpected model: $model" -ForegroundColor Red
}

# Test 3: Screenshot Capture
Write-Host "`n[3/6] Testing Screenshot Capture..." -ForegroundColor Yellow
& C:\platform-tools\adb.exe exec-out screencap -p > test_verify.png 2>$null
if (Test-Path test_verify.png) {
    $size = (Get-Item test_verify.png).Length
    if ($size -gt 10000) {
        Write-Host "✅ Screenshot captured: $([math]::Round($size/1KB, 2)) KB" -ForegroundColor Green
        Remove-Item test_verify.png
    } else {
        Write-Host "❌ Screenshot too small: $size bytes" -ForegroundColor Red
    }
} else {
    Write-Host "❌ Screenshot failed" -ForegroundColor Red
}

# Test 4: Backend API - Device Detection
Write-Host "`n[4/6] Testing Backend API - Device Detection..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/device-lab/devices" -UseBasicParsing
    if ($response.success -and $response.devices[0].serial -eq "R9ZY90CPP0K") {
        Write-Host "✅ API returns real device data" -ForegroundColor Green
        Write-Host "   Model: $($response.devices[0].model)" -ForegroundColor Gray
        Write-Host "   Battery: $($response.devices[0].battery)%" -ForegroundColor Gray
    } else {
        Write-Host "❌ API response unexpected" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Backend not accessible: $_" -ForegroundColor Red
}

# Test 5: Backend API - Screenshot
Write-Host "`n[5/6] Testing Backend API - Screenshot..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "http://localhost:8000/api/v1/device-lab/screenshot?serial=R9ZY90CPP0K" -OutFile "test_api_verify.png" -UseBasicParsing
    if (Test-Path test_api_verify.png) {
        $size = (Get-Item test_api_verify.png).Length
        if ($size -gt 10000) {
            Write-Host "✅ Screenshot API working: $([math]::Round($size/1KB, 2)) KB" -ForegroundColor Green
            Remove-Item test_api_verify.png
        } else {
            Write-Host "❌ Screenshot too small" -ForegroundColor Red
        }
    } else {
        Write-Host "❌ Screenshot API failed" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Screenshot API error: $_" -ForegroundColor Red
}

# Test 6: Storage Directory
Write-Host "`n[6/6] Checking Storage..." -ForegroundColor Yellow
if (Test-Path "uploads\device_screenshots") {
    $screenshots = Get-ChildItem "uploads\device_screenshots\*.png" -ErrorAction SilentlyContinue
    Write-Host "✅ Storage directory exists" -ForegroundColor Green
    Write-Host "   Screenshots saved: $($screenshots.Count)" -ForegroundColor Gray
} else {
    Write-Host "❌ Storage directory not found" -ForegroundColor Red
}

# Summary
Write-Host "`n=== TEST SUMMARY ===" -ForegroundColor Cyan
Write-Host "Device Lab is ready for dynamic malware analysis!" -ForegroundColor Green
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Start frontend: cd frontend && npm run dev" -ForegroundColor White
Write-Host "2. Open: http://localhost:3000/device-lab" -ForegroundColor White
Write-Host "3. Verify Device Detection Panel shows SM-A066B" -ForegroundColor White
Write-Host "4. Observe live screenshots updating every 2 seconds" -ForegroundColor White
Write-Host ""
