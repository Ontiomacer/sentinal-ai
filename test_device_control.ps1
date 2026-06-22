# Device Control Testing Script
# Tests interactive device mirroring functionality

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Device Lab V3 - Interactive Control Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$API_BASE = "http://localhost:8000/api/v1/device-lab"
$DEVICE_SERIAL = "R9ZY90CPP0K"

# Test 1: Device Detection
Write-Host "[TEST 1] Device Detection" -ForegroundColor Yellow
$response = Invoke-RestMethod -Uri "$API_BASE/devices" -Method GET
Write-Host "Connected Devices: $($response.count)" -ForegroundColor Green
if ($response.devices -and $response.devices.Count -gt 0) {
    $device = $response.devices[0]
    Write-Host "  Model: $($device.model)" -ForegroundColor Gray
    Write-Host "  Serial: $($device.serial)" -ForegroundColor Gray
    Write-Host "  Battery: $($device.battery)%" -ForegroundColor Gray
    Write-Host "  Status: $($device.status)" -ForegroundColor Gray
    Write-Host "✓ Device detected successfully" -ForegroundColor Green
} else {
    Write-Host "✗ No device detected" -ForegroundColor Red
    exit 1
}
Write-Host ""

Start-Sleep -Seconds 1

# Test 2: Touch Control - Center Tap
Write-Host "[TEST 2] Touch Control - Center Tap (540, 1170)" -ForegroundColor Yellow
$tapBody = @{
    device_serial = $DEVICE_SERIAL
    x = 540
    y = 1170
} | ConvertTo-Json

try {
    $tapResponse = Invoke-RestMethod -Uri "$API_BASE/control/tap" -Method POST -Body $tapBody -ContentType "application/json"
    if ($tapResponse.success) {
        Write-Host "✓ Tap sent successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Tap failed: $($tapResponse.message)" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

Start-Sleep -Seconds 2

# Test 3: HOME Button
Write-Host "[TEST 3] HOME Button" -ForegroundColor Yellow
$homeBody = @{
    device_serial = $DEVICE_SERIAL
    keycode = "KEYCODE_HOME"
} | ConvertTo-Json

try {
    $homeResponse = Invoke-RestMethod -Uri "$API_BASE/control/key" -Method POST -Body $homeBody -ContentType "application/json"
    if ($homeResponse.success) {
        Write-Host "✓ HOME button sent successfully" -ForegroundColor Green
        Write-Host "  Check device: Should return to home screen" -ForegroundColor Gray
    } else {
        Write-Host "✗ HOME button failed: $($homeResponse.message)" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

Start-Sleep -Seconds 2

# Test 4: BACK Button
Write-Host "[TEST 4] BACK Button" -ForegroundColor Yellow
$backBody = @{
    device_serial = $DEVICE_SERIAL
    keycode = "KEYCODE_BACK"
} | ConvertTo-Json

try {
    $backResponse = Invoke-RestMethod -Uri "$API_BASE/control/key" -Method POST -Body $backBody -ContentType "application/json"
    if ($backResponse.success) {
        Write-Host "✓ BACK button sent successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ BACK button failed: $($backResponse.message)" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

Start-Sleep -Seconds 2

# Test 5: Swipe Gesture (Vertical scroll)
Write-Host "[TEST 5] Swipe Gesture - Vertical Scroll" -ForegroundColor Yellow
$swipeBody = @{
    device_serial = $DEVICE_SERIAL
    x1 = 540
    y1 = 1400
    x2 = 540
    y2 = 400
    duration = 300
} | ConvertTo-Json

try {
    $swipeResponse = Invoke-RestMethod -Uri "$API_BASE/control/swipe" -Method POST -Body $swipeBody -ContentType "application/json"
    if ($swipeResponse.success) {
        Write-Host "✓ Swipe sent successfully" -ForegroundColor Green
        Write-Host "  Check device: Should scroll up" -ForegroundColor Gray
    } else {
        Write-Host "✗ Swipe failed: $($swipeResponse.message)" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

Start-Sleep -Seconds 2

# Test 6: Text Input
Write-Host "[TEST 6] Text Input - 'Hello Device Lab'" -ForegroundColor Yellow
Write-Host "  Note: Open any text field on device first" -ForegroundColor Gray
$textBody = @{
    device_serial = $DEVICE_SERIAL
    text = "Hello Device Lab"
} | ConvertTo-Json

try {
    $textResponse = Invoke-RestMethod -Uri "$API_BASE/control/text" -Method POST -Body $textBody -ContentType "application/json"
    if ($textResponse.success) {
        Write-Host "✓ Text sent successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Text input failed: $($textResponse.message)" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

Start-Sleep -Seconds 2

# Test 7: App Switcher
Write-Host "[TEST 7] App Switcher (RECENTS)" -ForegroundColor Yellow
$recentsBody = @{
    device_serial = $DEVICE_SERIAL
    keycode = "KEYCODE_APP_SWITCH"
} | ConvertTo-Json

try {
    $recentsResponse = Invoke-RestMethod -Uri "$API_BASE/control/key" -Method POST -Body $recentsBody -ContentType "application/json"
    if ($recentsResponse.success) {
        Write-Host "✓ RECENTS sent successfully" -ForegroundColor Green
        Write-Host "  Check device: Should show recent apps" -ForegroundColor Gray
    } else {
        Write-Host "✗ RECENTS failed: $($recentsResponse.message)" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

# Test 8: Screenshot Capture
Write-Host "[TEST 8] Screenshot Capture" -ForegroundColor Yellow
try {
    $screenshotPath = "test_screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').png"
    Invoke-WebRequest -Uri "$API_BASE/screenshot?serial=$DEVICE_SERIAL" -OutFile $screenshotPath
    $fileSize = (Get-Item $screenshotPath).Length
    if ($fileSize -gt 0) {
        Write-Host "✓ Screenshot captured: $screenshotPath" -ForegroundColor Green
        Write-Host "  Size: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor Gray
    } else {
        Write-Host "✗ Screenshot file is empty" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $_" -ForegroundColor Red
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "All interactive control tests completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Open Device Lab in browser: http://localhost:5173/device-lab" -ForegroundColor Gray
Write-Host "2. Verify device is connected and displaying" -ForegroundColor Gray
Write-Host "3. Click on the device screen to test touch" -ForegroundColor Gray
Write-Host "4. Use Android navigation buttons (Back/Home/Recents)" -ForegroundColor Gray
Write-Host "5. Test APK installation and runtime monitoring" -ForegroundColor Gray
Write-Host ""
Write-Host "Interactive mirroring is ready!" -ForegroundColor Green
