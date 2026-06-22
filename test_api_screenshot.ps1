# Test screenshot API endpoint
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Screenshot API Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$API_URL = "http://localhost:8000/api/v1/device-lab/screenshot?serial=R9ZY90CPP0K"
$OUTPUT_FILE = "test_screenshot_api.png"

Write-Host "[1] Testing screenshot API endpoint..." -ForegroundColor Yellow
Write-Host "  URL: $API_URL" -ForegroundColor Gray
Write-Host ""

try {
    $response = Invoke-WebRequest -Uri $API_URL -OutFile $OUTPUT_FILE -PassThru
    
    Write-Host "  Status Code: $($response.StatusCode)" -ForegroundColor Green
    Write-Host "  Content Type: $($response.Headers.'Content-Type')" -ForegroundColor Gray
    
    if (Test-Path $OUTPUT_FILE) {
        $fileSize = (Get-Item $OUTPUT_FILE).Length
        Write-Host "  File Size: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor Green
        
        if ($fileSize -gt 1000) {
            Write-Host ""
            Write-Host "✓ Screenshot API working!" -ForegroundColor Green
            Write-Host "✓ Screenshot saved: $OUTPUT_FILE" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "✗ Screenshot file too small: $fileSize bytes" -ForegroundColor Red
        }
    } else {
        Write-Host ""
        Write-Host "✗ Screenshot file not created" -ForegroundColor Red
    }
    
} catch {
    Write-Host ""
    Write-Host "✗ API Error: $_" -ForegroundColor Red
    Write-Host "✗ Is the backend running on port 8000?" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
