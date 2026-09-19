Add-Type -AssemblyName System.Drawing

$deepfakeProc = Start-Process java -ArgumentList "-Dserver.port=8085", "-jar", "trustshield-deepfake-service\target\trustshield-deepfake-service-1.0.0-SNAPSHOT.jar" -PassThru -WindowStyle Hidden
$gatewayProc = Start-Process java -ArgumentList "-Dserver.port=8080", "-jar", "trustshield-gateway\target\trustshield-gateway-1.0.0-SNAPSHOT.jar" -PassThru -WindowStyle Hidden

try {
    Write-Host "Waiting for ports 8085 and 8080..."
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $r1 = Invoke-RestMethod -Uri "http://localhost:8085/actuator/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            $r2 = Invoke-RestMethod -Uri "http://localhost:8080/actuator/health" -TimeoutSec 1 -ErrorAction SilentlyContinue
            if ($r1.status -eq "UP" -and $r2.status -eq "UP") {
                $ready = $true
                break
            }
        } catch {}
    }

    if (-not $ready) {
        Write-Error "Services did not start within 30 seconds"
        exit 1
    }

    Write-Host "`nBoth services UP and healthy on 8085 and 8080!`n" -ForegroundColor Green

    Write-Host "=== 1. Testing GET /api/v1/deepfake/forensics/info via Gateway (8080) ===" -ForegroundColor Cyan
    $info = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/deepfake/forensics/info"
    $info | ConvertTo-Json -Depth 4 | Write-Host

    Write-Host "`n=== 2. Generating synthetic test image in memory ===" -ForegroundColor Cyan
    $bmp = New-Object System.Drawing.Bitmap 200, 200
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(120, 140, 160))
    $graphics.FillRectangle($brush, 0, 0, 200, 200)
    $brush.Dispose()
    $graphics.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg)
    $b64 = [Convert]::ToBase64String($ms.ToArray())
    $bmp.Dispose()
    $ms.Dispose()

    Write-Host "`n=== 3. Testing POST /api/v1/deepfake/scan via Gateway (8080) ===" -ForegroundColor Cyan
    $body = @{
        imageBase64 = $b64
        filename = "camera_test.jpg"
        mimeType = "image/jpeg"
        context = "WEB_UPLOAD"
    } | ConvertTo-Json

    $scanRes = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/deepfake/scan" -Method Post -Body $body -ContentType "application/json"
    $scanRes | ConvertTo-Json -Depth 5 | Write-Host

    Write-Host "`n=== 4. Testing POST /api/v1/deepfake/scan with WHATSAPP_ATTACHMENT (recompressed -> UNKNOWN) ===" -ForegroundColor Cyan
    $waBody = @{
        imageBase64 = $b64
        filename = "forwarded_sample.jpg"
        mimeType = "image/jpeg"
        context = "WHATSAPP_ATTACHMENT"
    } | ConvertTo-Json

    $waRes = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/deepfake/scan" -Method Post -Body $waBody -ContentType "application/json"
    $waRes | ConvertTo-Json -Depth 5 | Write-Host

    Write-Host "`n=== 5. Testing GET /api/v1/deepfake/stats via Gateway (8080) ===" -ForegroundColor Cyan
    $statsRes = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/deepfake/stats"
    $statsRes | ConvertTo-Json -Depth 3 | Write-Host

} finally {
    Write-Host "`nTerminating test processes..." -ForegroundColor Yellow
    Stop-Process -Id $deepfakeProc.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $gatewayProc.Id -Force -ErrorAction SilentlyContinue
}
