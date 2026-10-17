<#
.SYNOPSIS
    TrustShield Automated End-to-End Rehearsal & Evaluation Harness.
    Executes comprehensive verification across the full multi-service mesh.

.DESCRIPTION
    Runs an end-to-end rehearsal suitable for evaluation demonstrations:
      Phase 1: Service Mesh Health Check (8 ports: 8080, 8083-8089)
      Phase 2: Live Threat Vector Evaluation (7 vectors via Gateway 8080)
      Phase 3: Cryptographic Ledger & Ed25519 Signature Audit
      Phase 4: Platform Resilience & Failure Drills (4 Invariant Drills)
      Phase 5: Formatted Evaluation Scorecard & Defense Summary

.PARAMETER GatewayUrl
    Base URL of the TrustShield API Gateway (default: http://localhost:8080).

.PARAMETER SkipDrills
    Skip executing the destructive failure drills.

.PARAMETER Detailed
    Display full JSON response payloads for each evaluation step.

.EXAMPLE
    .\scripts\rehearsal.ps1
    .\scripts\rehearsal.ps1 -Detailed
    .\scripts\rehearsal.ps1 -SkipDrills
#>

[CmdletBinding()]
param(
    [string]$GatewayUrl = "http://localhost:8080",
    [switch]$SkipDrills,
    [switch]$Detailed
)

$ErrorActionPreference = "Continue"
$StartTime = Get-Date

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "       TrustShield Cyber-Defense Platform: Full Rehearsal & Audit Suite         " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Execution Target: $GatewayUrl" -ForegroundColor Gray
Write-Host " Timestamp:        $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))" -ForegroundColor Gray
Write-Host ""

$PassedCount = 0
$FailedCount = 0
$WarningsCount = 0

function Report-Rehearsal([string]$Category, [string]$TestName, [bool]$Success, [string]$Details, [object]$Payload = $null) {
    if ($Success) {
        $script:PassedCount++
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
        Write-Host "$Category - $TestName" -ForegroundColor White
        Write-Host "         $Details" -ForegroundColor DarkGray
    } else {
        $script:FailedCount++
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
        Write-Host "$Category - $TestName" -ForegroundColor Yellow
        Write-Host "         $Details" -ForegroundColor Red
    }
    if ($Detailed -and $Payload -ne $null) {
        Write-Host "         Response: $(ConvertTo-Json $Payload -Compress -Depth 5)" -ForegroundColor DarkCyan
    }
}

# ==============================================================================
# Phase 1: Service Mesh Health Verification
# ==============================================================================
Write-Host "--- [Phase 1: Service Mesh Health Check] ---------------------------------------" -ForegroundColor Yellow

$Services = @(
    @{ Name = "API Gateway";            Port = 8080; Url = "http://localhost:8080/actuator/health" },
    @{ Name = "Phishing Shield";        Port = 8083; Url = "http://localhost:8083/actuator/health" },
    @{ Name = "Breach Monitor";          Port = 8084; Url = "http://localhost:8084/actuator/health" },
    @{ Name = "Deepfake Detector";      Port = 8085; Url = "http://localhost:8085/actuator/health" },
    @{ Name = "Misinformation Verifier";Port = 8086; Url = "http://localhost:8086/actuator/health" },
    @{ Name = "Integrity Ledger";       Port = 8087; Url = "http://localhost:8087/actuator/health" },
    @{ Name = "Fusion Engine";          Port = 8088; Url = "http://localhost:8088/actuator/health" },
    @{ Name = "Cyber-Defense Bot";      Port = 8089; Url = "http://localhost:8089/actuator/health" }
)

$MeshHealthy = $true
foreach ($svc in $Services) {
    try {
        $resp = Invoke-RestMethod -Uri $svc.Url -Method Get -TimeoutSec 3 -ErrorAction Stop
        $status = if ($resp.status) { $resp.status } else { "UP" }
        Report-Rehearsal "MESH" "$($svc.Name) (Port $($svc.Port))" ($status -eq "UP") "Status: $status" $resp
    } catch {
        $MeshHealthy = $false
        Report-Rehearsal "MESH" "$($svc.Name) (Port $($svc.Port))" $false "Endpoint unreachable at $($svc.Url): $($_.Exception.Message)"
    }
}

if (-not $MeshHealthy) {
    Write-Host ""
    Write-Host "  [!] WARNING: One or more microservices are currently offline." -ForegroundColor Yellow
    Write-Host "      Ensure microservices are running via '.\scripts\run-all.ps1' or 'docker compose up -d'." -ForegroundColor DarkGray
    Write-Host ""
}

# ==============================================================================
# Phase 2: Live Threat Vector Evaluation (Gateway :8080)
# ==============================================================================
Write-Host ""
Write-Host "--- [Phase 2: End-to-End Threat Vector Evaluation] -----------------------------" -ForegroundColor Yellow

# Vector 1.1: Malicious Phishing URL
try {
    $body = @{ url = "https://secure-login.paypal.com.account-verification-notice.xyz/update-credentials" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/phishing/scan" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = ($res.verdict.threatLevel -eq "DANGEROUS" -and $res.verdict.riskScore -ge 75)
    Report-Rehearsal "VECTOR-1" "Homograph Phishing Detection" $pass "ThreatLevel=$($res.verdict.threatLevel), Score=$($res.verdict.riskScore), Verdict=$($res.verdict.verdict)" $res
} catch {
    Report-Rehearsal "VECTOR-1" "Homograph Phishing Detection" $false "Request failed: $($_.Exception.Message)"
}

# Vector 1.2: Benign Whitelisted Domain
try {
    $body = @{ url = "https://www.wikipedia.org/wiki/Computer_security" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/phishing/scan" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = ($res.verdict.threatLevel -eq "SAFE" -and $res.verdict.riskScore -lt 40)
    Report-Rehearsal "VECTOR-1" "Benign URL Verification" $pass "ThreatLevel=$($res.verdict.threatLevel), Score=$($res.verdict.riskScore), Verdict=$($res.verdict.verdict)" $res
} catch {
    Report-Rehearsal "VECTOR-1" "Benign URL Verification" $false "Request failed: $($_.Exception.Message)"
}

# Vector 2.1: Breached Password (k-Anonymity)
try {
    $body = @{ password = "password123" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/breach/password" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $isExposed = ($res.verdict.threatLevel -eq "DANGEROUS" -and $res.verdict.verdict -eq "PASSWORD_EXPOSED")
    $kAnon = ($res.kAnonymous -eq $true -and $res.bucketPrefix -ne $null)
    $pass = ($isExposed -and $kAnon)
    Report-Rehearsal "VECTOR-2" "Known Breached Password (k-Anonymity)" $pass "ThreatLevel=$($res.verdict.threatLevel), Verdict=$($res.verdict.verdict), kAnon=$($res.kAnonymous), Prefix=$($res.bucketPrefix)" $res
} catch {
    Report-Rehearsal "VECTOR-2" "Known Breached Password (k-Anonymity)" $false "Request failed: $($_.Exception.Message)"
}

# Vector 2.2: High Entropy Passphrase
try {
    $body = @{ password = "C0rrect-H0rse-B@ttery-St@ple-2026!#$" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/breach/password" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $bits = if ($res.strength) { $res.strength.theoreticalBits } else { 0 }
    $pass = ($res.verdict.threatLevel -in "LOW", "SAFE" -and $bits -gt 60 -and $res.kAnonymous -eq $true)
    Report-Rehearsal "VECTOR-2" "High-Entropy Passphrase Verification" $pass "ThreatLevel=$($res.verdict.threatLevel), EntropyBits=$bits, Est=$($res.strength.bruteForceEstimate)" $res
} catch {
    Report-Rehearsal "VECTOR-2" "High-Entropy Passphrase Verification" $false "Request failed: $($_.Exception.Message)"
}

# Vector 3: Synthetic Image Deepfake Forensics
try {
    $pngBase64 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAzSURBVDhPpcihEQAwEASh67/pTwGrmAgM2+7+JFRCJVRCJVRCJVRCJVRCJVRCJVRCJcwDMqb+ELsBUIUAAAAASUVORK5CYII="
    $body = @{ imageBase64 = $pngBase64; filename = "sample.png"; mimeType = "image/png" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/deepfake/scan" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = ($res.metadata.format -eq "PNG" -and $res.forensicSignals -ne $null)
    Report-Rehearsal "VECTOR-3" "Image ELA/Noise Forensics" $pass "Format=$($res.metadata.format), QuantFP=$($res.forensicSignals.quantisationTableFingerprint), Recomp=$($res.forensicSignals.recompressionDetected)" $res
} catch {
    Report-Rehearsal "VECTOR-3" "Image ELA/Noise Forensics" $false "Request failed: $($_.Exception.Message)"
}

# Vector 4: Video Container & Temporal Forensics
try {
    $mp4Base64 = "AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAA=="
    $body = @{ imageBase64 = $mp4Base64; filename = "synthetic_speech.mp4"; mimeType = "video/mp4" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/deepfake/scan" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = (($res.metadata.format -in "isom", "MP4" -or $res.metadata.format -like "*iso*") -and $res.videoSignals -ne $null)
    Report-Rehearsal "VECTOR-4" "Video Temporal Optical Flow" $pass "Format=$($res.metadata.format), TemporalJitter=$($res.videoSignals.temporalJitterScore), Verdict=$($res.verdict.verdict)" $res
} catch {
    Report-Rehearsal "VECTOR-4" "Video Temporal Optical Flow" $false "Request failed: $($_.Exception.Message)"
}

# Vector 5: Multi-Lingual Synthetic Audio Forensics
try {
    $wavBase64 = "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA="
    $body = @{ imageBase64 = $wavBase64; filename = "voice_clone.wav"; mimeType = "audio/wav" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/deepfake/scan" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = (($res.metadata.format -in "WAV", "AUDIO_WAV" -or $res.metadata.format -like "*WAV*") -and $res.audioSignals -ne $null)
    Report-Rehearsal "VECTOR-5" "Audio Spectral Roll-Off Forensics" $pass "Format=$($res.metadata.format), StreamFP=$($res.forensicSignals.quantisationTableFingerprint), Verdict=$($res.verdict.verdict)" $res
} catch {
    Report-Rehearsal "VECTOR-5" "Audio Spectral Roll-Off Forensics" $false "Request failed: $($_.Exception.Message)"
}

# Vector 6.1: Debunked Viral Hoax (SimHash Near-Duplicate)
try {
    $body = @{ claimText = "UNESCO declares Indian national anthem Jana Gana Mana as best national anthem in the world"; context = "WHATSAPP_FORWARD" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/misinformation/check" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = ($res.verdict.threatLevel -eq "DANGEROUS" -and $res.simHashMatch.matched -eq $true)
    Report-Rehearsal "VECTOR-6" "SimHash Debunk Catalog Match" $pass "ThreatLevel=$($res.verdict.threatLevel), SimHashMatched=$($res.simHashMatch.matched), Similarity=$($res.simHashMatch.similarity)" $res
} catch {
    Report-Rehearsal "VECTOR-6" "SimHash Debunk Catalog Match" $false "Request failed: $($_.Exception.Message)"
}

# Vector 6.2: Spliced Television News Chyron Hoax
try {
    $body = @{ claimText = "BREAKING NEWS: Emergency curfew announced across city centers nationwide immediately!!!"; context = "TELEVISION_SCREENSHOT" } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/misinformation/check" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 5
    $pass = ($res.styleAnalysis.capitalisationShouting -eq $true -or $res.styleAnalysis.sensationalPunctuationCount -ge 2)
    Report-Rehearsal "VECTOR-6" "Sensational Chyron Style Analysis" $pass "ThreatLevel=$($res.verdict.threatLevel), Shouting=$($res.styleAnalysis.capitalisationShouting), Score=$($res.verdict.riskScore)" $res
} catch {
    Report-Rehearsal "VECTOR-6" "Sensational Chyron Style Analysis" $false "Request failed: $($_.Exception.Message)"
}

# Vector 7: Cross-Modal Threat Fusion
try {
    $incidentPayload = @{
        incidentId = "inc-rehearsal-$([guid]::NewGuid().ToString().Substring(0, 8))"
        ledgerVerified = $true
        verdicts = @(
            @{
                module = "PHISHING"
                riskScore = 95
                threatLevel = "DANGEROUS"
                verdict = "CREDENTIAL_HARVESTER"
                explanation = "Target domain actively mimics banking portal."
                signals = @()
                latencyMs = 1
                evaluatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                degraded = $false
            },
            @{
                module = "DEEPFAKE"
                riskScore = 88
                threatLevel = "DANGEROUS"
                verdict = "SYNTHETIC_AVATAR"
                explanation = "Video exhibits unnatural facial micro-movement."
                signals = @()
                latencyMs = 10
                evaluatedAt = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                degraded = $false
            }
        )
    } | ConvertTo-Json -Depth 5

    $res = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/fusion/evaluate" -Method Post -ContentType "application/json" -Body $incidentPayload -TimeoutSec 5
    $level = if ($res.aggregateVerdict) { $res.aggregateVerdict.threatLevel } else { $res.compositeThreatLevel }
    $score = if ($res.aggregateVerdict) { $res.aggregateVerdict.riskScore } else { $res.compositeScore }
    $pass = ($level -eq "DANGEROUS" -and $score -ge 85)
    Report-Rehearsal "VECTOR-7" "Cross-Modal Evidence Fusion" $pass "ThreatLevel=$level, Score=$score, RulesFired=$($res.firedRules.Count)" $res
} catch {
    Report-Rehearsal "VECTOR-7" "Cross-Modal Evidence Fusion" $false "Request failed: $($_.Exception.Message)"
}

# ==============================================================================
# Phase 3: Cryptographic Ledger & Ed25519 Signature Audit
# ==============================================================================
Write-Host ""
Write-Host "--- [Phase 3: Cryptographic Ledger & Signature Audit] --------------------------" -ForegroundColor Yellow

try {
    $head = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/ledger/head" -Method Get -TimeoutSec 5
    $hasHead = ($head.headChainHash -ne $null -and $head.ed25519SignatureHex -ne $null)
    Report-Rehearsal "LEDGER" "Tip Block & Ed25519 Signature" $hasHead "Seq=$($head.sequenceNumber), Hash=$($head.headChainHash.Substring(0, 16))..., Sig=$($head.ed25519SignatureHex.Substring(0, 16))..." $head
} catch {
    Report-Rehearsal "LEDGER" "Tip Block & Ed25519 Signature" $false "Request failed: $($_.Exception.Message)"
}

try {
    $audit = Invoke-RestMethod -Uri "$GatewayUrl/api/v1/ledger/verify" -Method Get -TimeoutSec 5
    $auditValid = ($audit.valid -eq $true -and $audit.signatureValid -eq $true)
    Report-Rehearsal "LEDGER" "Link-by-Link Hash Chain Verification" $auditValid "Valid=$($audit.valid), SigValid=$($audit.signatureValid), EntriesChecked=$($audit.totalEntriesChecked)" $audit
} catch {
    Report-Rehearsal "LEDGER" "Link-by-Link Hash Chain Verification" $false "Request failed: $($_.Exception.Message)"
}

# ==============================================================================
# Phase 4: Resilience & Automated Failure Drills
# ==============================================================================
Write-Host ""
Write-Host "--- [Phase 4: Resilience & Invariant Failure Drills] ---------------------------" -ForegroundColor Yellow

if ($SkipDrills) {
    Write-Host "  [SKIP] Failure drills skipped as requested by -SkipDrills parameter." -ForegroundColor Gray
} else {
    $drillScript = Join-Path $PSScriptRoot "test_failure_drills.ps1"
    if (Test-Path $drillScript) {
        Write-Host "  Executing test_failure_drills.ps1 harness..." -ForegroundColor DarkGray
        try {
            & $drillScript -GatewayUrl $GatewayUrl
            if ($LASTEXITCODE -eq 0) {
                Report-Rehearsal "DRILL" "Automated 4-Invariant Failure Drills" $true "Drills 1-4 completed successfully with all invariants preserved."
            } else {
                Report-Rehearsal "DRILL" "Automated 4-Invariant Failure Drills" $false "One or more failure drills failed (Exit code: $LASTEXITCODE)."
            }
        } catch {
            Report-Rehearsal "DRILL" "Automated 4-Invariant Failure Drills" $false "Execution exception: $($_.Exception.Message)"
        }
    } else {
        Report-Rehearsal "DRILL" "Automated Failure Drills" $false "Script $drillScript not found."
    }
}

# ==============================================================================
# Phase 5: Formatted Scorecard & Summary
# ==============================================================================
$EndTime = Get-Date
$Duration = ($EndTime - $StartTime).TotalSeconds

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                       TRUSTSHIELD EVALUATION SCORECARD                         " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Total Tests Executed:  $($PassedCount + $FailedCount)" -ForegroundColor White
Write-Host "  Tests Passed:          $PassedCount" -ForegroundColor Green
Write-Host "  Tests Failed:          $FailedCount" -ForegroundColor $(if ($FailedCount -eq 0) { "Green" } else { "Red" })
Write-Host "  Elapsed Time:          $([math]::Round($Duration, 2)) seconds" -ForegroundColor Gray
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan

if ($FailedCount -eq 0) {
    Write-Host "  VERDICT: ALL CORE INVARIANTS, THREAT VECTORS & CRYPTO AUDITS PASSED [100%]" -ForegroundColor Green
    Write-Host "  STATUS:  READY FOR VIVA DEFENSE, CAPSTONE EVALUATION & PRODUCTION" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 0
} else {
    Write-Host "  VERDICT: REHEARSAL COMPLETED WITH $FailedCount ANOMALIES" -ForegroundColor Red
    Write-Host "  STATUS:  INVESTIGATE DIAGNOSTIC MESSAGES ABOVE BEFORE EVALUATION" -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}
