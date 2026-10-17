<#
.SYNOPSIS
    TrustShield Multi-Service Orchestrator.
    Builds fat jars once and launches microservices as background processes with java -jar.

.DESCRIPTION
    Replaces multiple "mvn spring-boot:run" windows with a single, manageable runner.
    Supports building, starting, stopping, and inspecting service health across:
      - 8080 : trustshield-gateway
      - 8083 : trustshield-phishing-service
      - 8084 : trustshield-breach-service
      - 8085 : trustshield-deepfake-service
      - 8086 : trustshield-fakenews-service
      - 8087 : trustshield-integrity-service
      - 8088 : trustshield-fusion-service
      - 8089 : trustshield-bot-service

.PARAMETER Build
    Runs 'mvn clean package -DskipTests' prior to starting services.

.PARAMETER Stop
    Gracefully stops all running TrustShield microservice processes.

.PARAMETER Status
    Displays the health and process status of all TrustShield services.

.PARAMETER NoWait
    Do not wait for health check endpoints to become responsive after launch.

.EXAMPLE
    .\scripts\run-all.ps1 -Build
    .\scripts\run-all.ps1 -Status
    .\scripts\run-all.ps1 -Stop
#>

[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Stop,
    [switch]$Status,
    [switch]$NoWait,
    [switch]$Watch
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$PidFile = Join-Path $RepoRoot ".run-all-pids.json"
$LogsDir = Join-Path $RepoRoot "logs"

if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
}

$Services = @(
    @{ Name = "trustshield-gateway";          Port = 8080; Module = "trustshield-gateway";          Jar = "trustshield-gateway\target\trustshield-gateway-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-phishing-service"; Port = 8083; Module = "trustshield-phishing-service"; Jar = "trustshield-phishing-service\target\trustshield-phishing-service-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-breach-service";   Port = 8084; Module = "trustshield-breach-service";   Jar = "trustshield-breach-service\target\trustshield-breach-service-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-deepfake-service"; Port = 8085; Module = "trustshield-deepfake-service"; Jar = "trustshield-deepfake-service\target\trustshield-deepfake-service-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-fakenews-service"; Port = 8086; Module = "trustshield-fakenews-service"; Jar = "trustshield-fakenews-service\target\trustshield-fakenews-service-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-integrity-service";Port = 8087; Module = "trustshield-integrity-service";Jar = "trustshield-integrity-service\target\trustshield-integrity-service-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-fusion-service";   Port = 8088; Module = "trustshield-fusion-service";   Jar = "trustshield-fusion-service\target\trustshield-fusion-service-1.0.0-SNAPSHOT.jar" },
    @{ Name = "trustshield-bot-service";      Port = 8089; Module = "trustshield-bot-service";      Jar = "trustshield-bot-service\target\trustshield-bot-service-1.0.0-SNAPSHOT.jar" }
)

function Test-PortOpen([int]$port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect("127.0.0.1", $port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne(500, $false)
        if ($success) {
            $client.EndConnect($async)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

function Get-PidMap {
    $map = @{}
    if (Test-Path $PidFile) {
        try {
            $raw = Get-Content $PidFile -Raw
            if ($raw -and $raw.Trim()) {
                $obj = $raw | ConvertFrom-Json
                if ($obj) {
                    foreach ($prop in $obj.PSObject.Properties) {
                        $map[$prop.Name] = $prop.Value
                    }
                }
            }
        } catch {}
    }
    return $map
}

function Show-Status {
    Write-Host "`n=== TrustShield Services Status ===" -ForegroundColor Cyan
    $activePids = Get-PidMap

    $results = @()
    foreach ($svc in $Services) {
        $name = $svc.Name
        $port = $svc.Port
        $jarExists = Test-Path (Join-Path $RepoRoot $svc.Jar)
        $isListening = Test-PortOpen $port
        $pidVal = $activePids[$name]

        $statusStr = "NOT RUNNING"
        if ($isListening) {
            $statusStr = "LISTENING (Port $port)"
        } elseif (-not $jarExists) {
            $statusStr = "JAR NOT BUILT"
        }

        $results += [PSCustomObject]@{
            Service = $name
            Port    = $port
            Status  = $statusStr
            PID     = if ($pidVal) { $pidVal } else { "-" }
            Built   = if ($jarExists) { "Yes" } else { "No" }
        }
    }
    $results | Format-Table -AutoSize
}

if ($Stop) {
    Write-Host "`n[Stopping TrustShield services]..." -ForegroundColor Yellow
    $activePids = Get-PidMap
    if ($activePids.Count -gt 0) {
        foreach ($key in $activePids.Keys) {
            $targetPid = $activePids[$key]
            if ($targetPid) {
                try {
                    $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
                    if ($p) {
                        Write-Host "  Stopping $key (PID: $targetPid)..."
                        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }

    # Additional cleanup: check any process bound to the ports
    foreach ($svc in $Services) {
        $port = $svc.Port
        try {
            $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
            foreach ($conn in $connections) {
                if ($conn.OwningProcess -and $conn.OwningProcess -ne 0) {
                    Write-Host "  Stopping process $($conn.OwningProcess) bound to port $port..."
                    Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }

    Write-Host "All registered TrustShield processes stopped." -ForegroundColor Green
    Show-Status
    exit 0
}

if ($Status) {
    Show-Status
    exit 0
}

if ($Build) {
    Write-Host "`n[Building client packages: verdict-core & web-console]..." -ForegroundColor Cyan
    Push-Location (Join-Path $RepoRoot "packages\verdict-core")
    try {
        npm run build
    } catch {
        Write-Warning "verdict-core build encountered an issue: $_"
    } finally {
        Pop-Location
    }

    Push-Location (Join-Path $RepoRoot "packages\web-console")
    try {
        npm run build
        $staticTarget = Join-Path $RepoRoot "trustshield-gateway\src\main\resources\static"
        if (-not (Test-Path $staticTarget)) {
            New-Item -ItemType Directory -Force -Path $staticTarget | Out-Null
        }
        Copy-Item -Recurse -Force dist/* $staticTarget/
    } catch {
        Write-Warning "web-console build encountered an issue: $_"
    } finally {
        Pop-Location
    }

    Write-Host "`n[Building all available modules with Maven]..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & mvn clean package -DskipTests
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Maven build failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
    } finally {
        Pop-Location
    }
    Write-Host "Build complete.`n" -ForegroundColor Green
}

# Start available services
Write-Host "`n[Launching TrustShield Microservices]..." -ForegroundColor Cyan
$runningPids = Get-PidMap

$startedCount = 0
foreach ($svc in $Services) {
    $name = $svc.Name
    $port = $svc.Port
    $jarRelPath = $svc.Jar
    $jarFullPath = Join-Path $RepoRoot $jarRelPath

    if (-not (Test-Path $jarFullPath)) {
        Write-Host "  [-] $name : jar not found at $jarRelPath (skipping)" -ForegroundColor DarkGray
        continue
    }

    if (Test-PortOpen $port) {
        Write-Host "  [~] $name : already listening on port $port" -ForegroundColor Yellow
        continue
    }

    $logFile = Join-Path $LogsDir "$name.log"
    $errFile = Join-Path $LogsDir "$name-err.log"
    Write-Host "  [+] Starting $name on port $port -> log: logs/$name.log" -ForegroundColor Green

    $proc = Start-Process -FilePath "java" `
        -ArgumentList "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-Dserver.port=$port", "-jar", "`"$jarFullPath`"" `
        -RedirectStandardOutput $logFile `
        -RedirectStandardError $errFile `
        -WorkingDirectory $RepoRoot `
        -WindowStyle Hidden `
        -PassThru

    if ($proc) {
        $runningPids[$name] = $proc.Id
    }
    $startedCount++
}

if (-not $NoWait -and $startedCount -gt 0) {
    $timeoutSeconds = 60
    Write-Host "`nWaiting for all services to become healthy (timeout: ${timeoutSeconds}s)..." -ForegroundColor Cyan
    $startTime = Get-Date

    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($svc in $Services) {
        if (Test-Path (Join-Path $RepoRoot $svc.Jar)) {
            $pending.Add($svc)
        }
    }

    while ($pending.Count -gt 0 -and ((Get-Date) - $startTime).TotalSeconds -lt $timeoutSeconds) {
        for ($i = $pending.Count - 1; $i -ge 0; $i--) {
            $svc = $pending[$i]
            if (Test-PortOpen $svc.Port) {
                Write-Host "  [OK] $($svc.Name) ready on port $($svc.Port)" -ForegroundColor Green
                $pending.RemoveAt($i)
            }
        }
        if ($pending.Count -gt 0) {
            Start-Sleep -Seconds 1
        }
    }

    foreach ($svc in $pending) {
        Write-Host "  [WARN] $($svc.Name) did not open port $($svc.Port) within ${timeoutSeconds}s (check logs/$($svc.Name).log)" -ForegroundColor Red
    }
}

$runningPids | ConvertTo-Json | Set-Content $PidFile -Encoding UTF8

Show-Status
Write-Host "`nUse '.\scripts\run-all.ps1 -Stop' to terminate all background services.`n" -ForegroundColor Cyan

if ($Watch) {
    Write-Host "[Supervisor Mode] Monitoring active services. Press Ctrl+C to stop.`n" -ForegroundColor Green
    try {
        while ($true) {
            Start-Sleep -Seconds 5
        }
    } finally {
        Write-Host "`nExiting supervisor..." -ForegroundColor Yellow
    }
}
