param(
    [string]$SentryExe = "D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\rasp_sentry.exe",
    [string]$RulesPath = "D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\config\rasp_rules.json",
    [string]$LogDir = "D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\online_view_logs",
    [string]$StagingDir = "D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\online_view_staging",
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SentryExe)) {
    throw "rasp_sentry.exe not found: $SentryExe"
}
if (-not (Test-Path -LiteralPath $RulesPath)) {
    throw "rules file not found: $RulesPath"
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null

$snapshot = Join-Path $LogDir "rasp-dll-instances.json"
Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $snapshot

Write-Host "Starting rasp_sentry.exe..."
$sentry = Start-Process -FilePath $SentryExe `
    -ArgumentList @("--log", $LogDir, "--rules", $RulesPath, "--staging", $StagingDir) `
    -WindowStyle Hidden `
    -PassThru

try {
    Write-Host ""
    Write-Host "Trigger the real DLL load now, then wait for DLL_LOADED / RULE_LOAD_RESULT."
    Write-Host "Watching: $snapshot"
    Write-Host ""

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $snapshot) {
            $json = Get-Content -Raw -LiteralPath $snapshot | ConvertFrom-Json
            if ($json.onlineDllCount -ge 1 -or $json.historicalLoadedDllCount -ge 1) {
                Write-Host "Snapshot detected."
                Write-Host "onlineDllCount=$($json.onlineDllCount)"
                Write-Host "staleDllCount=$($json.staleDllCount)"
                Write-Host "unloadedDllCount=$($json.unloadedDllCount)"
                Write-Host "historicalLoadedDllCount=$($json.historicalLoadedDllCount)"
                Write-Host "instancesWithRuleLoadResult=$($json.instancesWithRuleLoadResult)"
                Write-Host "instancesWithoutRuleLoadResult=$($json.instancesWithoutRuleLoadResult)"
                Write-Host ""
                $json.instances | Select-Object `
                    instanceId,state,pid,processPath,parentPid,parentProcessPath,ruleLoadSeen,lastRuleVersion |
                    Format-List

                $hardFailures = @()
                if ($json.onlineDllCount -lt 1) {
                    $hardFailures += "onlineDllCount must be >= 1"
                }
                $onlineInstances = @($json.instances | Where-Object { $_.state -eq "Online" })
                if ($onlineInstances.Count -lt 1) {
                    $hardFailures += "at least one instance must be Online"
                }
                if (-not (@($json.instances | Where-Object { $_.ruleLoadSeen -eq $true }).Count -ge 1)) {
                    $hardFailures += "at least one instance must have ruleLoadSeen=true"
                }
                if (-not (@($json.instances | Where-Object { -not [string]::IsNullOrWhiteSpace($_.processPath) }).Count -ge 1)) {
                    $hardFailures += "at least one instance must have non-empty processPath"
                }

                if ($hardFailures.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Hard assertions failed:"
                    $hardFailures | ForEach-Object { Write-Host "  - $_" }
                    exit 2
                }

                Write-Host ""
                Write-Host "Hard assertions passed:"
                Write-Host "  - onlineDllCount >= 1"
                Write-Host "  - at least one Online instance"
                Write-Host "  - at least one ruleLoadSeen=true instance"
                Write-Host "  - at least one non-empty processPath"

                $missingParentPaths = @($json.instances | Where-Object {
                    [string]::IsNullOrWhiteSpace($_.parentProcessPath)
                })
                if ($missingParentPaths.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Soft warning: one or more instances have empty parentProcessPath."
                    Write-Host "This can happen when the parent process exited quickly or access was denied."
                }
                exit 0
            }
        }
        Start-Sleep -Seconds 1
    }

    throw "Timed out waiting for DLL online view snapshot with at least one instance."
}
finally {
    if ($sentry -and -not $sentry.HasExited) {
        Stop-Process -Id $sentry.Id -Force
        $sentry.WaitForExit(3000) | Out-Null
    }
}
