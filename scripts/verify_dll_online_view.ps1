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
