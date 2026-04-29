param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
}

Set-Location $RepoRoot

function Check-NoPattern($Path, [string[]]$Patterns, $Message) {
    foreach ($pattern in $Patterns) {
        $hit = Select-String -Path $Path -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        if ($hit) {
            $hit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
            throw "$Message : $pattern"
        }
    }
}

$interfaceFiles = @(
    "src\rasp_rule_engine\include\rule_json_parser.h",
    "src\rasp_rule_engine\include\rule_control_client.h",
    "src\rasp_rule_engine\include\event_submit_client.h",
    "src\rasp_rule_engine\include\diag_logger.h",
    "src\rasp_rule_engine\include\legacy_pipe_transport.h"
)

foreach ($file in $interfaceFiles) {
    if (-not (Test-Path $file)) {
        throw "Required B0 interface header missing: $file"
    }
}

Check-NoPattern $interfaceFiles @(
    "amsi.h",
    "objbase.h",
    "combaseapi.h",
    "IAmsiStream",
    "IAntimalwareProvider",
    "EDR",
    "SQL",
    "database"
) "Forbidden dependency in B0 interface header"

Check-NoPattern "src\rasp_rule_engine\include\rule_json_parser.h" @(
    "CreateNamedPipe",
    "ConnectNamedPipe",
    "rasp_sentry_rules",
    "rasp_sentry_events",
    "rasp_sentry_config",
    "IEventSubmitClient",
    "IDiagLogger",
    "ILegacyPipeTransport"
) "RuleJsonParser boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\rule_control_client.h" @(
    "lua_State",
    "pcre2",
    "IEventSubmitClient"
) "RuleControlClient boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\event_submit_client.h" @(
    "RuleSnapshot",
    "lua_State",
    "pcre2"
) "EventSubmitClient boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\diag_logger.h" @(
    "DetectionAction",
    "ScanStatus",
    "AMSI_RESULT"
) "DiagLogger boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\legacy_pipe_transport.h" @(
    "ControlMessage",
    "RuleSnapshot",
    "DetectionAction",
    "ScanStatus"
) "LegacyPipeTransport boundary violation"

$changed = git diff --name-only -- src/rasp_rule_engine/src/rasp_sentry_base.cpp
if ($changed) {
    throw "B0-1 must not modify rasp_sentry_base.cpp main-path logic"
}

Write-Host "[b0-boundary] passed"
