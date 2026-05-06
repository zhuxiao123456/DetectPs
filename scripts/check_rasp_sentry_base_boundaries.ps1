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

function Check-NoStrongPattern($Path, [string[]]$Patterns, $Message) {
    if (-not (Test-Path $Path)) {
        return
    }

    $lines = Get-Content $Path
    $inBlockComment = $false
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        $trim = $line.Trim()

        if ($inBlockComment) {
            if ($trim.Contains("*/")) {
                $inBlockComment = $false
            }
            continue
        }

        if ($trim.StartsWith("//")) {
            continue
        }
        if ($trim.StartsWith("/*")) {
            if (-not $trim.Contains("*/")) {
                $inBlockComment = $true
            }
            continue
        }

        $code = $line
        $lineComment = $code.IndexOf("//")
        if ($lineComment -ge 0) {
            $code = $code.Substring(0, $lineComment)
        }

        foreach ($pattern in $Patterns) {
            if ($code.Contains($pattern)) {
                Write-Host ("{0}:{1} {2}" -f $Path, ($i + 1), $line)
                throw "$Message : $pattern"
            }
        }
    }
}

function Write-WeakPatternWarnings($Path, [string[]]$Patterns, $Message) {
    if (-not (Test-Path $Path)) {
        return
    }

    foreach ($pattern in $Patterns) {
        $hit = Select-String -Path $Path -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        if ($hit) {
            $hit | ForEach-Object {
                Write-Warning ("{0}: {1}:{2} {3}" -f $Message, $_.Path, $_.LineNumber, $_.Line)
            }
        }
    }
}

$interfaceFiles = @(
    "src\rasp_rule_engine\include\rule_json_parser.h",
    "src\rasp_rule_engine\include\rule_control_client.h",
    "src\rasp_rule_engine\include\event_submit_client.h",
    "src\rasp_rule_engine\include\event_transport.h",
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
    "pcre2",
    "RaspLuaEngine",
    "EngineRuntime",
    "IAmsiStream",
    "AMSI_RESULT",
    "CreateNamedPipe",
    "ConnectNamedPipe",
    "WaitNamedPipe",
    "CreateFileW",
    "WriteFile"
) "EventSubmitClient boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\event_transport.h" @(
    "RuleSnapshot",
    "RaspEvalResult",
    "AsyncEvent",
    "DetectionEventLite",
    "lua_State",
    "pcre2",
    "RaspLuaEngine",
    "EngineRuntime",
    "IAmsiStream",
    "AMSI_RESULT",
    "CreateNamedPipe",
    "ConnectNamedPipe",
    "WaitNamedPipe",
    "CreateFileW",
    "WriteFile"
) "EventTransport boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\diag_logger.h" @(
    "DetectionAction",
    "ScanStatus",
    "AMSI_RESULT",
    "RuleSnapshot",
    "lua_State",
    "pcre2",
    "RaspLuaEngine",
    "IAmsiStream"
) "DiagLogger boundary violation"

Check-NoPattern "src\rasp_rule_engine\include\legacy_pipe_transport.h" @(
    "ControlMessage",
    "RuleSnapshot",
    "DetectionAction",
    "ScanStatus",
    "EDR",
    "SQL",
    "database"
) "LegacyPipeTransport boundary violation"

Check-NoStrongPattern "src\rasp_rule_engine\include\legacy_pipe_transport.h" @(
    "Reload",
    "Unload",
    "DetectionEvent",
    "DrainAck",
    "ConfigUpdate",
    "FetchRules",
    "SubmitDetection"
) "LegacyPipeTransport public seam must not expose business semantics"

Write-WeakPatternWarnings "src\rasp_rule_engine\include\legacy_pipe_transport.h" @(
    "Reload",
    "Unload",
    "DetectionEvent",
    "DrainAck",
    "ConfigUpdate",
    "FetchRules",
    "SubmitDetection"
) "LegacyPipeTransport business term appears in comments or docs; review manually"

Check-NoPattern "src\rasp_rule_engine\include\rule_control_client.h" @(
    "RuleSnapshotPayload"
) "RuleControlClient naming should avoid compiled RuleSnapshot confusion"

if (Test-Path "src\rasp_rule_engine\src\rule_json_parser.cpp") {
    Check-NoPattern "src\rasp_rule_engine\src\rule_json_parser.cpp" @(
        "Log(",
        "SendDetectionEvent",
        "ConnectSentry",
        "CreateNamedPipe",
        "ConnectNamedPipe",
        "rasp_sentry_rules",
        "rasp_sentry_events",
        "rasp_sentry_config",
        "EngineRuntime",
        "IAmsiStream",
        "windows.h",
        "amsi.h"
    ) "RuleJsonParser implementation boundary violation"
}

if (Test-Path "src\rasp_rule_engine\src\event_submit_client.cpp") {
    Check-NoPattern "src\rasp_rule_engine\src\event_submit_client.cpp" @(
        "RuleSnapshot",
        "lua_State",
        "pcre2",
        "RaspLuaEngine",
        "EngineRuntime",
        "IAmsiStream",
        "AMSI_RESULT",
        "CreateNamedPipe",
        "ConnectNamedPipe",
        "WaitNamedPipe",
        "CreateFileW",
        "WriteFile"
    ) "EventSubmitClient implementation boundary violation"
}

if (Test-Path "src\rasp_rule_engine\src\event_transport.cpp") {
    Check-NoPattern "src\rasp_rule_engine\src\event_transport.cpp" @(
        "RuleSnapshot",
        "RaspEvalResult",
        "AsyncEvent",
        "DetectionEventLite",
        "lua_State",
        "pcre2",
        "RaspLuaEngine",
        "EngineRuntime",
        "IAmsiStream",
        "AMSI_RESULT",
        "CreateNamedPipe",
        "ConnectNamedPipe",
        "WaitNamedPipe",
        "CreateFileW",
        "WriteFile"
    ) "EventTransport implementation boundary violation"
}

if (Test-Path "src\rasp_rule_engine\src\diag_logger.cpp") {
    Check-NoPattern "src\rasp_rule_engine\src\diag_logger.cpp" @(
        "DetectionAction",
        "ScanStatus",
        "AMSI_RESULT",
        "RuleSnapshot",
        "lua_State",
        "pcre2",
        "RaspLuaEngine",
        "IAmsiStream"
    ) "DiagLogger implementation boundary violation"
}

if (Test-Path "src\rasp_rule_engine\src\legacy_pipe_transport.cpp") {
    Check-NoStrongPattern "src\rasp_rule_engine\src\legacy_pipe_transport.cpp" @(
        "Reload",
        "Unload",
        "RuleSnapshot",
        "DetectionEvent",
        "DrainAck",
        "ConfigUpdate",
        "FetchRules",
        "SubmitDetection"
    ) "LegacyPipeTransport implementation must not expose business semantics"
    Check-NoPattern "src\rasp_rule_engine\src\legacy_pipe_transport.cpp" @(
        "EDR",
        "SQL",
        "database"
    ) "LegacyPipeTransport implementation boundary violation"
}

if (Test-Path "src\rasp_rule_engine\include\legacy_pipe_event_transport.h") {
    Check-NoPattern "src\rasp_rule_engine\include\legacy_pipe_event_transport.h" @(
        "RaspEvalResult",
        "AsyncEvent",
        "DetectionEventLite",
        "RuleSnapshot",
        "lua_State",
        "pcre2",
        "RaspLuaEngine",
        "EngineRuntime",
        "AMSI_RESULT",
        "EDR",
        "SQL",
        "database"
    ) "LegacyPipeEventTransport header boundary violation"
    Check-NoStrongPattern "src\rasp_rule_engine\include\legacy_pipe_event_transport.h" @(
        "Reload",
        "Unload",
        "DetectionEvent",
        "DrainAck",
        "ConfigUpdate"
    ) "LegacyPipeEventTransport header must not expose business semantics"
}

if (Test-Path "src\rasp_rule_engine\src\legacy_pipe_event_transport.cpp") {
    Check-NoPattern "src\rasp_rule_engine\src\legacy_pipe_event_transport.cpp" @(
        "RaspEvalResult",
        "AsyncEvent",
        "DetectionEventLite",
        "RuleSnapshot",
        "lua_State",
        "pcre2",
        "RaspLuaEngine",
        "EngineRuntime",
        "AMSI_RESULT",
        "EDR",
        "SQL",
        "database"
    ) "LegacyPipeEventTransport implementation boundary violation"
    Check-NoStrongPattern "src\rasp_rule_engine\src\legacy_pipe_event_transport.cpp" @(
        "Reload",
        "Unload",
        "DetectionEvent",
        "DrainAck",
        "ConfigUpdate"
    ) "LegacyPipeEventTransport implementation must not expose business semantics"
}

Write-Host "[b0-boundary] passed"
