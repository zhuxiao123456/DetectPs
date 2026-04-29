param(
    [string]$BuildDir = "src\rasp_mod_amsi\build-codex",
    [string]$Configuration = "Release",
    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

function Step($Message) {
    Write-Host "[phase3-session] $Message"
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not $SkipConfigure) {
    Step "configure"
    cmake -S src\rasp_mod_amsi -B $BuildDir -G "Visual Studio 17 2022" -A x64
}

Step "build tests and DLL"
cmake --build $BuildDir --config $Configuration --target session_context_cache_tests script_input_normalizer_tests engine_runtime_tests scan_budget_tests async_event_queue_tests rasp_mod_amsi

Step "run session_context_cache_tests"
& ".\$BuildDir\$Configuration\session_context_cache_tests.exe"

Step "run script_input_normalizer_tests"
& ".\$BuildDir\$Configuration\script_input_normalizer_tests.exe"

Step "run engine_runtime_tests"
& ".\$BuildDir\$Configuration\engine_runtime_tests.exe"

Step "run scan_budget_tests"
& ".\$BuildDir\$Configuration\scan_budget_tests.exe"

Step "run async_event_queue_tests"
& ".\$BuildDir\$Configuration\async_event_queue_tests.exe"

Step "static session-context boundary checks"
$sessionFiles = @(
    "src\rasp_mod_amsi\include\script_session_context_cache.h",
    "src\rasp_mod_amsi\src\script_session_context_cache.cpp"
)

$required = @(
    "ScriptSessionContextCache",
    "ScriptSessionKey",
    "SessionKeyConfidence",
    "SessionContextView",
    "SessionContextCacheConfig",
    "UpdateAndBuildView",
    "CloseSession",
    "Clear",
    "CachedBytes",
    "SessionCount",
    "/*<rasp_truncated>*/"
)

foreach ($pattern in $required) {
    $hit = Select-String -Path $sessionFiles -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hit) {
        throw "Required phase3 session pattern missing: $pattern"
    }
}

$forbidden = @(
    "IAmsiStream",
    "IAntimalwareProvider",
    "RuleSnapshot",
    "lua_State",
    "pcre2",
    "rasp_sentry_rules",
    "rasp_sentry_events",
    "rasp_sentry_config",
    "CreateNamedPipe",
    "ConnectNamedPipe",
    "EDR",
    "SQL",
    "database"
)

foreach ($pattern in $forbidden) {
    $hit = Select-String -Path $sessionFiles -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
    if ($hit) {
        $hit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
        throw "Forbidden phase3 session dependency found: $pattern"
    }
}

Step "passed"
