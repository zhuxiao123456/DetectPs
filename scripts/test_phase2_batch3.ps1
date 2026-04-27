param(
    [string]$BuildDir = "src\rasp_mod_amsi\build-codex",
    [string]$Configuration = "Release",
    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

function Step($Message) {
    Write-Host "[phase2-batch3] $Message"
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not $SkipConfigure) {
    Step "configure"
    cmake -S src\rasp_mod_amsi -B $BuildDir -G "Visual Studio 17 2022" -A x64
}

Step "build scan_budget_tests"
cmake --build $BuildDir --config $Configuration --target scan_budget_tests

Step "build engine_runtime_tests and rasp_mod_amsi"
cmake --build $BuildDir --config $Configuration --target engine_runtime_tests rasp_mod_amsi

Step "run scan_budget_tests"
& ".\$BuildDir\$Configuration\scan_budget_tests.exe"

Step "run engine_runtime_tests"
& ".\$BuildDir\$Configuration\engine_runtime_tests.exe"

Step "static boundary checks"
$sourceFiles = Get-ChildItem src -Recurse -Include *.h,*.hpp,*.cpp,*.cxx,*.cc
$forbidden = @(
    "TerminateThread",
    "std::async",
    "worker thread timeout",
    "session_cache",
    "window_scan",
    "event_queue"
)

foreach ($pattern in $forbidden) {
    $hit = $sourceFiles | Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
    if ($hit) {
        $hit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
        throw "Forbidden batch3 pattern found: $pattern"
    }
}

$required = @(
    "ScanBudget",
    "ScanDeadline",
    "ScanExecutionContext",
    "lua_sethook",
    "pcre2_set_match_limit",
    "pcre2_set_depth_limit",
    "pcre2_set_heap_limit",
    "maxRegexSubjectBytes",
    "maxRegexCalls",
    "maxRules"
)

foreach ($pattern in $required) {
    $hit = $sourceFiles | Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hit) {
        throw "Required batch3 pattern missing: $pattern"
    }
}

Step "passed"
