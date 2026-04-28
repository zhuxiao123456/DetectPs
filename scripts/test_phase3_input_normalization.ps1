param(
    [string]$BuildDir = "src\rasp_mod_amsi\build-codex",
    [string]$Configuration = "Release",
    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

function Step($Message) {
    Write-Host "[phase3-input] $Message"
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not $SkipConfigure) {
    Step "configure"
    cmake -S src\rasp_mod_amsi -B $BuildDir -G "Visual Studio 17 2022" -A x64
}

Step "build tests and DLL"
cmake --build $BuildDir --config $Configuration --target script_input_normalizer_tests engine_runtime_tests scan_budget_tests async_event_queue_tests rasp_mod_amsi

Step "run script_input_normalizer_tests"
& ".\$BuildDir\$Configuration\script_input_normalizer_tests.exe"

Step "run engine_runtime_tests"
& ".\$BuildDir\$Configuration\engine_runtime_tests.exe"

Step "run scan_budget_tests"
& ".\$BuildDir\$Configuration\scan_budget_tests.exe"

Step "run async_event_queue_tests"
& ".\$BuildDir\$Configuration\async_event_queue_tests.exe"

Step "static boundary checks"
$sourceRoots = @(
    "src\rasp_mod_amsi",
    "src\rasp_rule_engine"
)
$sourceFiles = foreach ($sourceRoot in $sourceRoots) {
    if (Test-Path $sourceRoot) {
        Get-ChildItem $sourceRoot -Recurse -Include *.h,*.hpp,*.cpp,*.cxx,*.cc |
            Where-Object { $_.FullName -notmatch "\\third_party\\" -and $_.FullName -notmatch "\\build" }
    }
}

$required = @(
    "ScriptInputNormalizer",
    "NormalizedScriptInput",
    "kMaxNormalizedBodyBytes",
    "kMaxEncodedCommandTokenBytes",
    "SHA-256",
    "/*<rasp_truncated>*/",
    "EncodedCommand"
)

foreach ($pattern in $required) {
    $hit = $sourceFiles | Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hit) {
        throw "Required phase3 input pattern missing: $pattern"
    }
}

$forbidden = @(
    "session_cache",
    "window_scan",
    "event_collector",
    "ALTER TABLE",
    "CREATE TABLE"
)

foreach ($pattern in $forbidden) {
    $hit = $sourceFiles | Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
    if ($hit) {
        $hit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
        throw "Forbidden phase3 input pattern found: $pattern"
    }
}

Step "passed"
