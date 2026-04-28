param(
    [string]$BuildDir = "src\rasp_mod_amsi\build-codex",
    [string]$Configuration = "Release",
    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

function Step($Message) {
    Write-Host "[phase2-batch4] $Message"
}

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repo

if (-not $SkipConfigure) {
    Step "configure"
    cmake -S src\rasp_mod_amsi -B $BuildDir -G "Visual Studio 17 2022" -A x64
}

Step "build tests and DLL"
cmake --build $BuildDir --config $Configuration --target async_event_queue_tests engine_runtime_tests scan_budget_tests rasp_mod_amsi

Step "run async_event_queue_tests"
& ".\$BuildDir\$Configuration\async_event_queue_tests.exe"

Step "run engine_runtime_tests"
& ".\$BuildDir\$Configuration\engine_runtime_tests.exe"

Step "run scan_budget_tests"
& ".\$BuildDir\$Configuration\scan_budget_tests.exe"

Step "static boundary checks"
$sourceFiles = Get-ChildItem src -Recurse -Include *.h,*.hpp,*.cpp,*.cxx,*.cc |
    Where-Object { $_.FullName -notmatch "\\third_party\\" -and $_.FullName -notmatch "\\build" }

$required = @(
    "enum class EnqueueResult",
    "DroppedQueueFull",
    "DroppedLockContention",
    "DroppedStopping",
    "DroppedTooLarge",
    "AsyncEventSink",
    "SendDetectionEventSyncWorkerOnly",
    "TrySubmitDetectionEvent",
    "maxEventBytes",
    "workerBackoffCount",
    "shutdownFlushTimeoutCount",
    "TruncateUtf8Field"
)

foreach ($pattern in $required) {
    $hit = $sourceFiles | Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $hit) {
        throw "Required batch4 pattern missing: $pattern"
    }
}

$hotPathFiles = @(
    "src\rasp_mod_amsi\src\amsi_rule_engine.cpp",
    "src\rasp_mod_amsi\src\amsi_provider.cpp"
)

foreach ($path in $hotPathFiles) {
    if (Test-Path $path) {
        $syncHit = Select-String -Path $path -Pattern "SendDetectionEventSyncWorkerOnly" -SimpleMatch -ErrorAction SilentlyContinue
        if ($syncHit) {
            $syncHit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
            throw "Scan hot-path file calls worker-only sync sender: $path"
        }
    }
}

$forbidden = @(
    "TerminateThread",
    "std::async",
    "compactJson.resize",
    "session_cache",
    "window_scan"
)

foreach ($pattern in $forbidden) {
    $hit = $sourceFiles | Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
    if ($hit) {
        $hit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
        throw "Forbidden batch4 pattern found: $pattern"
    }
}

Step "passed"
