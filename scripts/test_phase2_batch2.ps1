param(
    [string]$Configuration = "Release",
    [string]$BuildDir = "",
    [int]$StressLoops = 100,
    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

function Step($Message) {
    Write-Host ""
    Write-Host "== $Message" -ForegroundColor Cyan
}

function Fail($Message) {
    Write-Host "FAIL: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Checked($Command, $Arguments) {
    Write-Host "+ $Command $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$Command failed with exit code $LASTEXITCODE"
    }
}

function Assert-FileExists($Path, $Description) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Fail "$Description not found: $Path"
    }
}

function Assert-NoSourceMatch($Pattern, $Description) {
    $matches = Get-ChildItem -LiteralPath $SourceRoot -Recurse -File |
        Where-Object { $_.FullName -notlike "*\build-codex\*" -and $_.FullName -notlike "*\build\*" } |
        Select-String -Pattern $Pattern

    if ($matches) {
        Write-Host "Forbidden pattern found for: $Description" -ForegroundColor Red
        $matches | ForEach-Object {
            Write-Host ("  {0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim()) -ForegroundColor Red
        }
        exit 1
    }
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$ModuleRoot = Join-Path $RepoRoot "src\rasp_mod_amsi"
$SourceRoot = $ModuleRoot
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $ModuleRoot "build-codex"
}

$TestExe = Join-Path $BuildDir "$Configuration\engine_runtime_tests.exe"
$DllPath = Join-Path $BuildDir "$Configuration\rasp_mod_amsi.dll"

Step "Phase 2 batch 2 verification context"
Write-Host "RepoRoot      : $RepoRoot"
Write-Host "ModuleRoot    : $ModuleRoot"
Write-Host "BuildDir      : $BuildDir"
Write-Host "Configuration : $Configuration"
Write-Host "StressLoops   : $StressLoops"

if (-not $SkipConfigure) {
    Step "Configure CMake"
    Invoke-Checked "cmake" @(
        "-S", $ModuleRoot,
        "-B", $BuildDir,
        "-G", "Visual Studio 17 2022",
        "-A", "x64",
        "-DFETCHCONTENT_UPDATES_DISCONNECTED=ON",
        "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
    )
}

Step "Build engine_runtime_tests"
Invoke-Checked "cmake" @("--build", $BuildDir, "--config", $Configuration, "--target", "engine_runtime_tests")
Assert-FileExists $TestExe "engine_runtime_tests.exe"

Step "Build rasp_mod_amsi.dll"
Invoke-Checked "cmake" @("--build", $BuildDir, "--config", $Configuration, "--target", "rasp_mod_amsi")
Assert-FileExists $DllPath "rasp_mod_amsi.dll"

Step "Run engine_runtime_tests once"
Invoke-Checked $TestExe @()

Step "Run engine_runtime_tests stress loop"
for ($i = 1; $i -le $StressLoops; $i++) {
    & $TestExe
    if ($LASTEXITCODE -ne 0) {
        Fail "engine_runtime_tests failed at loop $i with exit code $LASTEXITCODE"
    }
}
Write-Host "Stress loops passed: $StressLoops" -ForegroundColor Green

Step "Static source constraints"
Assert-NoSourceMatch "\bg_engine\b" "global g_engine must not return"
Assert-NoSourceMatch "\bg_unloadInProgress\b" "global unload flag must not return"
Assert-NoSourceMatch "std::atomic\s*<\s*RuleSnapshot\s*\*" "RuleSnapshot must not use atomic raw pointer"
Assert-NoSourceMatch "m_snapshot\.exchange" "snapshot reload must not exchange raw pointers"
Assert-NoSourceMatch "m_snapshot\.load" "snapshot readers must use atomic_load(shared_ptr)"
Assert-NoSourceMatch "delete\s+old" "old snapshots must not be manually deleted"
Assert-NoSourceMatch "delete\s+snapshot" "snapshots must not be manually deleted"
Assert-NoSourceMatch "TerminateThread" "runtime must not force-kill threads"
Assert-NoSourceMatch "std::queue<|concurrent_queue|event_queue|lua_sethook|match_limit|depth_limit|session_cache" "batch 2 must not implement later-scope features"

$runtimeHeader = Get-Content -LiteralPath (Join-Path $ModuleRoot "include\engine_runtime.h") -Raw
foreach ($required in @("class ReloadGuard", "CanAttemptReload", "TryEnterReload", "EmitTelemetry")) {
    if ($runtimeHeader -notmatch [regex]::Escape($required)) {
        Fail "engine_runtime.h missing required API: $required"
    }
}

$runtimeSource = Get-Content -LiteralPath (Join-Path $ModuleRoot "src\engine_runtime.cpp") -Raw
foreach ($required in @("reload_complete_ignored", "reload_begin", "reload_success", "reload_failed", "shutdown_begin")) {
    if ($runtimeSource -notmatch [regex]::Escape($required)) {
        Fail "engine_runtime.cpp missing telemetry/state behavior: $required"
    }
}
if ($runtimeSource -notmatch "m_state != EngineState::Reloading") {
    Fail "Reload completion must ignore non-Reloading states"
}

$ruleSource = Get-Content -LiteralPath (Join-Path $ModuleRoot "src\amsi_rule_engine.cpp") -Raw
foreach ($required in @("CanAttemptReload", "BuildNextSnapshot", "TryEnterReload", "PublishSnapshot", "guard.Complete")) {
    if ($ruleSource -notmatch [regex]::Escape($required)) {
        Fail "OnReloadSignal path missing runtime arbitration piece: $required"
    }
}

$onReload = [regex]::Match($ruleSource, "void\s+AmsiRuleEngine::OnReloadSignal\(\)\s*\{(?<body>.*?)\n\}", "Singleline")
if (-not $onReload.Success) {
    Fail "OnReloadSignal body not found"
}
$body = $onReload.Groups["body"].Value
if ($body -match "std::lock_guard|std::unique_lock") {
    Fail "OnReloadSignal must not hold runtime locks around IPC/parse/precompile"
}

Step "Git diff hygiene"
Invoke-Checked "git" @("-C", $RepoRoot, "diff", "--check")

Write-Host ""
Write-Host "Phase 2 batch 2 verification passed." -ForegroundColor Green
