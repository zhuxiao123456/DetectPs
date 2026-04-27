param(
    [string]$Configuration = "Release",
    [string]$BuildDir = "",
    [int]$StressLoops = 50,
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

function Assert-FileExists($Path, $Description) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Fail "$Description not found: $Path"
    }
}

function Invoke-Checked($Command, $Arguments, $WorkingDirectory) {
    Write-Host "+ $Command $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$Command failed with exit code $LASTEXITCODE"
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

Step "Phase 2 batch 1 verification context"
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
    ) $RepoRoot
}

Step "Build engine_runtime_tests"
Invoke-Checked "cmake" @(
    "--build", $BuildDir,
    "--config", $Configuration,
    "--target", "engine_runtime_tests"
) $RepoRoot
Assert-FileExists $TestExe "engine_runtime_tests.exe"

Step "Build rasp_mod_amsi.dll"
Invoke-Checked "cmake" @(
    "--build", $BuildDir,
    "--config", $Configuration,
    "--target", "rasp_mod_amsi"
) $RepoRoot
Assert-FileExists $DllPath "rasp_mod_amsi.dll"

Step "Run engine_runtime_tests once"
Invoke-Checked $TestExe @() $RepoRoot

Step "Run engine_runtime_tests stress loop"
for ($i = 1; $i -le $StressLoops; $i++) {
    & $TestExe
    if ($LASTEXITCODE -ne 0) {
        Fail "engine_runtime_tests failed at loop $i with exit code $LASTEXITCODE"
    }
}
Write-Host "Stress loops passed: $StressLoops" -ForegroundColor Green

Step "Static source constraints"
Assert-NoSourceMatch "\bg_engine\b" "business code must not read global g_engine"
Assert-NoSourceMatch "\bg_unloadInProgress\b" "business code must not use global unload flag"
Assert-NoSourceMatch "std::atomic\s*<\s*RuleSnapshot\s*\*" "RuleSnapshot must not use atomic raw pointer"
Assert-NoSourceMatch "m_snapshot\.exchange" "snapshot reload must not exchange raw pointers"
Assert-NoSourceMatch "m_snapshot\.load" "snapshot readers must use atomic_load(shared_ptr)"
Assert-NoSourceMatch "delete\s+old" "old snapshots must not be manually deleted"
Assert-NoSourceMatch "delete\s+snapshot" "snapshots must not be manually deleted"

$providerPath = Join-Path $ModuleRoot "src\amsi_provider.cpp"
$providerText = Get-Content -LiteralPath $providerPath -Raw
if ($providerText -notmatch "GetAmsiEngineRuntime\(\)\.EnsureInitialized\(\)") {
    Fail "CreateInstance/Scan runtime initialization entry was not found"
}
if ($providerText -notmatch "ScanGuard\s+scan\s*=\s*runtime\.TryEnterScan\(\)") {
    Fail "ScanGuard runtime entry was not found in Scan path"
}
if ($providerText -match "std::lock_guard|std::unique_lock") {
    Fail "amsi_provider.cpp must not add provider-level locks around Scan hot path"
}

$runtimePath = Join-Path $ModuleRoot "src\engine_runtime.cpp"
$runtimeText = Get-Content -LiteralPath $runtimePath -Raw
if ($runtimeText -notmatch "wait_for") {
    Fail "bounded shutdown drain wait_for was not found"
}
if ($runtimeText -match "TerminateThread") {
    Fail "runtime must not use TerminateThread"
}

Step "Git diff hygiene"
Invoke-Checked "git" @("-C", $RepoRoot, "diff", "--check") $RepoRoot

Write-Host ""
Write-Host "Phase 2 batch 1 verification passed." -ForegroundColor Green
