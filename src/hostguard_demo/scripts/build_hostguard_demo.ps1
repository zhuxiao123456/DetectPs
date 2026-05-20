param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [string]$BuildDir = "build-hostguard-demo",

    [switch]$RunTests,

    [switch]$IncludeManualIntegration,

    [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Step $Name
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Resolve-Path (Join-Path $ScriptDir "..")
$BuildPath = Join-Path $RepoDir $BuildDir

Set-Location $RepoDir

Write-Host "hostguard_demo build"
Write-Host "  repo          : $RepoDir"
Write-Host "  buildDir      : $BuildPath"
Write-Host "  configuration : $Configuration"
Write-Host "  runTests      : $RunTests"
Write-Host "  manualIPC     : $IncludeManualIntegration"

if ($Clean -and (Test-Path $BuildPath)) {
    Write-Step "clean build directory"
    Remove-Item -LiteralPath $BuildPath -Recurse -Force
}

if (-not (Test-Path $BuildPath)) {
    Invoke-Step "configure CMake" {
        cmake -S $RepoDir -B $BuildPath
    }
}

Invoke-Step "build all hostguard_demo targets" {
    cmake --build $BuildPath --config $Configuration
}

$OutputDir = Join-Path $BuildPath $Configuration

Write-Step "build outputs"
$ExpectedOutputs = @(
    "hostguard_demo.exe",
    "hostguard_demo_pipe_client.exe",
    "hostguard_demo_options_tests.exe",
    "hostguard_demo_smoke_tests.exe",
    "hostguard_amsi_ipc_adapter_tests.exe",
    "hostguard_amsi_ipc_module_tests.exe",
    "hostguard_amsi_ipc_adapter_runtime_smoke_tests.exe"
)

foreach ($Name in $ExpectedOutputs) {
    $Path = Join-Path $OutputDir $Name
    if (Test-Path $Path) {
        Write-Host "  OK  $Path"
    } else {
        throw "missing expected build output: $Path"
    }
}

if ($RunTests) {
    $Tests = @(
        "hostguard_demo_options_tests.exe",
        "hostguard_demo_smoke_tests.exe",
        "hostguard_amsi_ipc_adapter_tests.exe",
        "hostguard_amsi_ipc_module_tests.exe"
    )

    if ($IncludeManualIntegration) {
        $Tests += "hostguard_amsi_ipc_adapter_runtime_smoke_tests.exe"
    }

    foreach ($Test in $Tests) {
        $TestPath = Join-Path $OutputDir $Test
        Invoke-Step "run $Test" {
            & $TestPath
        }
    }
}

Write-Step "done"
Write-Host "hostguard_demo.exe: $(Join-Path $OutputDir 'hostguard_demo.exe')"
Write-Host "pipe client       : $(Join-Path $OutputDir 'hostguard_demo_pipe_client.exe')"
