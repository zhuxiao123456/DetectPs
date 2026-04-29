param(
    [switch]$SkipConfigure
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$srcDir = Join-Path $repoRoot "src\rasp_mod_amsi"
$buildDir = Join-Path $srcDir "build-codex"

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

if (-not $SkipConfigure) {
    Write-Host "[b0-2-parser] configure"
    Invoke-NativeChecked { cmake -S $srcDir -B $buildDir -G "Visual Studio 17 2022" }
}

Write-Host "[b0-2-parser] build rule_json_parser_tests"
Invoke-NativeChecked { cmake --build $buildDir --config Release --target rule_json_parser_tests }

Write-Host "[b0-2-parser] run rule_json_parser_tests"
Invoke-NativeChecked { & (Join-Path $buildDir "Release\rule_json_parser_tests.exe") }

Write-Host "[b0-2-parser] boundary checks"
& (Join-Path $repoRoot "scripts\check_rasp_sentry_base_boundaries.ps1") -RepoRoot $repoRoot

Write-Host "[b0-2-parser] passed"
