param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
}

Set-Location $RepoRoot

function Fail($Message) {
    throw "[session-dormant] $Message"
}

function Check-NoPattern($Path, [string[]]$Patterns, $Message) {
    if (-not (Test-Path $Path)) {
        Fail "missing file: $Path"
    }

    foreach ($pattern in $Patterns) {
        $hit = Select-String -Path $Path -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
        if ($hit) {
            $hit | ForEach-Object { Write-Host ("{0}:{1} {2}" -f $_.Path, $_.LineNumber, $_.Line) }
            Fail "$Message : $pattern"
        }
    }
}

Check-NoPattern "src\rasp_mod_amsi\include\amsi_rule_engine.h" @(
    "script_session_context_cache.h",
    "ScriptSessionContextCache",
    "m_sessionCache"
) "AmsiRuleEngine header must not wire session aggregation into production"

Check-NoPattern "src\rasp_mod_amsi\src\amsi_rule_engine.cpp" @(
    "ScriptSessionKey",
    "SessionContextView",
    "SessionKeyConfidence",
    "UpdateAndBuildView",
    "m_sessionCache",
    "sessionAggregated",
    "sessionTruncated",
    "sessionBypassed"
) "AmsiRuleEngine implementation must not use session aggregation in production"

Check-NoPattern "src\rasp_mod_amsi\tests\engine_runtime_tests.cpp" @(
    "session context exposes split token across chunks",
    "split token across chunks"
) "Production tests must not assert session aggregation behavior"

$cmakePath = "src\rasp_mod_amsi\CMakeLists.txt"
if (-not (Test-Path $cmakePath)) {
    Fail "missing file: $cmakePath"
}

$lines = Get-Content $cmakePath
$inSessionTestTarget = $false
for ($i = 0; $i -lt $lines.Length; $i++) {
    $line = $lines[$i]
    if ($line -match "add_executable\s*\(\s*session_context_cache_tests") {
        $inSessionTestTarget = $true
    } elseif ($inSessionTestTarget -and $line.Trim() -eq ")") {
        $inSessionTestTarget = $false
    }

    if ($line.Contains("src/script_session_context_cache.cpp") -and -not $inSessionTestTarget) {
        Write-Host ("{0}:{1} {2}" -f $cmakePath, ($i + 1), $line)
        Fail "script_session_context_cache.cpp may only be compiled by session_context_cache_tests"
    }
}

$docsWithStatus = @(
    "docs\phase3_batch2_session_context_design.md",
    "docs\edr_migration_boundary_plan.md",
    "docs\edr_migration_readiness_review.md",
    "docs\session_aggregation_dormant_plan.md"
)

foreach ($doc in $docsWithStatus) {
    if (-not (Test-Path $doc)) {
        Fail "missing session status document: $doc"
    }
    $content = Get-Content $doc -Raw
    if (-not $content.Contains("Status: Dormant / Experimental")) {
        Fail "missing dormant status tag in $doc"
    }
    if (-not $content.Contains("Production state: Not wired into current AMSI scan path")) {
        Fail "missing production-state tag in $doc"
    }
    if (-not $content.Contains("Release commitment: Not supported in current version")) {
        Fail "missing release-commitment tag in $doc"
    }
}

Write-Host "[session-dormant] passed"
