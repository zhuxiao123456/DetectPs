param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"

$forbidden = @(
    "rasp_sentry_rules",
    "rasp_sentry_config",
    "rasp_sentry_events",
    "\\.\pipe\rasp_sentry_rules",
    "\\.\pipe\rasp_sentry_config",
    "\\.\pipe\rasp_sentry_events"
)

$scanRoots = @(
    "src/rasp_mod_amsi",
    "src/rasp_rule_engine",
    "src/rasp_sentry_native"
)

$allowPathFragments = @(
    "/build/",
    "/build-codex/"
)

$violations = New-Object System.Collections.Generic.List[string]

foreach ($root in $scanRoots) {
    $fullRoot = Join-Path $RepoRoot $root
    if (!(Test-Path $fullRoot)) {
        continue
    }

    Get-ChildItem -Path $fullRoot -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($RepoRoot.Length).TrimStart('\') -replace '\\','/'
        foreach ($fragment in $allowPathFragments) {
            if ($relative.Contains($fragment)) {
                return
            }
        }

        $text = [System.IO.File]::ReadAllText($_.FullName, [System.Text.Encoding]::Default)
        foreach ($token in $forbidden) {
            if ($text.Contains($token)) {
                $violations.Add("${relative}: forbidden legacy pipe token '$token'")
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host "Legacy rasp_sentry pipe names are forbidden in production source:"
    $violations | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "OK: production source uses amsi_detect pipe names only."
