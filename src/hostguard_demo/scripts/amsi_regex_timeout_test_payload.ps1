param(
    [int]$Repeat = 4096,
    [switch]$NoInvoke
)

$ErrorActionPreference = "Stop"

# This script is paired with scripts/amsi_regex_timeout_test_rules.json.
# It builds a marker-prefixed subject that nearly matches:
#   REGEX_TIMEOUT_PROBE:(?:a|aa)+$
# and then appends "b" so the regex must fail after heavy backtracking.
#
# Expected diagnostic logs:
#   regex error type=match_limit
#   scan_budget reason=regex_limit_hit
$payload = "# REGEX_TIMEOUT_PROBE:" + ("a" * $Repeat) + "b"

Write-Host "AMSI regex timeout test payload"
Write-Host "repeat=$Repeat"
Write-Host "length=$($payload.Length)"
Write-Host "mode=$(if ($NoInvoke) { 'string-only' } else { 'Invoke-Expression comment payload' })"

if ($NoInvoke) {
    $payload | Out-Null
    Write-Host "Payload string built only. Use without -NoInvoke to submit it to AMSI."
    return
}

Invoke-Expression $payload
Write-Host "Payload submitted. Check AMSI diag logs for match_limit / regex_limit_hit / scan_budget."
