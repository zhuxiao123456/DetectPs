param(
    [int]$Repeat = 2600,
    [switch]$NoInvoke
)

$ErrorActionPreference = "Stop"

# This probe targets the current AMSI-P03 regex shape:
#   [Reflection.Assembly]::Load .*? ([char](123) | [Registry]::LocalMachine)
#
# The script intentionally repeats the prefix many times and omits the suffix.
# It is meant to exercise PCRE2 match_limit / scan budget logging only.
$token = "[Reflection.Assembly]::Load "
$probe = "# " + ($token * $Repeat)

Write-Host "AMSI regex timeout probe"
Write-Host "repeat=$Repeat"
Write-Host "length=$($probe.Length)"
Write-Host "mode=$(if ($NoInvoke) { 'string-only' } else { 'Invoke-Expression comment probe' })"

if ($NoInvoke) {
    $probe | Out-Null
    Write-Host "Probe string built only. Use without -NoInvoke to force AMSI scan through Invoke-Expression."
    return
}

Invoke-Expression $probe
Write-Host "Probe submitted. Check AMSI diag logs for match_limit / regex_limit_hit / scan_budget messages."
