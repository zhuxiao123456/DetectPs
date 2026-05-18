# DLL instance online view test steps

Date: 2026-05-18

This document describes how to validate the DLL instance online view with the
real `rasp_sentry.exe` host. `hostguard_demo.exe` is not the final acceptance
target for this feature.

## Build artifacts

```text
rasp_sentry.exe:
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\rasp_sentry.exe

rasp_mod_amsi.dll:
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\rasp_mod_amsi.dll
```

## Build commands

```powershell
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target rasp_sentry
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex --config Release --target rasp_mod_amsi
```

Recommended regression checks:

```powershell
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target dll_instance_registry_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\dll_instance_registry_tests.exe

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target amsi_ipc_host_adapter_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\amsi_ipc_host_adapter_tests.exe

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target amsi_ipc_hostguard_integration_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\amsi_ipc_hostguard_integration_tests.exe

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex --config Release --target engine_runtime_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
```

## Manual validation

Start `rasp_sentry.exe`:

```powershell
$logDir = "D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\online_view_logs"
$stagingDir = "D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\online_view_staging"
$rules = "D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\config\rasp_rules.json"

D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\rasp_sentry.exe `
  --log $logDir `
  --rules $rules `
  --staging $stagingDir
```

Then trigger a real process that loads `rasp_mod_amsi.dll`.

Check raw control status:

```powershell
Get-Content $logDir\rasp-control-status-2026-05-18.jsonl -Tail 20
```

Expected payloads:

```text
DLL_LOADED
RULE_LOAD_RESULT
DLL_HEARTBEAT
DLL_UNLOADED, if the process exits through a controlled path
```

Check the online view:

```powershell
Get-Content $logDir\rasp-dll-instances.json -Raw | ConvertFrom-Json
```

Acceptance points:

- `onlineDllCount >= 1` after DLL load.
- `historicalLoadedDllCount >= 1` after the first observed instance.
- `instances[].state` is `Online` after load or heartbeat.
- `instances[].ruleLoadSeen` becomes `true` after `RULE_LOAD_RESULT`.
- `instances[].processPath` is non-empty.
- `instances[].parentPid` is non-zero when Windows exposes it.
- `instances[].parentProcessPath` is populated when permission allows it.

## Semi-automatic script

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\scripts\verify_dll_online_view.ps1
```

The script starts `rasp_sentry.exe`, waits for `rasp-dll-instances.json`, and
prints key fields. It still expects a human or external harness to trigger a
real DLL load.

## Common failures

- The formal pipe is occupied by another `rasp_sentry.exe`.
- The target process did not load the latest `rasp_mod_amsi.dll`.
- `rasp-control-status-YYYY-MM-DD.jsonl` has no `DLL_LOADED`, meaning the DLL
  did not reach lifecycle reporting.
- `RULE_LOAD_RESULT` is absent, meaning rules were not loaded or the rule pipe
  did not respond.
- `parentProcessPath` is empty because the parent process exited quickly or
  access was denied.
- `rasp-dll-instances.json` is absent because no recognized lifecycle/status
  message has been received.

## Out of scope for this phase

Do not add these behaviors in this phase:

- slot control
- admission
- lease
- quota
- capacity blocking
- strong real-time process scanning
- UI status page
