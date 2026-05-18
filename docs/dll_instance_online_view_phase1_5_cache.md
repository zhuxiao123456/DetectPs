# DLL instance online view Phase 1.5 cache

Date: 2026-05-18

This document records the paused implementation for the DLL instance online
view. The code changes are intentionally cached instead of committed so another
development plan can proceed without mixing scopes.

## Scope

The cached work implements the minimum online view only. It does not implement
slot, admission, lease, quota, capacity control, or blocking decisions.

## Intended runtime target

Final validation target is `rasp_sentry.exe`, not `hostguard_demo.exe`.

`hostguard_demo.exe` is only a protocol/dev helper and should not be used as the
final acceptance surface for this feature.

## Implemented behavior in cached code

### DLL side

`rasp_mod_amsi.dll` / shared `RaspSentryBase`:

- Generates a stable `dllInstanceId` / `instanceId`.
- Sends `DLL_LOADED` when the runtime initializes.
- Sends `DLL_HEARTBEAT` every 5 minutes from a background thread.
- Sends `DLL_UNLOADED` best effort during shutdown.
- Uses the same instance id in `RULE_LOAD_RESULT`.
- Adds `parentPid` and `parentProcessPath` to `DLL_LOADED`.

### sentry side

`rasp_sentry.exe`:

- Adds `DllInstanceRegistry`.
- `ControlStatusCollector` observes:
  - `DLL_LOADED`
  - `DLL_HEARTBEAT`
  - `DLL_UNLOADED`
  - `RULE_LOAD_RESULT`
- Online/stale decisions use HostGuard/sentry receive time, not payload
  timestamp.
- Each control-status payload refreshes registry state, purges old stale or
  unloaded instances, preserves the raw `rasp-control-status-YYYY-MM-DD.jsonl`
  behavior, and writes:

```text
rasp-dll-instances.json
```

Snapshot fields:

- `onlineDllCount`
- `staleDllCount`
- `unloadedDllCount`
- `historicalLoadedDllCount`
- `instancesWithRuleLoadResult`
- `instancesWithoutRuleLoadResult`
- `heartbeatIntervalMs`
- `staleThresholdMs`
- `instances[]`

Each instance includes:

- `instanceId`
- `state`
- `pid`
- `processStartTime`
- `processPath`
- `parentPid`
- `parentProcessPath`
- `firstSeenMs`
- `lastSeenMs`
- `ruleLoadSeen`
- `lastRuleVersion`

### hostguard_demo side

There is also a demo-side copy of the registry and status output. It was useful
for early protocol validation, but the preferred next development path should
keep final validation on `rasp_sentry.exe`.

## Cached source files

The relevant cached files are:

```text
src/rasp_sentry_native/CMakeLists.txt
src/rasp_sentry_native/include/control_status_collector.h
src/rasp_sentry_native/src/control_status_collector.cpp
src/rasp_sentry_native/include/dll_instance_registry.h
src/rasp_sentry_native/src/dll_instance_registry.cpp
src/rasp_sentry_native/tests/dll_instance_registry_tests.cpp
src/rasp_rule_engine/include/rasp_sentry_base.h
src/rasp_rule_engine/src/rasp_sentry_base.cpp
src/hostguard_demo/CMakeLists.txt
src/hostguard_demo/src/hostguard_demo_app.cpp
src/hostguard_demo/src/hostguard_jsonl_control_status_sink.h
src/hostguard_demo/src/hostguard_jsonl_control_status_sink.cpp
src/hostguard_demo/src/hostguard_dll_instance_registry.h
src/hostguard_demo/src/hostguard_dll_instance_registry.cpp
src/hostguard_demo/tests/hostguard_dll_instance_registry_tests.cpp
src/hostguard_demo/tests/hostguard_demo_smoke_tests.cpp
```

## Last verification commands

These commands passed before caching:

```powershell
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target dll_instance_registry_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\dll_instance_registry_tests.exe

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target rasp_sentry

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex --config Release --target engine_runtime_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex --config Release --target rasp_mod_amsi

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target amsi_ipc_host_adapter_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\amsi_ipc_host_adapter_tests.exe

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex --config Release --target amsi_ipc_hostguard_integration_tests
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\amsi_ipc_hostguard_integration_tests.exe
```

Expected non-blocking warning:

```text
C4819 encoding warning in existing sentry headers
```

## Restore guidance

Find the cached stash:

```powershell
git -C D:\Code\rasp\DetectPsByAmsiCodex stash list
```

Apply it when development resumes:

```powershell
git -C D:\Code\rasp\DetectPsByAmsiCodex stash apply stash@{N}
```

After restore, rebuild `rasp_sentry.exe` and `rasp_mod_amsi.dll`, then validate
that `rasp-dll-instances.json` is generated under the sentry log directory.

## Recommended resume point

When this work resumes, continue from:

1. Keep `rasp_sentry.exe` as the only final validation target.
2. Add state transition logs for online, stale, resumed, unloaded, and
   rule-load-seen.
3. Add a semi-automatic `rasp_sentry.exe + real DLL` verification script.
4. Avoid slot/admission/quota work until the online view is accepted.
