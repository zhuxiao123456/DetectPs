# Phase 2 Batch 1 Test Plan

## Scope

This plan verifies only the first approved Phase 2 batch:

1. `EngineRuntime` state gateway.
2. `ScanGuard` and `active_scan_count`.
3. `RuleSnapshot` publication through `shared_ptr<const RuleSnapshot>`.

It intentionally does not validate Lua/PCRE2 timeout budgets, async event queues,
session cache, or sample windowing. Those belong to later Phase 2 batches.

## Test Entry Points

Primary script:

```powershell
.\scripts\test_phase2_batch1.ps1
```

Fast local rerun after CMake has already been configured:

```powershell
.\scripts\test_phase2_batch1.ps1 -SkipConfigure -StressLoops 10
```

Strict stress run:

```powershell
.\scripts\test_phase2_batch1.ps1 -StressLoops 200
```

The script uses `src\rasp_mod_amsi\build-codex` by default and verifies:

- `engine_runtime_tests.exe` builds.
- `rasp_mod_amsi.dll` builds.
- `engine_runtime_tests.exe` runs once.
- `engine_runtime_tests.exe` survives a stress loop.
- source-level forbidden patterns are absent.
- `git diff --check` reports no whitespace errors.

## Build Tests

Commands covered by the script:

```powershell
cmake -S src\rasp_mod_amsi -B src\rasp_mod_amsi\build-codex -G "Visual Studio 17 2022" -A x64 -DFETCHCONTENT_UPDATES_DISCONNECTED=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON
cmake --build src\rasp_mod_amsi\build-codex --config Release --target engine_runtime_tests
cmake --build src\rasp_mod_amsi\build-codex --config Release --target rasp_mod_amsi
```

Pass criteria:

- `engine_runtime_tests.exe` is produced.
- `rasp_mod_amsi.dll` is produced.
- No link errors.
- No new lifecycle or concurrency related compiler warnings.

Known residual warning class:

- Historical source encoding warnings from `rasp_mod_amsi.h` may still appear on a full rebuild. They are not introduced by Phase 2 batch 1 and should be handled as a separate cleanup.

## Runtime Harness Coverage

The current C++ harness is:

```text
src\rasp_mod_amsi\tests\engine_runtime_tests.cpp
```

It validates:

- New runtime starts in `Uninitialized`.
- `EnsureInitialized()` moves runtime to `Ready`.
- `TryEnterScan()` succeeds only in ready runtime.
- `ScanGuard` increments `active_scan_count` on entry.
- `ScanGuard` decrements `active_scan_count` on destruction.
- `BeginShutdown()` has a bounded drain timeout while a scan is active.
- Shutdown timeout enters `Inert`.
- `Inert` rejects new scans.
- A concurrent scan entry releases `active_scan_count` after the worker exits.

Manual command:

```powershell
.\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
```

Pass criteria:

- Exit code is `0`.
- No `FAIL:` lines are printed.

## Static Architecture Checks

The script rejects these regressions:

- `g_engine` usage reappears in source.
- `g_unloadInProgress` usage reappears in source.
- `RuleSnapshot` returns to `std::atomic<RuleSnapshot*>`.
- `m_snapshot.exchange()` or `m_snapshot.load()` raw pointer style reappears.
- Old snapshots are manually deleted.
- `amsi_provider.cpp` adds provider-level `std::lock_guard` or `std::unique_lock`.
- `TerminateThread` appears in runtime code.
- `wait_for` disappears from shutdown drain logic.
- `ScanGuard scan = runtime.TryEnterScan()` disappears from the scan path.

Manual equivalent:

```powershell
rg -n "\bg_engine\b|\bg_unloadInProgress\b|atomic<RuleSnapshot|RuleSnapshot\*|m_snapshot\.exchange|m_snapshot\.load|delete\s+old|delete\s+snapshot" src\rasp_mod_amsi
```

Pass criteria:

- No forbidden matches outside generated build directories.

## Acceptance Matrix

| Requirement | Verification |
| --- | --- |
| Business code does not directly read `g_engine` | static forbidden-pattern check |
| `CreateInstance` enters runtime | static provider check |
| `Scan` enters runtime | static provider check plus harness |
| `ScanGuard` releases active count | harness |
| Shutdown rejects new scans | harness |
| Shutdown drain is bounded | harness plus `wait_for` static check |
| `RuleSnapshot` is not manually deleted | static forbidden-pattern check |
| `Evaluate()` holds a local shared snapshot | code review plus shared pointer pattern check |
| DLL still builds | CMake build target |
| Runtime harness is repeatable | stress loop |

## Gaps And Follow-Up Tests

Not covered in batch 1:

- Real COM/AMSI host loading in `powershell.exe`.
- Real `IAmsiStream` scan extraction.
- Rule reload success/failure with live sentry.
- Lua timeout and regex limit behavior.
- IPC disconnect behavior.
- Event/log queue behavior.

Recommended follow-up for batch 2:

- Add reload/shutdown race harness.
- Add explicit reload failure preserves old snapshot test.
- Add telemetry assertions for `reload_begin`, `reload_success`, `reload_failed`, and `shutdown_drain_timeout`.
