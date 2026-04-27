# Phase 2 Runtime, ScanGuard, and Snapshot Design

## Scope

Phase 2 is an architecture safety fix. The first implementation batch is limited to:

1. EngineRuntime state machine.
2. ScanGuard and active scan accounting.
3. RuleSnapshot publication through `shared_ptr<const RuleSnapshot>`.

The first batch must not change Lua timeout behavior, PCRE2 limits, event queues, session cache, or sample windowing.

## EngineRuntime Boundary

`EngineRuntime` owns only runtime coordination:

- `EngineState`
- `AmsiRuleEngine` lifecycle
- `active_scan_count`
- `ScanGuard`
- reload, shutdown, and unload coordination
- state telemetry

It must not own:

- AMSI stream extraction
- Lua rule execution
- PCRE2 details
- sample normalization
- event JSON construction
- rule JSON parsing

## EngineState

```cpp
enum class EngineState {
    Uninitialized,
    Initializing,
    Ready,
    Reloading,
    Stopping,
    Inert,
    Stopped,
    Faulted
};
```

Allowed first-batch transitions:

```text
Uninitialized -> Initializing -> Ready
Ready -> Stopping -> Inert
Ready -> Inert
Initializing -> Faulted
Faulted -> Inert
```

Reserved for later batches:

```text
Ready -> Reloading -> Ready
Reloading -> Stopping
Stopping -> Stopped
Inert -> Stopped
```

Priority:

- `Inert` rejects all business actions.
- `Stopping` rejects new scans.
- `Faulted` rejects complex logic and must not retry automatically.
- `Ready` is the only state that allows scan entry.
- `Stopped` is terminal.

## Scan Hot Path

`Scan()` may enter runtime only long enough to:

1. Check state.
2. Increment `active_scan_count`.
3. Get a local engine pointer.
4. Exit runtime lock.

`Scan()` must not hold a runtime mutex while:

- executing Lua
- executing PCRE2
- writing a pipe
- waiting for sentry
- emitting blocking logs

## Shutdown Drain

`BeginShutdown()` must:

1. Move the runtime to `Stopping` or `Inert`.
2. Reject new scans.
3. Wait for `active_scan_count` with a bounded timeout.
4. Enter `Inert` on timeout and emit `shutdown_drain_timeout`.

Shutdown must never wait forever.

## Snapshot Publication

`RuleSnapshot` is published as `std::shared_ptr<const RuleSnapshot>`.

Rules:

- `Evaluate()` loads a local `shared_ptr` at the start.
- The local snapshot remains valid for the entire scan.
- Reload builds a complete next snapshot before publishing.
- Reload failure keeps the old snapshot.
- Published snapshots are immutable.
- Old snapshots are not manually deleted.

## First-Batch Acceptance

Build:

- `rasp_mod_amsi.dll` is produced successfully.
- No new lifecycle or concurrency related warnings.
- No new linker errors.

Code:

- Business code does not directly read `g_engine`.
- `CreateInstance`, `Scan`, and `OnUnloadSignal` go through `EngineRuntime`.
- `ScanGuard` releases `active_scan_count` in its destructor.
- `BeginShutdown` causes later `TryEnterScan` calls to fail.
- `WaitForActiveScansToDrain` is bounded.
- `RuleSnapshot` has no manual delete path.
- `Evaluate()` holds a local `shared_ptr<const RuleSnapshot>`.

Concurrency:

- scan plus reload does not crash.
- scan plus shutdown does not crash.
- shutdown rejects new scans.
- inert state does not enter complex logic.
- reload failure preserves the old snapshot.
