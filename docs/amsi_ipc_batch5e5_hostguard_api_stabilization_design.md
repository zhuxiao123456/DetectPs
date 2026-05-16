# Batch 5e-5 HostGuard API Stabilization Design

## 1. Goal

Batch 5e-5 stabilizes the minimum HostGuard-facing AMSI IPC API.

The target is that HostGuard depends on `AmsiIpcHost`, `AmsiIpcHostConfig`, `AmsiIpcHostAdapters`, and the three adapter interfaces only. HostGuard must not directly construct or include demo-only classes such as `RuleServer`, `DemoFileRuleProvider`, `EventCollector`, `ControlStatusCollector`, `ConfigWatcher`, or `AmsiStagingWatcher`.

This batch does not change DLL behavior, named pipe wire protocol, rule JSON schema, reload/unload semantics, or production pipe names.

## 2. Public Entry Points

`AmsiIpcHostConfig` provides two recommended factories:

- `AmsiIpcHostConfig::ForDemo(logDir, rulesPath, stagingDir)`
- `AmsiIpcHostConfig::ForHostGuard()`

`ForDemo(...)` preserves current `rasp_sentry.exe` demo fallback behavior:

- demo file rule provider remains available through `rulesPath`
- demo event/status collectors can write JSONL under `logDir`
- demo config and staging watchers stay enabled by default

`ForHostGuard()` is strict HostGuard mode:

- `logDir`, `rulesPath`, and `stagingDir` are empty
- `enableDemoConfigWatcher = false`
- `enableDemoStagingWatcher = false`
- `strictHostGuardMode = true`

`ForDemo(...)` and `ForHostGuard()` are recommended construction factories. The effective runtime mode is still determined by both `AmsiIpcHostConfig` and `AmsiIpcHostAdapters`. Empty path fields alone must not be treated as a reliable mode detector.

## 3. Strict HostGuard Mode Contract

When a caller constructs:

```cpp
auto config = AmsiIpcHostConfig::ForHostGuard();
AmsiIpcHost host(config, adapters);
```

`AmsiIpcHost::Start()` must require all HostGuard-owned adapters:

- `adapters.ruleProvider`
- `adapters.eventSink`
- `adapters.controlStatusSink`

If any required adapter is missing, `Start()` returns `false`.

In this failure path, `AmsiIpcHost` must not silently fall back to demo internals:

- no `DemoFileRuleProvider`
- no demo `EventCollector`
- no demo `ControlStatusCollector`
- no `ConfigWatcher`
- no `AmsiStagingWatcher`
- no rules/events/control-status pipe workers

This avoids a dangerous mixed mode where the caller believes HostGuard owns rule/event/status flow but the process has silently reverted to demo file and JSONL behavior.

## 4. Minimal HostGuard Usage

```cpp
class HostGuardAmsiModule {
public:
    bool Start()
    {
        auto config = AmsiIpcHostConfig::ForHostGuard();

        AmsiIpcHostAdapters adapters;
        adapters.ruleProvider = &ruleProvider_;
        adapters.eventSink = &eventSink_;
        adapters.controlStatusSink = &controlStatusSink_;

        host_.reset(new AmsiIpcHost(config, adapters));
        return host_->Start();
    }

    void Stop()
    {
        if (host_) {
            host_->Stop();
            host_.reset();
        }
    }

private:
    HostGuardRuleProvider ruleProvider_;
    HostGuardAmsiEventSink eventSink_;
    HostGuardAmsiControlStatusSink controlStatusSink_;
    std::unique_ptr<AmsiIpcHost> host_;
};
```

Recommended rule update order:

```cpp
host.InvalidateRules();
auto result = host.BroadcastReload();
```

`InvalidateRules()` only forwards to the current provider. `BroadcastReload()` and `BroadcastUnload()` only wrap the current 1-byte config pipe broadcaster.

## 5. Tests

Required tests:

- `ForDemo(...)` preserves demo path fields and enables demo watchers.
- `ForHostGuard()` clears demo paths, disables demo watchers, and marks strict mode.
- `ForHostGuard()` with missing required adapters returns `false`.
- `ForHostGuard()` with missing required adapters does not create rules/events/control-status test pipes.
- `ForHostGuard()` with injected rule/event/status adapters still serves `GET_RULES`, `GET_ALL_RULES`, raw event payloads, raw control-status payloads, `InvalidateRules()`, `BroadcastReload()`, and `BroadcastUnload()`.

## 6. Non-Goals

- Do not remove demo fallback.
- Do not remove `RuleServer` compatibility wrapper.
- Do not change default production pipe names.
- Do not change `amsi_detect_config` 1-byte reload/unload protocol.
- Do not modify DLL reload/unload handling.
- Do not introduce HostGuard SDK dependencies.
