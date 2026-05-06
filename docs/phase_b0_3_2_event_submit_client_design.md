# Phase B0-3-2 EventSubmitClient 抽离设计

## 1. 目标

B0-3-2 的目标是从 `RaspSentryBase` 中逐步抽离事件 JSON 构造和 worker-only 发送边界，同时保持现有事件 schema、字段顺序、pipe 协议、`AsyncEventQueue` 行为和 Scan 热路径非阻塞模型不变。

本阶段必须小步提交，不允许把 JSON builder 生产接入、transport seam、真实 pipe adapter 混在一个 commit 中。

当前下一步只做 **B0-3-2b-2 design-only**：补充 `LegacyPipeEventTransport` 文档和测试计划，不改代码。

## 2. 分批路线

| 批次 | 目标 | 是否改生产路径 |
| --- | --- | --- |
| B0-3-2a | 固化 `EventJsonBuilder` golden JSON | 否 |
| B0-3-2b-1 | 新增 `IEventTransport` seam、fake transport 测试、worker-only helper | 否 |
| B0-3-2b-2 | 设计真实 `LegacyPipeEventTransport` adapter 和测试计划 | 否 |
| B0-3-2b-3 | 实现真实 `LegacyPipeEventTransport`，但不接生产路径 | 否 |
| B0-3-2b-4 | 评审后将 `SendDetectionEventSyncWorkerOnly()` 改成 transport 薄包装 | 是 |
| B0-3-2b-A | 评审后将 `TrySubmitDetectionEvent()` 改用 `EventJsonBuilder` | 是 |

`B0-3-2b-4` 和 `B0-3-2b-A` 是两个独立风险点，必须独立 commit、独立 review。

## 3. 非目标

B0-3-2 不做：

- 不修改 `rasp_sentry_events` pipe 名称或 wire format。
- 不修改 `AsyncEventQueue` drop / backoff / worker 模型。
- 不修改 Scan 热路径入队模型。
- 不修改 reload / unload / shutdown。
- 不修改 AMSI `Scan()` 返回语义。
- 不接入 EDR SDK。
- 不新增数据库字段。
- 不修改 `RuleJsonParser`。
- 不抽 `DiagLogger`。
- 不新增 dropped / timeout / diag event schema。

## 4. 当前事件路径基线

当前生产路径：

```text
Evaluate()
  -> TrySubmitDetectionEvent(RaspEvalResult)
      -> 生成 id / timestamp
      -> 构造 compactJson
      -> 填充 AsyncEvent
      -> m_eventSink.TrySubmit(event)
          -> AsyncEventQueue
          -> worker
              -> SendDetectionEventSyncWorkerOnly(AsyncEvent)
                  -> 写入 \\.\pipe\rasp_sentry_events
```

当前 `TrySubmitDetectionEvent()` 同时负责：

- 构造 detection compact JSON。
- 填充 `AsyncEvent` 队列 DTO。

当前 `SendDetectionEventSyncWorkerOnly()` 负责：

- worker-only 同步写旧 `rasp_sentry_events` pipe。
- 返回 `true/false` 给 async worker。

## 5. Golden JSON 字段基线

以当前 `RaspSentryBase::TrySubmitDetectionEvent()` 为准，检测事件 JSON 字段顺序必须保持：

```json
{
  "id": "...",
  "ts": "...",
  "sev": "...",
  "act": "...",
  "cat": "Detection",
  "mod": "...",
  "sensor": "...",
  "rule": "...",
  "desc": "...",
  "appName": "...",
  "contentName": "...",
  "confidence": "...",
  "ip": "...",
  "ua": "...",
  "pattern": "..."
}
```

当前字段语义：

- `act`：`result.block == true` 时为 `"block"`，否则为 `"audit"`。
- `cat`：固定为 `"Detection"`。
- `sev`：`result.severity` 为空时回退 `"High"`。
- `confidence`：`result.confidence != 0` 时使用 `std::to_string(result.confidence)`，否则回退 `"70"`。
- `pattern`：只使用 `result.payload`，payload 为空时保持空字符串，不回退 `desc`。
- `desc`：当前旧路径不截断，完整 JSON escape 后写入。
- `pattern`：当前按 8KB 字段上限截断，并追加 `...[Truncated]`。
- 所有字符串字段必须经过与旧路径一致的 JSON escape。

## 6. B0-3-2a 当前状态

B0-3-2a 已固化纯 JSON builder seam：

- `EventJsonBuilder` 只负责 JSON 构造。
- 不接 pipe。
- 不替换 `RaspSentryBase` 生产路径。
- 不修改 `AsyncEventQueue`。

进入后续批次前，`event_json_builder_tests.exe` 必须持续通过。

## 7. B0-3-2b-1 当前状态

B0-3-2b-1 已建立 fake transport seam：

- `event_transport.h` 定义 `EventTransportStatus` 和 bytes-only `IEventTransport`。
- `event_worker_sender.h/.cpp` 定义 `SendAsyncEventWorkerOnly()`。
- `event_transport_tests.cpp` 使用 fake transport 验证状态映射。
- 不接真实 pipe。
- 不修改 `SendDetectionEventSyncWorkerOnly()`。
- 不修改 `TrySubmitDetectionEvent()`。
- 不修改 `AsyncEventQueue`。

## 8. B0-3-2b-2 Design-Only 目标

B0-3-2b-2 只补文档和测试计划，不改代码。

目标：

- 明确 `LegacyPipeEventTransport` 的文件位置、职责和禁止依赖。
- 明确旧 pipe 行为保持策略。
- 明确 Win32 错误码到 `EventTransportStatus` 的映射。
- 明确单元测试、可跳过集成测试和回归测试范围。
- 明确后续实现仍不得接入生产 `SendDetectionEventSyncWorkerOnly()`。

## 9. LegacyPipeEventTransport 设计

建议文件：

```text
src/rasp_rule_engine/include/legacy_pipe_event_transport.h
src/rasp_rule_engine/src/legacy_pipe_event_transport.cpp
src/rasp_mod_amsi/tests/legacy_pipe_event_transport_tests.cpp
```

建议接口：

```cpp
class LegacyPipeEventTransport final : public IEventTransport {
public:
    LegacyPipeEventTransport();
    explicit LegacyPipeEventTransport(std::wstring pipeName);

    EventTransportStatus Send(std::string_view payload,
                              uint32_t timeoutMs) override;
};
```

职责：

- 只负责发送 `std::string_view payload`。
- 默认 pipe 为 `\\.\pipe\rasp_sentry_events`。
- 内部执行 `CreateFileW`、`WriteFile`、`CloseHandle`。
- 将 Win32 结果映射为 `EventTransportStatus`。

禁止：

- 不构造 JSON。
- 不理解 `ruleId`、`severity`、`decision`、`sensor`、`contentName`。
- 不依赖 `AsyncEvent`。
- 不依赖 `RaspEvalResult`。
- 不访问 `RuleSnapshot`、Lua、PCRE2、`RaspLuaEngine`、`EngineRuntime`。
- 不调用 `DiagLogger`。
- 不接 EDR SDK。
- 不访问数据库。

## 10. 旧 pipe 行为保持策略

第一版必须保持旧行为：

- 不新增 `WaitNamedPipeW`。
- 不新增重试。
- 不新增同步等待。
- 不改变 worker/backoff 时序。
- `CreateFileW` 失败即返回非 `Sent` 状态。
- `WriteFile` 完整写入才返回 `Sent`。
- `WriteFile` 失败或部分写入返回 `Failed`。

`timeoutMs` 参数先保留为未来扩展，第一版 `LegacyPipeEventTransport` 不主动引入等待语义。

## 11. 错误映射表

| Win32 / 旧 pipe 情况 | EventTransportStatus |
| --- | --- |
| `CreateFileW` 成功且 `WriteFile` 完整写入 | `Sent` |
| `CreateFileW` 返回 `ERROR_FILE_NOT_FOUND` | `Unavailable` |
| `CreateFileW` 返回 `ERROR_PIPE_BUSY` | `Unavailable` |
| `CreateFileW` / `WriteFile` 返回 `ERROR_ACCESS_DENIED` | `AccessDenied` |
| 未来显式等待或写入超时 | `Timeout` |
| `WriteFile` 失败 | `Failed` |
| `WriteFile` 成功但部分写入 | `Failed` |
| 其它 `CreateFileW` 失败 | `Failed` |

建议后续实现把错误映射拆成纯 helper，便于单测：

```cpp
EventTransportStatus MapCreateFileErrorForEventPipe(DWORD error);
EventTransportStatus MapWriteFileErrorForEventPipe(DWORD error);
```

helper 可放在 `.cpp` 内部匿名命名空间；若需要单测，可通过 test-only include 或内部测试接口暴露。实现前需要评审具体暴露方式。

## 12. B0-3-2b-2 测试计划

### 12.1 单元测试

新增 `legacy_pipe_event_transport_tests.cpp`，优先覆盖纯状态映射，不依赖真实 pipe。

必须测试：

- `ERROR_FILE_NOT_FOUND` -> `Unavailable`
- `ERROR_PIPE_BUSY` -> `Unavailable`
- `ERROR_ACCESS_DENIED` -> `AccessDenied`
- 其它 `CreateFileW` 错误 -> `Failed`
- `WriteFile` 返回 `ERROR_ACCESS_DENIED` -> `AccessDenied`
- 其它 `WriteFile` 错误 -> `Failed`
- 部分写入 -> `Failed`
- 完整写入 -> `Sent`

空 payload 行为建议：

- 第一版允许发送空 payload 由 `WriteFile` 语义决定，transport 本身不做业务校验。
- 空 `compactJson` 的拒绝逻辑保留在 `SendAsyncEventWorkerOnly()`，不放进 `LegacyPipeEventTransport`。

### 12.2 可跳过集成测试

如需验证真实 pipe，可新增单独脚本并默认可跳过：

```text
scripts/test_phase_b0_3_2_legacy_pipe_transport.ps1
```

集成测试原则：

- 不要求 Scan 热路径参与。
- 不启动 AMSI Provider。
- 使用测试 pipe server 模拟 `rasp_sentry_events`。
- 验证 adapter 能完整写入 payload。
- pipe 不存在时返回 `Unavailable` 或 `Failed`，按错误码映射判断。

该集成测试不能成为普通开发环境的硬依赖，避免环境不具备 pipe server 时阻塞回归。

### 12.3 回归测试

B0-3-2b-2 design-only 只需跑：

- `scripts/check_rasp_sentry_base_boundaries.ps1`
- `git diff --check`

B0-3-2b-3 实现真实 adapter 后必须跑：

- `legacy_pipe_event_transport_tests.exe`
- `event_transport_tests.exe`
- `event_json_builder_tests.exe`
- `scripts/check_rasp_sentry_base_boundaries.ps1`
- `scripts/test_phase_b0_2_rule_json_parser.ps1 -SkipConfigure`
- `scripts/test_phase2_batch4.ps1 -SkipConfigure`
- `scripts/test_phase3_input_normalization.ps1 -SkipConfigure`
- `scripts/test_phase3_batch2_session_context.ps1 -SkipConfigure`

## 13. 静态边界检查

### 13.1 event_submit_client.* 禁止项

`event_submit_client.h/.cpp` 不得出现：

- `CreateFileW`
- `WriteFile`
- `WaitNamedPipe`
- `CreateNamedPipe`
- `ConnectNamedPipe`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EngineRuntime`
- `IAmsiStream`
- `AMSI_RESULT`
- `EDR`
- `SQL`
- `database`

### 13.2 event_transport.* 禁止项

`event_transport.h/.cpp` 不得出现：

- `CreateFileW`
- `WriteFile`
- `WaitNamedPipe`
- `CreateNamedPipe`
- `ConnectNamedPipe`
- `AsyncEvent`
- `RaspEvalResult`
- `DetectionEventLite`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EngineRuntime`
- `IAmsiStream`
- `AMSI_RESULT`
- `EDR`
- `SQL`
- `database`

### 13.3 legacy_pipe_event_transport.* 边界

`legacy_pipe_event_transport.*` 允许出现：

- `CreateFileW`
- `WriteFile`
- `GetLastError`
- `CloseHandle`

但禁止出现：

- `RaspEvalResult`
- `AsyncEvent`
- `DetectionEventLite`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EngineRuntime`
- `AMSI_RESULT`
- `EDR`
- `SQL`
- `database`
- `Reload`
- `Unload`
- `DetectionEvent`
- `DrainAck`
- `ConfigUpdate`

`legacy_pipe_event_transport.*` 只能接收 `std::string_view payload`，不能依赖 `AsyncEvent`。

## 14. AsyncEvent 字段保持要求

如果后续 `TrySubmitDetectionEvent()` 改用 `EventJsonBuilder`，必须保证以下字段不变：

- `AsyncEvent.priority == EventPriority::Detection`
- `AsyncEvent.type == EventType::Detection`
- `AsyncEvent.pid == GetCurrentProcessId()`
- `AsyncEvent.tid == GetCurrentThreadId()`
- `AsyncEvent.ruleId == result.ruleId`
- `AsyncEvent.decision == block/audit`
- `AsyncEvent.contentName == result.contentName`
- `AsyncEvent.appName == result.appName`
- `AsyncEvent.sampleLen == result.payload.size()`
- `AsyncEvent.reason == result.desc`
- `AsyncEvent.eventTruncated` 与 builder payload 截断结果一致
- `AsyncEvent.compactJson` 与 B0-3-2a golden JSON 一致

这属于后续 B0-3-2b-A，不在 B0-3-2b-2 中实现。

## 15. 红线

B0-3-2 后续实现禁止：

- 在 Scan 热路径直接调用 transport。
- 在 transport 中构造 JSON。
- 在 transport 中理解 detection / diag / reload / unload 业务语义。
- 在 `event_submit_client.*` 中调用 Windows pipe API。
- 在 `LegacyPipeEventTransport` 中依赖 `AsyncEvent` 或 `RaspEvalResult`。
- 修改 `AsyncEventQueue` 行为。
- 修改 pipe 名称或 wire format。
- 新增 `WaitNamedPipeW` 等待导致 worker/backoff 时序变化。
- 接入 EDR SDK。
- 新增事件 schema。

## 16. 回滚策略

- `RaspSentryBase::TrySubmitDetectionEvent()` 保留旧入口。
- `SendDetectionEventSyncWorkerOnly()` 保留旧入口。
- B0-3-2b-2 只改文档，回滚不影响代码。
- B0-3-2b-3 如果真实 pipe adapter 行为不一致，可回退到旧直接 pipe 写。
- B0-3-2b-A 如果 builder 生产接入导致 JSON 或 `AsyncEvent` 字段不一致，停止接入并保留旧内联 JSON 构造。
