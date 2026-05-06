# Phase B0-3-2 EventSubmitClient 抽离设计

## 1. 目标

B0-3-2 的目标是从 `RaspSentryBase` 中逐步抽离事件 JSON 构造和 worker-only 发送边界，同时保持现有事件 schema、字段顺序、pipe 协议、`AsyncEventQueue` 行为和 Scan 热路径非阻塞模型不变。

本阶段必须继续小步提交，不允许把 JSON builder 生产接入、transport seam、真实 pipe adapter 混在一个 commit 中。

## 2. 评审意见处理结论

本次评审提出的 5 个收敛点全部接受，原因如下：

- 先做 fake transport 能把 worker-only wrapper 的行为验证清楚，避免过早引入 Windows pipe API、错误码映射、超时语义和部分写入处理。
- 真实 pipe adapter 必须位于 compatibility / transport 层，不能污染 `event_submit_client.*`，否则会破坏 B0-3 已经建立的 seam 边界。
- pipe 错误映射必须先定义，否则 B0-3-2b 容易在“抽象 transport”时顺手改变旧失败语义。
- `TrySubmitDetectionEvent()` 改用 `EventJsonBuilder` 和 `SendDetectionEventSyncWorkerOnly()` 改用 transport 是两个独立风险点，必须拆开评审和提交。
- `TrySubmitDetectionEvent()` 除了 compact JSON，还填充 `AsyncEvent` 多个 DTO 字段，必须用测试锁定，避免生产接入 builder 时发生隐式漂移。

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

当前 `TrySubmitDetectionEvent()` 同时负责两类事情：

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

## 6. JSON Escape 与截断语义

`EventJsonBuilder` 必须与旧路径保持一致：

- `"` -> `\"`
- `\` -> `\\`
- `\n` -> `\n`
- `\r` -> `\r`
- `\t` -> `\t`
- 其他小于 `0x20` 的控制字符 -> `\u00xx`

payload 截断必须是 UTF-8 安全截断：

- 不允许截断在中文、emoji 等多字节字符中间。
- 如果边界落在多字节字符内部，必须回退到上一个完整字符，再追加 `...[Truncated]`。
- 输出 `pattern` 字段最大为 8192 字节。
- `desc` 超长当前不截断，这是 legacy 行为，测试必须显式覆盖。

## 7. B0-3-2a 当前状态

B0-3-2a 已固化纯 JSON builder seam：

- `EventJsonBuilder` 只负责 JSON 构造。
- 不接 pipe。
- 不替换 `RaspSentryBase` 生产路径。
- 不修改 `AsyncEventQueue`。

进入 B0-3-2b 前，`event_json_builder_tests.exe` 必须持续通过。

## 8. B0-3-2b 分批方案

### 8.1 B0-3-2b-0：设计文档更新

目标：

- 更新本设计文档。
- 明确 `EventTransportStatus`。
- 明确 `IEventTransport` 只发送 bytes。
- 明确旧 pipe 错误映射表。
- 明确第一版不改变 pipe 等待 / 失败行为。
- 明确 builder 替换和 transport 替换分开 commit。

本批只保存文档，不改运行行为。

### 8.2 B0-3-2b-1：fake transport seam 测试

目标：

- 新增 `IEventTransport` seam。
- 新增 fake transport 测试。
- 验证 worker-only wrapper 行为。
- 不新增真实 pipe adapter。
- 不改 `TrySubmitDetectionEvent()`。

建议接口：

```cpp
enum class EventTransportStatus {
    Sent,
    Timeout,
    AccessDenied,
    Unavailable,
    Failed
};

class IEventTransport {
public:
    virtual ~IEventTransport() = default;
    virtual EventTransportStatus Send(std::string_view payload,
                                      uint32_t timeoutMs) = 0;
};
```

`IEventTransport` 只发送 bytes / string payload，不知道 `DetectionEvent`、`DiagEvent`、`RuleId`、`severity`、`decision` 等业务字段。

禁止出现：

```cpp
IEventTransport::SendDetection(...)
IEventTransport::SendDiag(...)
IEventTransport::SendDroppedSummary(...)
```

测试要求：

- `compactJson` 非空时调用 `Send()`。
- `EventTransportStatus::Sent` -> wrapper 返回 `true`。
- `Failed / Timeout / AccessDenied / Unavailable` -> wrapper 返回 `false`。
- `compactJson` 为空 -> wrapper 返回 `false`，且不调用 transport。
- wrapper 不修改 `AsyncEvent`。

### 8.3 B0-3-2b-2：生产 LegacyPipeEventTransport

目标：

- 新增真实 legacy pipe adapter。
- 保持旧 pipe 名称 `\\.\pipe\rasp_sentry_events`。
- 保持旧 `CreateFileW + WriteFile` 行为。
- 不构造 JSON。
- 不理解业务字段。
- 不调用 `DiagLogger`。
- 不访问 `RuleSnapshot` / Lua / PCRE2 / `EngineRuntime`。

建议文件：

```text
src/rasp_rule_engine/include/event_transport.h
src/rasp_rule_engine/include/legacy_pipe_event_transport.h
src/rasp_rule_engine/src/legacy_pipe_event_transport.cpp
```

不允许把 `CreateFileW` / `WriteFile` / `WaitNamedPipeW` 放进：

```text
event_submit_client.h
event_submit_client.cpp
```

### 8.4 B0-3-2b-3：worker-only 薄包装接入

目标：

- `SendDetectionEventSyncWorkerOnly()` 改为调用 transport seam。
- `AsyncEventQueue` / worker / backoff / drop policy 不变。
- 不修改 `TrySubmitDetectionEvent()` JSON 构造。

注意：`TrySubmitDetectionEvent()` 是否改用 `EventJsonBuilder` 是单独动作，不能和 transport seam 接入同一个 commit。

### 8.5 B0-3-2b-A：TrySubmitDetectionEvent 使用 EventJsonBuilder

这是独立评审 / 独立 commit，不属于 worker-only transport seam 本身。

目标：

- 用 B0-3-2a 的 `EventJsonBuilder` 替换 `TrySubmitDetectionEvent()` 中的内联 JSON 构造。
- 保持 `AsyncEvent` DTO 字段完全一致。
- 保持入队行为完全一致。

必须新增测试锁定 `AsyncEvent` 字段。

### 8.6 B0-3-2b-B：SendDetectionEventSyncWorkerOnly 使用 IEventTransport

这是独立评审 / 独立 commit。

目标：

- 用 `IEventTransport` 替换 `SendDetectionEventSyncWorkerOnly()` 中的直接 pipe 写。
- 保持旧失败语义：写失败返回 `false`，由现有 worker/backoff 处理。

## 9. 真实 pipe adapter 错误映射

第一版必须保持旧行为：不新增 `WaitNamedPipeW` 等待，不改变 `CreateFileW` 失败即 `false` 的时序。

`timeoutMs` 参数先保留为未来扩展，legacy adapter 第一版不主动引入等待语义。

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

## 10. AsyncEvent 字段保持要求

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

必须新增测试覆盖这些字段，不能只测试 compact JSON。

## 11. 状态语义说明

当前 `EventSubmitStatus::Submitted` 在不同层级含义不同：

- `TrySubmitDetectionEvent` 层：表示事件进入 `AsyncEventQueue`。
- transport 层：应使用 `EventTransportStatus::Sent` 表示 payload 发送成功。

B0-3-2b 不应继续扩大 `EventSubmitStatus` 的含义。建议新增 `EventTransportStatus`，避免“入队成功”和“pipe 发送成功”语义混淆。

## 12. 静态边界检查

### 12.1 event_submit_client.* 禁止项

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

### 12.2 legacy_pipe_event_transport.* 允许项

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

## 13. 测试方案

B0-3-2b-1 fake transport 测试：

- fake transport 记录是否被调用。
- fake transport 记录收到的 payload。
- fake transport 可配置返回 `Sent / Failed / Timeout / AccessDenied / Unavailable`。
- wrapper 对空 payload 快速失败。
- wrapper 不修改输入事件。

B0-3-2b-2 legacy adapter 测试：

- 优先单测错误映射 helper，不直接依赖真实 pipe。
- 如需集成测试，必须单独脚本并可跳过。
- 不要求 Scan 热路径参与真实 pipe 测试。

B0-3-2b-A builder 生产接入测试：

- golden JSON 继续通过。
- `AsyncEvent` 字段保持测试通过。
- 入队状态语义不变。

回归测试：

- `event_json_builder_tests.exe`
- `scripts/check_rasp_sentry_base_boundaries.ps1`
- `scripts/test_phase_b0_2_rule_json_parser.ps1 -SkipConfigure`
- `scripts/test_phase2_batch4.ps1 -SkipConfigure`
- `scripts/test_phase3_input_normalization.ps1 -SkipConfigure`
- `scripts/test_phase3_batch2_session_context.ps1 -SkipConfigure`

## 14. 红线

B0-3-2b 禁止：

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

## 15. 回滚策略

- `RaspSentryBase::TrySubmitDetectionEvent()` 保留旧入口。
- `SendDetectionEventSyncWorkerOnly()` 保留旧入口。
- B0-3-2b-1 只引入 fake transport seam，回滚不影响生产路径。
- B0-3-2b-2 如果真实 pipe adapter 行为不一致，可回退到旧直接 pipe 写。
- B0-3-2b-A 如果 builder 生产接入导致 JSON 或 `AsyncEvent` 字段不一致，停止接入并保留旧内联 JSON 构造。
