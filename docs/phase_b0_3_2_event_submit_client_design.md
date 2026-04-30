# Phase B0-3-2 EventSubmitClient 抽离设计

## 1. 目标

B0-3-2 的目标是从 `RaspSentryBase` 中逐步抽离事件 JSON 构造和 worker-only 发送边界，同时保持现有事件 schema、字段顺序、pipe 协议、`AsyncEventQueue` 行为和 Scan 热路径非阻塞模型不变。

本批必须拆成两个小阶段：

- B0-3-2a：只抽 `EventJsonBuilder` 的 JSON 构造能力，不接 pipe，不改生产发送路径。
- B0-3-2b：在 builder golden 验证完成后，再评审 `IEventTransport` 和 worker-only 薄包装。

当前修正批次仍属于 B0-3-2a，只固化旧事件 JSON golden 语义和 builder 测试。

## 2. 非目标

本批不做：

- 不修改 `rasp_sentry_events` pipe 名称或协议。
- 不修改 `AsyncEventQueue` drop policy。
- 不修改 Scan 热路径入队模型。
- 不修改 reload / unload / shutdown。
- 不修改 AMSI `Scan()` 返回语义。
- 不接入 EDR SDK。
- 不新增数据库字段。
- 不修改 `RuleJsonParser`。
- 不抽 `DiagLogger`。
- 不抽 `LegacyPipeTransport` 生产实现。

## 3. 当前事件路径基线

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

B0-3-2a 不替换上述生产路径，只用 builder 测试固化 JSON golden 行为。

## 4. Golden JSON 字段基线

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

## 5. JSON Escape 与截断语义

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

## 6. B0-3-2a 测试策略

本批先用固定输入模拟旧路径 golden：

- 固定 event id。
- 固定 timestamp。
- 固定 module name。
- 固定 `RaspEvalResult` 等价字段。

测试分两层：

- Raw JSON 一致：字段顺序、字段名、默认值、转义形式必须与旧路径一致。
- Canonical JSON 一致：解析成 key/value 后字段值一致。

必须覆盖：

- block -> `act=block`。
- non-block -> `act=audit`。
- `cat=Detection`。
- severity 空值 -> `High`。
- confidence 为 0 -> `70`。
- payload 空值 -> `pattern` 空字符串。
- payload 超 8KB -> UTF-8 安全截断并追加 `...[Truncated]`。
- 中文/emoji 跨截断边界时不产生残缺 UTF-8。
- desc 超长不截断。
- 控制字符按 `\u00xx` 转义。

timeout / dropped / diag event 如果当前没有稳定生产 JSON 语义，不得在 B0-3-2a 为测试新增 schema。

## 7. EventJsonBuilder 边界

`EventJsonBuilder` 允许：

- 接收轻量 DTO。
- 生成 legacy-compatible compact JSON。
- 执行字段默认值、JSON escape、payload 截断。

`EventJsonBuilder` 禁止：

- 写 pipe。
- 访问 `RuleSnapshot`。
- 访问 Lua / PCRE2 / `RaspLuaEngine`。
- 访问 `EngineRuntime` 内部锁。
- include AMSI / COM / EDR / DB 头文件。
- 同步调用日志或事件发送。

## 8. B0-3-2b 预留设计

B0-3-2b 才允许评审 transport：

```cpp
class IEventTransport {
public:
    virtual ~IEventTransport() = default;
    virtual EventSubmitStatus Send(std::string_view payload,
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

## 9. 状态语义说明

当前 `EventSubmitStatus::Submitted` 在不同层级含义不同：

- `TrySubmitDetectionEvent` 层：表示事件进入 `AsyncEventQueue`。
- B0-3-2b transport 层：表示 payload 已由 transport 成功发送。

B0-3-2a 不拆分状态类型，只在文档和测试中明确语义层级。后续可演进为：

- `EventEnqueueStatus`
- `EventTransportStatus`

## 10. 静态边界检查

`scripts/check_rasp_sentry_base_boundaries.ps1` 必须继续检查 `event_submit_client.h/.cpp` 不出现：

- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EngineRuntime`
- `IAmsiStream`
- `AMSI_RESULT`
- `CreateNamedPipe`
- `ConnectNamedPipe`
- `WaitNamedPipe`
- `CreateFileW`
- `WriteFile`
- `EDR`
- `SQL`
- `database`

## 11. 验收标准

B0-3-2a 修正批次验收：

- `event_json_builder_tests.exe` 通过。
- raw JSON 字段顺序与旧路径一致。
- canonical JSON 字段值与旧路径一致。
- severity / confidence / payload 空值行为与旧路径一致。
- desc 超长不截断的 legacy 行为被测试锁定。
- payload 8KB UTF-8 安全截断测试通过。
- `scripts/check_rasp_sentry_base_boundaries.ps1` 通过。
- Phase 2 / Phase 3 回归测试通过。

## 12. 回滚策略

- `RaspSentryBase::TrySubmitDetectionEvent()` 生产入口仍保留旧实现。
- `SendDetectionEventSyncWorkerOnly()` 生产入口仍保留旧实现。
- 如果 builder 与 golden 不一致，停止进入 B0-3-2b。
- B0-3-2a 不修改 pipe 协议，因此回滚不涉及 sentry。
